/*
sslgetcert.c -- libevent-based version of sslgetcert

Created:	April 2013 by Philip Homburg for RIPE NCC
*/

#include "libbb.h"
#include <assert.h>
#include <getopt.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>
#include <event2/event.h>
#include <event2/event_struct.h>

#include "eperd.h"
#include "tcputil.h"

#define SAFE_PREFIX_IN ATLAS_DATA_OUT
#define SAFE_PREFIX_OUT ATLAS_DATA_NEW

#define CONN_TO		   5

#define ENV2STATE(env) \
	((struct state *)((char *)env - offsetof(struct state, tu_env)))

#define DBQ(str) "\"" #str "\""

#define MAX_LINE_LEN	2048	/* We don't deal with lines longer than this */
#define POST_BUF_SIZE	2048	/* Big enough to be efficient? */

static struct option longopts[]=
{
	{ NULL, }
};

enum readstate { READ_HELLO, READ_CERTS, READ_DONE };
enum writestate { WRITE_HELLO, WRITE_DONE };

struct hgbase
{
	struct event_base *event_base;

	struct state **table;
	int tabsiz;

	/* For standalone sslgetcert. Called when a sslgetcert instance is
	 * done. Just one pointer for all instances. It is up to the caller
	 * to keep it consistent.
	 */
	void (*done)(void *state);
};

struct buf
{
	size_t offset;
	size_t size;
	size_t maxsize;
	char *buf;
	struct bufferevent *bev;
};

struct msgbuf
{
	struct buf *inbuf;
	struct buf *outbuf;

	struct buf buffer;
};

struct state
{
	/* Parameters */
	char *output_file;
	char *atlas;
	char only_v4;
	char only_v6;

	/* State */
	char busy;
	struct tu_env tu_env;
	char dnserr;
	char connecting;
	char *hostname;
	char *portname;
	struct bufferevent *bev;
	enum readstate readstate;
	enum writestate writestate;
	int http_result;
	char res_major;
	char res_minor;
	int headers_size;
	int tot_headers;
	int chunked;
	int tot_chunked;
	int content_length;
	int content_offset;
	int subid;
	int submax;
	time_t gstart;
	struct timeval start;
	struct timeval t_connect;
	double resptime;
	FILE *post_fh;
	char *post_buf;

	struct buf inbuf;
	struct msgbuf msginbuf;

	char *line;
	size_t linemax;		/* Allocated size of line */
	size_t linelen;		/* Current amount of data in line */
	size_t lineoffset;	/* Offset in line where to start processing */

	/* Base and index in table */
	struct hgbase *base;
	int index;

	struct sockaddr_in6 sin6;
	socklen_t socklen;
	struct sockaddr_in6 loc_sin6;
	socklen_t loc_socklen;

	char *result;
	size_t reslen;
	size_t resmax;
};

#define BUF_CHUNK	4096

#define MSG_HANDSHAKE	22
#define HS_CLIENT_HELLO	 1
#define HS_SERVER_HELLO	 2
#define HS_CERTIFICATE	 11

struct hsbuf
{
	struct buf buffer;
};

#define URANDOM_DEV	"/dev/urandom"

static struct hgbase *hg_base;

static int eat_server_hello(struct state *state);
static int eat_certificate(struct state *state);
static void report(struct state *state);
static void add_str(struct state *state, const char *str);

static void buf_init(struct buf *buf, struct bufferevent *bev)
{
	buf->maxsize= 0;
	buf->size= 0;
	buf->offset= 0;
	buf->buf= NULL;
	buf->bev= bev;
}

static void buf_add(struct buf *buf, const void *data, size_t len)
{
	size_t maxsize;
	void *newbuf;

	if (buf->size+len <= buf->maxsize)
	{
		/* Easy case, just add data */
		memcpy(buf->buf+buf->size, data, len);
		buf->size += len;
		return;
	}

	/* Just get a new buffer */
	maxsize= buf->size-buf->offset + len + BUF_CHUNK;
	newbuf= malloc(maxsize);
	if (!newbuf)
	{
		fprintf(stderr, "unable to allocate %ld bytes\n", maxsize);
		exit(1);
	}

	if (buf->offset < buf->size)
	{
		/* Copy existing data */
		memcpy(newbuf, buf->buf+buf->offset, buf->size-buf->offset);
		buf->size -= buf->offset;
		buf->offset= 0;
	}
	else
	{
		buf->size= buf->offset= 0;
	}
	buf->maxsize= maxsize;
	free(buf->buf);
	buf->buf= newbuf;

	memcpy(buf->buf+buf->size, data, len);
	buf->size += len;
}

static void buf_add_b64(struct buf *buf, void *data, size_t len)
{
	char b64[]=
		"ABCDEFGHIJKLMNOP"
		"QRSTUVWXYZabcdef"
		"ghijklmnopqrstuv"
		"wxyz0123456789+/";
	int i;
	uint8_t *p;
	uint32_t v;
	char str[4];

	p= data;

	for (i= 0; i+3 <= len; i += 3, p += 3)
	{
		v= (p[0] << 16) + (p[1] << 8) + p[2];
		str[0]= b64[(v >> 18) & 63];
		str[1]= b64[(v >> 12) & 63];
		str[2]= b64[(v >> 6) & 63];
		str[3]= b64[(v >> 0) & 63];
		buf_add(buf, str, 4);
		if (i % 48 == 45)
			buf_add(buf, "\n", 1);
	}
	switch(len-i)
	{
	case 0:	break;	/* Nothing to do */
	case 1:
		v= (p[0] << 16);
		str[0]= b64[(v >> 18) & 63];
		str[1]= b64[(v >> 12) & 63];
		str[2]= '=';
		str[3]= '=';
		buf_add(buf, str, 4);
		break;
	case 2:
		v= (p[0] << 16) + (p[1] << 8);
		str[0]= b64[(v >> 18) & 63];
		str[1]= b64[(v >> 12) & 63];
		str[2]= b64[(v >> 6) & 63];
		str[3]= '=';
		buf_add(buf, str, 4);
		break;
	default:
		fprintf(stderr, "bad state in buf_add_b64");
		return;
	}
}

static int buf_read(struct buf *buf)
{
	int r;
	size_t maxsize;
	void *newbuf;

	if (buf->size >= buf->maxsize)
	{
		if (buf->size-buf->offset + BUF_CHUNK <= buf->maxsize)
		{
			/* The buffer is big enough, just need to compact */
			fprintf(stderr, "buf_read: should compact");
			errno= ENOSYS;
			return -1;
		}
		else
		{
			maxsize= buf->size-buf->offset + BUF_CHUNK;
			newbuf= malloc(maxsize);
			if (!newbuf)
			{
				fprintf(stderr, "unable to allocate %lu bytes",
					(unsigned long)maxsize);
				errno= ENOMEM;
				return -1;
			}
			buf->maxsize= maxsize;

			if (buf->size > buf->offset)
			{
				memcpy(newbuf, buf->buf+buf->offset, 
					buf->size-buf->offset);
				buf->size -= buf->offset;
				buf->offset= 0;
			}
			else
			{
				buf->size= buf->offset= 0;
			}
			free(buf->buf);
			buf->buf= newbuf;
		}
	}

	r= bufferevent_read(buf->bev,
		buf->buf+buf->size, buf->maxsize-buf->size);
	if (r > 0)
	{
		buf->size += r;
		return 0;
	}
	if (r == 0)
	{
		errno= EAGAIN;
		return -1;
	}
	fprintf(stderr, "read error: %s",
		r == 0 ? "eof" : strerror(errno));
	return -1;
}

static int buf_write(struct buf *buf)
{
	int r;
	size_t len;
	struct evbuffer *output;

	output= bufferevent_get_output(buf->bev);
	while (buf->offset < buf->size)
	{
		len= buf->size - buf->offset;
		r= evbuffer_add(output, buf->buf+buf->offset, len);
		if (r >= 0)
		{
			buf->offset += len;
			continue;
		}
		fprintf(stderr, "write to %p failed: %s\n",
			buf->bev, r == 0 ? "eof" : strerror(errno));
		return -1;
	}
	return 0;
}

static void buf_cleanup(struct buf *buf)
{
	free(buf->buf);
	buf->offset= buf->size= buf->maxsize= 0;
}

static void msgbuf_init(struct msgbuf *msgbuf,
	struct buf *inbuf, struct buf *outbuf)
{
	buf_init(&msgbuf->buffer, NULL);
	msgbuf->inbuf= inbuf;
	msgbuf->outbuf= outbuf;
}

static void msgbuf_add(struct msgbuf *msgbuf, void *buf, size_t size)
{
	buf_add(&msgbuf->buffer, buf, size);
}

static int msgbuf_read(struct msgbuf *msgbuf, int type)
{
	int r;
	size_t len;
	uint8_t *p;

	for(;;)
	{
		if (msgbuf->inbuf->size - msgbuf->inbuf->offset < 5)
		{
			r= buf_read(msgbuf->inbuf);
			if (r < 0)
			{
				fprintf(stderr,
					"msgbuf_read: buf_read failed: %s\n",
					strerror(errno));
				return -1;
			}
			continue;
		}
		p= (uint8_t *)msgbuf->inbuf->buf+msgbuf->inbuf->offset;
		type= p[0];
		if (p[0] != type)
		{
			fprintf(stderr, "msgbuf_read: got type %d\n", p[0]);
			return -1;
		}
		if (p[1] != 3 || p[2] != 0)
		{
			fprintf(stderr,
				"msgbuf_read: got bad major/minor %d.%d\n",
				p[1], p[2]);
			return -1;
		}
		len= (p[3] << 8) + p[4];
		if (msgbuf->inbuf->size - msgbuf->inbuf->offset < 5 + len)
		{
			r= buf_read(msgbuf->inbuf);
			if (r < 0)
			{
				if (errno != EAGAIN)
				{
					fprintf(stderr,
					"msgbuf_read: buf_read failed: %s\n",
						strerror(errno));
				}
				return -1;
			}
			continue;
		}

		/* Move the data to the msg buffer */
		msgbuf_add(msgbuf, msgbuf->inbuf->buf+msgbuf->inbuf->offset+5,
			len);
		msgbuf->inbuf->offset += 5+len;
		break;
	}
	return 0;
}

static void msgbuf_final(struct msgbuf *msgbuf, int type)
{
	uint8_t c;
	size_t len;

	while (msgbuf->buffer.offset < msgbuf->buffer.size)
	{
		len= msgbuf->buffer.size-msgbuf->buffer.offset;
		if (len > 0x4000)
			len= 0x4000;

		c= type;
		buf_add(msgbuf->outbuf, &c, 1);

		c= 3;
		buf_add(msgbuf->outbuf, &c, 1);

		c= 0;
		buf_add(msgbuf->outbuf, &c, 1);

		c= len >> 8;
		buf_add(msgbuf->outbuf, &c, 1);

		c= len;
		buf_add(msgbuf->outbuf, &c, 1);

		buf_add(msgbuf->outbuf,
			msgbuf->buffer.buf + msgbuf->buffer.offset, len);

		msgbuf->buffer.offset += len;
	}
}

static void msgbuf_cleanup(struct msgbuf *msgbuf)
{
	buf_cleanup(&msgbuf->buffer);
}

static void hsbuf_init(struct hsbuf *hsbuf)
{
	buf_init(&hsbuf->buffer, NULL);
}

static void hsbuf_add(struct hsbuf *hsbuf, const void *buf, size_t len)
{
	buf_add(&hsbuf->buffer, buf, len);
}

static void hsbuf_cleanup(struct hsbuf *hsbuf)
{
	buf_cleanup(&hsbuf->buffer);
}

static void hsbuf_final(struct hsbuf *hsbuf, int type, struct msgbuf *msgbuf)
{
	uint8_t c;
	size_t len;

	len= hsbuf->buffer.size - hsbuf->buffer.offset;

	c= type;
	msgbuf_add(msgbuf, &c, 1);

	c= (len >> 16);
	msgbuf_add(msgbuf, &c, 1);

	c= (len >> 8);
	msgbuf_add(msgbuf, &c, 1);

	c= len;
	msgbuf_add(msgbuf, &c, 1);

	msgbuf_add(msgbuf, hsbuf->buffer.buf + hsbuf->buffer.offset, len);
	hsbuf->buffer.offset += len;
}

static void add_random(struct hsbuf *hsbuf)
{
	int fd;
	time_t t;
	uint8_t buf[32];

	t= time(NULL);
	buf[0]= t >> 24;
	buf[1]= t >> 16;
	buf[2]= t >> 8;
	buf[3]= t;

	fd= open(URANDOM_DEV, O_RDONLY);

	/* Best effort, just ignore errors */
	if (fd != -1)
	{
		read(fd, buf+4, sizeof(buf)-4);
		close(fd);
	}
	hsbuf_add(hsbuf, buf, sizeof(buf));
}

static void add_sessionid(struct hsbuf *hsbuf)
{
	uint8_t c;

	c= 0;
	hsbuf_add(hsbuf, &c, 1);
}

static void add_ciphers(struct hsbuf *hsbuf)
{
	uint8_t c;
	size_t len;
	uint8_t ciphers[]= { 0x0,0xff, 0x0,0x88, 0x0,0x87, 0x0,0x39, 0x0,0x38,
		0x0,0x84, 0x0,0x35, 0x0,0x45, 0x0,0x44, 0x0,0x33, 0x0,0x32,
		0x0,0x96, 0x0,0x41, 0x0,0x4, 0x0,0x5, 0x0,0x2f, 0x0,0x16,
		0x0,0x13, 0xfe,0xff, 0x0,0xa };

	len= sizeof(ciphers);

	c= len >> 8;
	hsbuf_add(hsbuf, &c, 1);
	c= len;
	hsbuf_add(hsbuf, &c, 1);

	hsbuf_add(hsbuf, ciphers, len);
}

static void add_compression(struct hsbuf *hsbuf)
{
	uint8_t c;
	size_t len;
	uint8_t compression[]= { 0x1, 0x0 };

	len= sizeof(compression);

	c= len;
	hsbuf_add(hsbuf, &c, 1);

	hsbuf_add(hsbuf, compression, len);
}


static struct hgbase *sslgetcert_base_new(struct event_base *event_base)
{
	struct hgbase *base;

	base= xzalloc(sizeof(*base));

	base->event_base= event_base;

	base->tabsiz= 10;
	base->table= xzalloc(base->tabsiz * sizeof(*base->table));

	return base;
}

static void timeout_callback(int __attribute((unused)) unused,
	const short __attribute((unused)) event, void *s)
{
	struct state *state;

	state= ENV2STATE(s);

	if (state->connecting)
	{
		add_str(state, DBQ(err) ":" DBQ(connect: timeout));
		if (0 /*state->do_all*/)
			report(state);
		else
			tu_restart_connect(&state->tu_env);
		return;
	}
	switch(state->readstate)
	{
	case READ_HELLO:
		add_str(state, DBQ(err) ":" DBQ(timeout reading hello));
		report(state);
		break;
	case READ_CERTS:
		add_str(state, DBQ(err) ":" DBQ(timeout reading certificates));
		report(state);
		break;
	default:
		printf("in timeout_callback, unhandled case: %d\n",
			state->readstate);
	}
}

static void *sslgetcert_init(int __attribute((unused)) argc, char *argv[],
	void (*done)(void *state))
{
	int c, i, only_v4, only_v6;
	size_t newsiz;
	char *hostname, *str_port;
	char *output_file, *A_arg;
	struct state *state;
	FILE *fh;

	/* Arguments */
	output_file= NULL;
	A_arg= NULL;
	str_port= NULL;
	only_v4= 0;
	only_v6= 0;

	if (!hg_base)
	{
		hg_base= sslgetcert_base_new(EventBase);
		if (!hg_base)
			crondlog(DIE9 "sslgetcert_base_new failed");
	}


	/* Allow us to be called directly by another program in busybox */
	optind= 0;
	while (c= getopt_long(argc, argv, "A:O:p:46", longopts, NULL), c != -1)
	{
		switch(c)
		{
		case 'A':
			A_arg= optarg;
			break;
		case 'O':
			output_file= optarg;
			break;
		case 'p':
			str_port= optarg;
			break;
		case '4':
			only_v4= 1;
			only_v6= 0;
			break;
		case '6':
			only_v6= 1;
			only_v4= 0;
			break;
		default:
			crondlog(LVL8 "bad option '%c'", c);
			return NULL;
		}
	}

	if (optind != argc-1)
	{
		crondlog(LVL8 "exactly one hostname expected");
		return NULL;
	}
	hostname= argv[optind];

	if (output_file)
	{
		if (!validate_filename(output_file, SAFE_PREFIX_OUT))
		{
			crondlog(LVL8 "insecure file '%s'", output_file);
			return NULL;
		}
		fh= fopen(output_file, "a");
		if (!fh)
		{
			crondlog(LVL8 "unable to append to '%s'",
				output_file);
			return NULL;
		}
		fclose(fh);
	}

	if (A_arg)
	{
		if (!validate_atlas_id(A_arg))
		{
			crondlog(LVL8 "bad atlas ID '%s'", A_arg);
			return NULL;
		}
	}

	state= xzalloc(sizeof(*state));
	state->base= hg_base;
	state->atlas= A_arg ? strdup(A_arg) : NULL;
	state->output_file= output_file ? strdup(output_file) : NULL;
	state->hostname= strdup(hostname);
	if (str_port)
		state->portname= strdup(str_port);
	else
		state->portname= strdup("443");

	state->only_v4= 2;

	state->only_v4= !!only_v4;	/* Gcc bug? */
	state->only_v6= !!only_v6;

	state->line= NULL;
	state->linemax= 0;
	state->linelen= 0;
	state->lineoffset= 0;

	for (i= 0; i<hg_base->tabsiz; i++)
	{
		if (hg_base->table[i] == NULL)
			break;
	}
	if (i >= hg_base->tabsiz)
	{
		newsiz= 2*hg_base->tabsiz;
		hg_base->table= xrealloc(hg_base->table,
			newsiz*sizeof(*hg_base->table));
		for (i= hg_base->tabsiz; i<newsiz; i++)
			hg_base->table[i]= NULL;
		i= hg_base->tabsiz;
		hg_base->tabsiz= newsiz;
	}
	state->index= i;
	hg_base->table[i]= state;
	hg_base->done= done;

	return state;
}

static void report(struct state *state)
{
	FILE *fh;
	char hostbuf[NI_MAXHOST];
	// char line[160];

	fh= NULL;
	if (state->output_file)
	{
		fh= fopen(state->output_file, "a");
		if (!fh)
			crondlog(DIE9 "unable to append to '%s'",
				state->output_file);
	}
	else
		fh= stdout;

	fprintf(fh, "RESULT { ");
	if (state->atlas)
	{
		fprintf(fh, DBQ(id) ":" DBQ(%s) ", "
			DBQ(fw) ":%d, "
			DBQ(time) ":%ld, ",
			state->atlas, get_atlas_fw_version(),
			state->gstart);
	}

	fprintf(fh, DBQ(dst_name) ":" DBQ(%s) ", "
		DBQ(dst_port) ":" DBQ(%s) ", ",
		state->hostname, state->portname);

	if (!state->dnserr)
	{
		getnameinfo((struct sockaddr *)&state->sin6, state->socklen,
			hostbuf, sizeof(hostbuf), NULL, 0,
			NI_NUMERICHOST);
		fprintf(fh, DBQ(dst_addr) ":" DBQ(%s) ", ", hostbuf);
		fprintf(fh, DBQ(af) ": %d, ",
			state->sin6.sin6_family == AF_INET6 ? 6 : 4);

#if 0
		getnameinfo((struct sockaddr *)&state->loc_sin6,
			state->loc_socklen, hostbuf, sizeof(hostbuf), NULL, 0,
			NI_NUMERICHOST);
		fprintf(fh, ", " DBQ(src_addr) ":" DBQ(%s), hostbuf);
#endif
	}

	fprintf(fh, "%s }\n", state->result);
	free(state->result);
	state->result= NULL;
	state->resmax= 0;
	state->reslen= 0;

	if (state->output_file)
		fclose(fh);

	free(state->post_buf);
	state->post_buf= NULL;

	if (state->linemax)
	{
		state->linemax= 0;
		free(state->line);
		state->line= NULL;
	}

	state->bev= NULL;

	tu_cleanup(&state->tu_env);

	state->busy= 0;
	if (state->base->done)
		state->base->done(state);
}


static void add_str(struct state *state, const char *str)
{
	size_t len;

	len= strlen(str);
	if (state->reslen + len+1 > state->resmax)
	{
		state->resmax= state->reslen + len+1 + 80;
		state->result= xrealloc(state->result, state->resmax);
	}
	memcpy(state->result+state->reslen, str, len+1);
	state->reslen += len;
	//printf("add_str: result = '%s'\n", state->result);
}

static void readcb(struct bufferevent *bev UNUSED_PARAM, void *ptr)
{
	int r;
	struct state *state;

	state= ENV2STATE(ptr);

	for (;;)
	{
		switch(state->readstate)
		{
		case READ_HELLO:
			r= eat_server_hello(state);
			if (r == -1)
				return;
			state->readstate= READ_CERTS;
			continue;

		case READ_CERTS:
			r= eat_certificate(state);
			if (r == -1)
				return;
			state->readstate= READ_DONE;
			continue;

		case READ_DONE:
			msgbuf_cleanup(&state->msginbuf);
			buf_cleanup(&state->inbuf);
			tu_cleanup(&state->tu_env);
			state->busy= 0;
			if (state->base->done)
				state->base->done(state);
			return;

		default:
			printf("readcb: readstate = %d\n", state->readstate);
			return;
		}
	}
}

static int eat_server_hello(struct state *state)
{
	int r;
	size_t len;
	uint8_t *p;
	struct msgbuf *msgbuf;

	msgbuf= &state->msginbuf;

	for (;;)
	{
		if (msgbuf->buffer.size - msgbuf->buffer.offset < 4)
		{
			r= msgbuf_read(msgbuf, MSG_HANDSHAKE);
			if (r < 0)
			{
				fprintf(stderr,
				"eat_server_hello: msgbuf_read failed\n");
				return -1;

			}
			continue;
		}
		p= (uint8_t *)msgbuf->buffer.buf+msgbuf->buffer.offset;
		if (p[0] != HS_SERVER_HELLO)
		{
			fprintf(stderr, "eat_server_hello: got type %d\n",
				p[0]);
			return -1;
		}
		len= (p[1] << 16) + (p[2] << 8) + p[3];
		if (msgbuf->buffer.size - msgbuf->buffer.offset < 4+len)
		{
			r= msgbuf_read(msgbuf, MSG_HANDSHAKE);
			if (r < 0)
			{
				fprintf(stderr,
				"eat_server_hello: msgbuf_read failed\n");
				return -1;
			}
			continue;
		}
		msgbuf->buffer.offset += 4+len;
		break;
	}
	return 0;
}

static int eat_certificate(struct state *state)
{
	int i, n, r, first, slen;
	size_t o, len;
	uint8_t *p;
	struct msgbuf *msgbuf;
	FILE *fh;
	double resptime;
	struct timeval endtime;
	struct buf tmpbuf;
	char hostbuf[NI_MAXHOST];

	msgbuf= &state->msginbuf;

	for (;;)
	{
		if (msgbuf->buffer.size - msgbuf->buffer.offset < 4)
		{
			r= msgbuf_read(msgbuf, MSG_HANDSHAKE);
			if (r < 0)
			{
				if (errno != EAGAIN)
				{
					fprintf(stderr,
				"eat_certificate: msgbuf_read failed: %s\n",
						strerror(errno));
				}
				return -1;
			}
			continue;
		}
		p= (uint8_t *)msgbuf->buffer.buf+msgbuf->buffer.offset;
		if (p[0] != HS_CERTIFICATE)
		{
			fprintf(stderr, "eat_certificate: got type %d\n", p[0]);
			return -1;
		}
		len= (p[1] << 16) + (p[2] << 8) + p[3];
		if (msgbuf->buffer.size - msgbuf->buffer.offset < 4+len)
		{
			r= msgbuf_read(msgbuf, MSG_HANDSHAKE);
			if (r < 0)
			{
				fprintf(stderr,
				"eat_certificate: msgbuf_read failed\n");
				return -1;
			}
			continue;
		}
		p += 4;
		n= (p[0] << 16) + (p[1] << 8) + p[2];
		o= 3;

		gettimeofday(&endtime, NULL);

		fh= NULL;
		if (state->output_file)
		{
			fh= fopen(state->output_file, "a");
			if (!fh)
				crondlog(DIE9 "unable to append to '%s'",
					state->output_file);
		}
		else
			fh= stdout;

		fprintf(fh, "RESULT { ");
		if (state->atlas)
		{
			fprintf(fh, DBQ(id) ":" DBQ(%s)
				", " DBQ(fw) ":%d",
				state->atlas, get_atlas_fw_version());
		}

		fprintf(fh, "%s" DBQ(time) ":%ld",
			state->atlas ? ", " : "", time(NULL));
		fprintf(fh, ", " DBQ(dst_name) ":" DBQ(%s) ", "
			DBQ(dst_port) ":" DBQ(%s),
			state->hostname, state->portname);

		fprintf(fh, ", " DBQ(method) ":" DBQ(SSL) ", "
			DBQ(ver) ":" DBQ(3.0));
		getnameinfo((struct sockaddr *)&state->sin6, state->socklen,
			hostbuf, sizeof(hostbuf), NULL, 0,
			NI_NUMERICHOST);
		fprintf(fh, ", " DBQ(dst_addr) ":" DBQ(%s), hostbuf);
		fprintf(fh, ", " DBQ(af) ": %d",
			state->sin6.sin6_family == AF_INET6 ? 6 : 4);

		getnameinfo((struct sockaddr *)&state->loc_sin6,
			state->loc_socklen, hostbuf, sizeof(hostbuf), NULL, 0,
			NI_NUMERICHOST);
		fprintf(fh, ", " DBQ(src_addr) ":" DBQ(%s), hostbuf);

		resptime= (state->t_connect.tv_sec- state->start.tv_sec)*1e3 +
			(state->t_connect.tv_usec-state->start.tv_usec)/1e3;
		fprintf(fh, ", " DBQ(ttc) ": %f", resptime);

		resptime= (endtime.tv_sec- state->start.tv_sec)*1e3 +
			(endtime.tv_usec-state->start.tv_usec)/1e3;
		fprintf(fh, ", " DBQ(rt) ": %f", resptime);

		first= 1;
		fprintf(fh, ", " DBQ(cert) ":[ ");

		buf_init(&tmpbuf, NULL);
		while (o < 3+n)
		{
			slen= (p[o] << 16) + (p[o+1] << 8) + p[o+2];
			buf_add_b64(&tmpbuf, p+o+3, slen);
			fprintf(fh, "%s\"-----BEGIN CERTIFICATE-----\\n",
				!first ? ", " : "");
			for (i= tmpbuf.offset; i<tmpbuf.size; i++)
			{
				if (tmpbuf.buf[i] == '\n')
					fputs("\\n", fh);
				else
					fputc(tmpbuf.buf[i], fh);
			}
			fprintf(fh, "\\n-----END CERTIFICATE-----\"");
			tmpbuf.size= tmpbuf.offset;
			o += 3+slen;
			first= 0;
		}
		buf_cleanup(&tmpbuf);
		fprintf(fh, " ]");
		if (o != 3+n)
		{
			fprintf(stderr,
				"do_certificate: bad amount of cert data\n");
			return -1;
		}
		if (o != len)
		{
			fprintf(stderr,
				"do_certificate: bad amount of cert data\n");
			return -1;
		}
		msgbuf->buffer.offset += 4+len;
		break;
	}

	fprintf(fh, " }\n");

	if (state->output_file)
		fclose(fh);

	return 0;
}

static void writecb(struct bufferevent *bev, void *ptr)
{
	struct state *state;
	struct buf outbuf;
	struct msgbuf msgoutbuf;
	struct hsbuf hsbuf;

	state= ENV2STATE(ptr);

	for(;;)
	{
		switch(state->writestate)
		{
		case WRITE_HELLO:
			gettimeofday(&state->t_connect, NULL);

			buf_init(&outbuf, bev);
			msgbuf_init(&msgoutbuf, NULL, &outbuf);
			hsbuf_init(&hsbuf);

			/* Major/minor */
			hsbuf_add(&hsbuf, "\3", 1);
			hsbuf_add(&hsbuf, "\0", 1);
			add_random(&hsbuf);
			add_sessionid(&hsbuf);
			add_ciphers(&hsbuf);
			add_compression(&hsbuf);

			hsbuf_final(&hsbuf, HS_CLIENT_HELLO, &msgoutbuf);
			msgbuf_final(&msgoutbuf, MSG_HANDSHAKE);

			/* Ignore error */
			(void) buf_write(&outbuf);

			hsbuf_cleanup(&hsbuf);
			msgbuf_cleanup(&msgoutbuf);
			buf_cleanup(&outbuf);

			/* Done */
			state->writestate= WRITE_DONE;
			continue;

		case WRITE_DONE:
			return;

		default:
			printf("writecb: unknown write state: %d\n",
				state->writestate);
			return;
		}
	}

}

static void err_reading(struct state *state)
{
	switch(state->readstate)
	{
	default:
		printf("in err_reading, unhandled case\n");
	}
}

static void dnscount(struct tu_env *env, int count)
{
	struct state *state;

	state= ENV2STATE(env);
	state->subid= 0;
	state->submax= count;
}

static void beforeconnect(struct tu_env *env,
	struct sockaddr *addr, socklen_t addrlen)
{
	struct state *state;

	state= ENV2STATE(env);

	state->socklen= addrlen;
	memcpy(&state->sin6, addr, state->socklen);

	state->connecting= 1;
	state->readstate= READ_HELLO;
	state->writestate= WRITE_HELLO;

	state->linelen= 0;
	state->lineoffset= 0;
	state->headers_size= 0;
	state->tot_headers= 0;

	/* Clear result */
	//if (!state->do_all || !state->do_combine)
	state->reslen= 0;

	gettimeofday(&state->start, NULL);
}


static void reporterr(struct tu_env *env, enum tu_err cause,
		const char *str)
{
	struct state *state;
	char line[80];

	state= ENV2STATE(env);

	if (env != &state->tu_env) abort();

	switch(cause)
	{
	case TU_DNS_ERR:
		snprintf(line, sizeof(line),
			DBQ(dnserr) ":" DBQ(%s), str);
		add_str(state, line);
		state->dnserr= 1;
		report(state);
		break;

	case TU_READ_ERR:
		err_reading(state);
		break;

	case TU_CONNECT_ERR:
		snprintf(line, sizeof(line),
			DBQ(err) ":" DBQ(connect: %s), str);
		add_str(state, line);

		if (0 /*state->do_all*/)
			report(state);
		else
			tu_restart_connect(&state->tu_env);
		break;

	case TU_OUT_OF_ADDRS:
		report(state);
		break;

	default:
		crondlog(DIE9 "reporterr: bad cause %d", cause);
	}
}

static void connected(struct tu_env *env, struct bufferevent *bev)
{
	struct state *state;

	state= ENV2STATE(env);

	if (env != &state->tu_env) abort();

	state->connecting= 0;
	state->bev= bev;

	buf_init(&state->inbuf, bev);
	msgbuf_init(&state->msginbuf, &state->inbuf, NULL);

	state->loc_socklen= sizeof(state->loc_sin6);
	getsockname(bufferevent_getfd(bev),	
		&state->loc_sin6, &state->loc_socklen);
}

static void sslgetcert_start(void *vstate)
{
	struct state *state;
	struct evutil_addrinfo hints;
	struct timeval interval;

	state= vstate;

	if (state->busy)
	{
		printf("httget_start: busy\n");
		return;
	}
	state->busy= 1;

	state->dnserr= 0;
	state->connecting= 0;
	state->readstate= READ_HELLO;
	state->writestate= WRITE_HELLO;
	state->gstart= time(NULL);

	memset(&hints, '\0', sizeof(hints));
	hints.ai_socktype= SOCK_STREAM;
	if (state->only_v4)
		hints.ai_family= AF_INET;
	else if (state->only_v6)
		hints.ai_family= AF_INET6;
	interval.tv_sec= CONN_TO;
	interval.tv_usec= 0;

	tu_connect_to_name(&state->tu_env, state->hostname,
		state->portname,
		&interval, &hints, timeout_callback,
		reporterr, dnscount, beforeconnect,
		connected, readcb, writecb);
}

static int sslgetcert_delete(void *vstate)
{
	int ind;
	struct state *state;
	struct hgbase *base;

	state= vstate;

	printf("sslgetcert_delete: state %p, index %d, busy %d\n",
		state, state->index, state->busy);

	if (state->busy)
		return 0;

	if (state->line)
		crondlog(DIE9 "line is not empty");

	base= state->base;
	ind= state->index;

	if (base->table[ind] != state)
		crondlog(DIE9 "strange, state not in table");
	base->table[ind]= NULL;

	//event_del(&state->timer);

	free(state->atlas);
	state->atlas= NULL;
	free(state->output_file);
	state->output_file= NULL;
	free(state->hostname);
	state->hostname= NULL;
	free(state->portname);
	state->portname= NULL;

	free(state);

	return 1;
}

struct testops sslgetcert_ops = { sslgetcert_init, sslgetcert_start,
	sslgetcert_delete };

