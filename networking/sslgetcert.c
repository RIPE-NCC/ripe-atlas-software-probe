/* Simple SSL client to get server certificates */

#include "libbb.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>

#define OPT_4	(1 << 0)
#define OPT_6	(1 << 1)

#define MSG_HANDSHAKE	22
#define HS_CLIENT_HELLO	 1
#define HS_SERVER_HELLO	 2
#define HS_CERTIFICATE	 11

struct buf
{
	size_t offset;
	size_t size;
	size_t maxsize;
	char *buf;
	int fd;
};

#define BUF_CHUNK	4096

struct msgbuf
{
	struct buf *inbuf;
	struct buf *outbuf;

	struct buf buffer;
};

struct hsbuf
{
	struct buf buffer;
};

#define URANDOM_DEV	"/dev/urandom"

#define DBQ(str) "\"" #str "\""

static int tcp_fd= -1;

static void fatal(const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "ssltestc30: ");

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, "\n");
	exit(1);
}

static void got_alarm(int sig __attribute__((unused)) )
{
	if (tcp_fd != -1)
		fcntl(tcp_fd, F_SETFL, fcntl(tcp_fd, F_GETFL) | O_NONBLOCK);
	alarm(1);
}

static void buf_init(struct buf *buf, int fd)
{
	buf->maxsize= 0;
	buf->size= 0;
	buf->offset= 0;
	buf->buf= NULL;
	buf->fd= fd;
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
		fatal("bad state in buf_add_b64");
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
			fatal("buf_read: should compact");
		}
		else
		{
			maxsize= buf->size-buf->offset + BUF_CHUNK;
			newbuf= malloc(maxsize);
			if (!newbuf)
				fatal("unable to allocate %d bytes", maxsize);
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

	for (;;)
	{
		r= read(buf->fd, buf->buf+buf->size, buf->maxsize-buf->size);
		if (r > 0)
		{
			buf->size += r;
			break;
		}
		fprintf(stderr, "read error on fd %d: %s",
			buf->fd, r == 0 ? "eof" : strerror(errno));
		return -1;
	}
	return 0;
}

static int buf_write(struct buf *buf)
{
	int r;
	size_t len;

	while (buf->offset < buf->size)
	{
		len= buf->size - buf->offset;
		r= write(buf->fd, buf->buf+buf->offset, len);
		if (len > 0)
		{
			buf->offset += len;
			continue;
		}
		fprintf(stderr, "write to %d failed: %s\n",
			buf->fd, r == 0 ? "eof" : strerror(errno));
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
	buf_init(&msgbuf->buffer, -1);
	msgbuf->inbuf= inbuf;
	msgbuf->outbuf= outbuf;
}

static void msgbuf_add(struct msgbuf *msgbuf, void *buf, size_t size)
{
	buf_add(&msgbuf->buffer, buf, size);
}

static int Xmsgbuf_read(struct msgbuf *msgbuf, int type)
{
	int r;
	size_t len;
	uint8_t *p;

	for(;;)
	{
		while (msgbuf->inbuf->size - msgbuf->inbuf->offset < 5)
		{
			r= buf_read(msgbuf->inbuf);
			if (r < 0)
			{
				fprintf(stderr,
					"msgbuf_read: buf_read failed\n");
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
				fprintf(stderr,
					"msgbuf_read: buf_read failed\n");
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
	buf_init(&hsbuf->buffer, -1);
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

static int connect_to_name(int af, const char *host, const char *port)
{
	int r, s, s_errno;
	struct addrinfo *res, *aip;
	struct addrinfo hints;

	memset(&hints, '\0', sizeof(hints));
	hints.ai_family= af;
	hints.ai_socktype= SOCK_STREAM;
	r= getaddrinfo(host, port, &hints, &res);
	if (r != 0)
	{
		fprintf(stderr,
			"unable to resolve '%s': %s", host, gai_strerror(r));
		return -1;
	}

	s_errno= 0;
	s= -1;
	for (aip= res; aip != NULL; aip= aip->ai_next)
	{
		s= socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s == -1)
		{	
			s_errno= errno;
			continue;
		}

		if (connect(s, res->ai_addr, res->ai_addrlen) == 0)
			break;

		s_errno= errno;
		close(s);
		s= -1;
	}

	freeaddrinfo(res);
	if (s == -1)
		errno= s_errno;
	return s;
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

static int Xeat_server_hello(struct msgbuf *msgbuf)
{
	int r;
	size_t len;
	uint8_t *p;

	for (;;)
	{
		if (msgbuf->buffer.size - msgbuf->buffer.offset < 4)
		{
			r= Xmsgbuf_read(msgbuf, MSG_HANDSHAKE);
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
			r= Xmsgbuf_read(msgbuf, MSG_HANDSHAKE);
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

static int Xeat_certificate(struct msgbuf *msgbuf)
{
	int i, n, r, first, slen, need_nl;
	size_t o, len;
	uint8_t *p;
	struct buf tmpbuf;

	for (;;)
	{
		if (msgbuf->buffer.size - msgbuf->buffer.offset < 4)
		{
			r= Xmsgbuf_read(msgbuf, MSG_HANDSHAKE);
			if (r < 0)
			{
				fprintf(stderr,
				"eat_certificate: msgbuf_read failed\n");
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
			r= Xmsgbuf_read(msgbuf, MSG_HANDSHAKE);
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
		first= 1;
		printf(", " DBQ(cert) ":[ ");

		buf_init(&tmpbuf, -1);
		while (o < 3+n)
		{
			slen= (p[o] << 16) + (p[o+1] << 8) + p[o+2];
			buf_add_b64(&tmpbuf, p+o+3, slen);
			printf("%s\"-----BEGIN CERTIFICATE-----\\n",
				!first ? ", " : "");
			need_nl=0;
			for (i= tmpbuf.offset; i<tmpbuf.size; i++)
			{
				if (tmpbuf.buf[i] == '\n')
				{
					fputs("\\n", stdout);
					need_nl=0;
				}
				else
				{
					putchar(tmpbuf.buf[i]);
					need_nl=1;
				}
			}
			if (need_nl)
				fputs("\\n", stdout);
			printf("-----END CERTIFICATE-----\"");
			tmpbuf.size= tmpbuf.offset;
			o += 3+slen;
			first= 0;
		}
		buf_cleanup(&tmpbuf);
		printf(" ]");
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

	return 0;
}

extern int get_atlas_fw_version(void);	/* In eperd */

int sslgetcert_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int sslgetcert_main(int argc UNUSED_PARAM, char **argv)
{
	int r, af;
	uint32_t opt;
	socklen_t salen;
	char *str_Atlas;
	const char *str_port;
	char *hostname;
	struct buf inbuf, outbuf;
	struct msgbuf msginbuf, msgoutbuf;
	struct hsbuf hsbuf;
	struct sockaddr_storage sa;
	struct sigaction sia;
	char hostbuf[NI_MAXHOST];

	str_Atlas= NULL;
	str_port= "https";

	opt_complementary = "=1";
	opt = getopt32(argv, "!46A:p:", &str_Atlas, &str_port);
	if (opt == (uint32_t)-1)
		return 1;
	hostname = argv[optind];

	af= AF_UNSPEC;
	if (opt & OPT_4)
		af= AF_INET;
	if (opt & OPT_6)
		af= AF_INET6;

	sia.sa_flags= 0;
	sia.sa_handler= got_alarm;
	sigemptyset(&sia.sa_mask);
	sigaction(SIGALRM, &sia, NULL);
	alarm(10);
	signal(SIGPIPE, SIG_IGN);

	tcp_fd= connect_to_name(af, hostname, str_port);

	printf("RESULT { ");
	if (str_Atlas)
	{
		printf(DBQ(id) ":" DBQ(%s)
			", " DBQ(fw) ":%d",
			str_Atlas, get_atlas_fw_version());
	}

	printf("%s" DBQ(time) ":%ld", str_Atlas ? ", " : "", time(NULL));
	printf(", " DBQ(dst_name) ":" DBQ(%s) ", " DBQ(dst_port) ":" DBQ(%s),
		hostname, str_port);

	printf(", " DBQ(method) ":" DBQ(SSL) ", " DBQ(ver) ":" DBQ(3.0));
	if (af != AF_UNSPEC)
		printf(", " DBQ(af) ": %d", af == AF_INET6 ? 6 : 4);

	if (tcp_fd == -1)
	{
		printf(", " DBQ(err) ":" DBQ(unable to connect) " }\n");
		return 0;
	}

	salen= sizeof(sa);
	if (getpeername(tcp_fd, (struct sockaddr *)&sa, &salen) != -1)
	{
		getnameinfo((struct sockaddr *)&sa, salen,
			hostbuf, sizeof(hostbuf), NULL, 0,
			NI_NUMERICHOST);
		printf(", " DBQ(dst_addr) ":" DBQ(%s), hostbuf);
		if (af == AF_UNSPEC)
		{
			printf(", " DBQ(af) ": %d",
				sa.ss_family == AF_INET6 ? 6 : 4);
		}
	}
	salen= sizeof(sa);
	if (getsockname(tcp_fd, (struct sockaddr *)&sa, &salen) != -1)
	{
		getnameinfo((struct sockaddr *)&sa, salen,
			hostbuf, sizeof(hostbuf), NULL, 0,
			NI_NUMERICHOST);
		printf(", " DBQ(src_addr) ":" DBQ(%s), hostbuf);
	}

	buf_init(&outbuf, tcp_fd);
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
	r= buf_write(&outbuf);
	if (r == -1)
		goto fail;

	buf_init(&inbuf, tcp_fd);
	msgbuf_init(&msginbuf, &inbuf, NULL);

	if (Xeat_server_hello(&msginbuf) < 0)
		goto fail;

	if (Xeat_certificate(&msginbuf) < 0)
		goto fail;

fail:
	printf(" }\n");

	close(tcp_fd);
	tcp_fd= -1;

	hsbuf_cleanup(&hsbuf);
	msgbuf_cleanup(&msginbuf);
	msgbuf_cleanup(&msgoutbuf);
	buf_cleanup(&inbuf);
	buf_cleanup(&outbuf);

	alarm(0);
	signal(SIGPIPE, SIG_DFL);

	return 0;
}
