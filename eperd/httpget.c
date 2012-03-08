/*
httpget.c -- libevent-based version of httpget

Created:	Jan 2012 by Philip Homburg for RIPE NCC
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

#define DBQ(str) "\"" #str "\""

#define MAX_LINE_LEN	2048	/* We don't deal with lines longer than this */

#define CONN_TO		   5	/* Should get connection CONN_TO seconds */

static struct option longopts[]=
{
	{ "append",	no_argument, NULL, 'a' },
	{ "delete-file", no_argument, NULL, 'd' },
	{ "get",	no_argument, NULL, 'g' },
	{ "head",	no_argument, NULL, 'E' },
	{ "post",	no_argument, NULL, 'P' },
	{ "post-file",	required_argument, NULL, 'p' },
	{ "post-dir",	required_argument, NULL, 'D' },
	{ "post-header", required_argument, NULL, 'h' },
	{ "post-footer", required_argument, NULL, 'f' },
	{ "store-headers", required_argument, NULL, 'H' },
	{ "store-body",	required_argument, NULL, 'B' },
	{ "summary",	no_argument, NULL, 'S' },
	{ "user-agent",	required_argument, NULL, 'u' },
	{ NULL, }
};

enum readstate { READ_STATUS, READ_HEADER, READ_BODY, READ_SIMPLE,
	READ_CHUNKED, READ_CHUNK_BODY, READ_CHUNK_END, READ_CHUNKED_TRAILER,
	READ_DONE };
enum writestate { WRITE_HEADER, WRITE_DONE };

struct hgbase
{
	struct event_base *event_base;

	struct hgstate **table;
	int tabsiz;

	/* For standalone httpget. Called when a httpget instance is
	 * done. Just one pointer for all instances. It is up to the caller
	 * to keep it consistent.
	 */
	void (*done)(void *state);
};

struct hgstate
{
	/* Parameters */
	char *atlas;
	char do_v6;
	char do_get;
	char do_head;
	char do_post;
	char do_http10;
	const char *user_agent;
	int max_headers;
	int max_body;

	/* State */
	char busy;
	char dnserr;
	char connecting;
	char *host;
	char *port;
	char *hostport;
	char *path;
	struct evutil_addrinfo *dns_res;
	struct evutil_addrinfo *dns_curr;
	struct bufferevent *bev;
	struct event timer;
	char *out_filename;
	enum readstate readstate;
	enum writestate writestate;
	int http_result;
	int headers_size;
	int tot_headers;
	int chunked;
	int tot_chunked;
	int content_length;
	int content_offset;
	struct timeval start;
	double resptime;

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

static struct hgbase *hg_base;

static void report(struct hgstate *state);
static void eventcb(struct bufferevent *bev, short events, void *ptr);
static void create_bev(struct hgstate *state);
static void add_str(struct hgstate *state, const char *str);

static struct hgbase *httpget_base_new(struct event_base *event_base)
{
	struct hgbase *base;

	base= xzalloc(sizeof(*base));

	base->event_base= event_base;

	base->tabsiz= 10;
	base->table= xzalloc(base->tabsiz * sizeof(*base->table));

	return base;
}

static int parse_url(char *url, char **hostp, char **portp, char **hostportp,
	char **pathp)
{
	char *item;
	const char *cp, *np, *prefix;
	size_t len;

	*hostp= NULL;
	*portp= NULL;
	*hostportp= NULL;
	*pathp= NULL;

	/* the url must start with 'http://' */
	prefix= "http://";
	len= strlen(prefix);
	if (strncasecmp(prefix, url, len) != 0)
	{
		crondlog(LVL8 "bad prefix in url '%s'", url);
		goto fail;
	}

	cp= url+len;

	/* Get hostport part */
	np= strchr(cp, '/');
	if (np != NULL)
		len= np-cp;
	else
	{
		len= strlen(cp);
		np= cp+len;
	}
	if (len == 0)
	{
		crondlog(LVL8 "missing host part in url '%s'", url);
		return 0;
	}
	item= xmalloc(len+1);
	memcpy(item, cp, len);
	item[len]= '\0';
	*hostportp= item;

	/* The remainder is the path */
	cp= np;
	if (cp[0] == '\0')
		cp= "/";
	len= strlen(cp);
	item= xmalloc(len+1);
	memcpy(item, cp, len);
	item[len]= '\0';
	*pathp= item;

	/* Extract the host name from hostport */
	cp= *hostportp;
	np= cp;
	if (cp[0] == '[')
	{
		/* IPv6 address literal */
		np= strchr(cp, ']');
		if (np == NULL || np == cp+1)
		{
			crondlog(LVL8
				"malformed IPv6 address literal in url '%s'",
				url);
			goto fail;
		}
	}

	np= strchr(np, ':');
	if (np != NULL)
		len= np-cp;
	else
	{
		len= strlen(cp);
		np= cp+len;
	}
	if (len == 0)
	{
		crondlog(LVL8 "missing host part in url '%s'", url);
		goto fail;
	}
	item= xmalloc(len+1);
	if (cp[0] == '[')
	{
		/* Leave out the square brackets */
		memcpy(item, cp+1, len-2);
		item[len-2]= '\0';
	}
	else
	{
		memcpy(item, cp, len);
		item[len]= '\0';
	}
	*hostp= item;

	/* Port */
	cp= np;
	if (cp[0] == '\0')
		cp= "80";
	else
		cp++;
	len= strlen(cp);
	item= xmalloc(len+1);
	memcpy(item, cp, len);
	item[len]= '\0';
	*portp= item;

	return 1;

fail:
	if (*hostp)
	{
		free(*hostp);
		*hostp= NULL;
	}
	if (*portp)
	{
		free(*portp);
		*portp= NULL;
	}
	if (*hostportp)
	{
		free(*hostportp);
		*hostportp= NULL;
	}
	if (*pathp)
	{
		free(*pathp);
		*pathp= NULL;
	}
	return 0;
}

static void restart_connect(struct hgstate *state)
{
	struct bufferevent *bev;
	struct timeval interval;

	/* Delete old bev */
	bufferevent_free(state->bev);
	state->bev= NULL;

	/* And create a new one */
	create_bev(state);
	bev= state->bev;

	/* Connect failed, try next address */
	if (state->dns_curr)
			/* Just to be on the safe side */
	{
		state->dns_curr= state->dns_curr->ai_next;
	}
	while (state->dns_curr)
	{
		state->socklen= state->dns_curr->ai_addrlen;
		memcpy(&state->sin6, state->dns_curr->ai_addr,
			state->socklen);

		/* Clear result */
		state->reslen= 0;

		interval.tv_sec= CONN_TO;
		interval.tv_usec= 0;
		evtimer_add(&state->timer, &interval);

		gettimeofday(&state->start, NULL);
		if (bufferevent_socket_connect(bev,
			state->dns_curr->ai_addr,
			state->dns_curr->ai_addrlen) == 0)
		{
			/* Connecting, wait for callback */
			return;
		}

		/* Immediate error? */
		printf("connect error\n");
		state->dns_curr= state->dns_curr->ai_next;
	}

	/* Something went wrong */
	state->bev= NULL;
	bufferevent_free(bev);
	evutil_freeaddrinfo(state->dns_res);
	state->dns_res= NULL;
	report(state);
}

static void timeout_callback(int __attribute((unused)) unused,
	const short __attribute((unused)) event, void *s)
{
	struct hgstate *state;

	state= s;

	if (state->connecting)
	{
		add_str(state, ", " DBQ(err) ":" DBQ(connect: timeout));
		restart_connect(state);
		return;
	}
	switch(state->readstate)
	{
	case READ_STATUS:
		add_str(state, ", " DBQ(err) ":" DBQ(timeout reading status));
		report(state);
		break;
	case READ_HEADER:
		if (state->max_headers)
			add_str(s, " ]");
		add_str(state, ", " DBQ(err) ":" DBQ(timeout reading headers));
		report(state);
		break;
	case READ_SIMPLE:
#if 0	/* Enable when adding storing bodies */
		if (state->max_body)
			add_str(s, " ]");
#endif
		add_str(state, ", " DBQ(err) ":" DBQ(timeout reading body));
		report(state);
		break;
	case READ_CHUNKED:
	case READ_CHUNK_BODY:
#if 0	/* Enable when adding storing bodies */
		if (state->max_body)
			add_str(s, " ]");
#endif
		add_str(state, ", " DBQ(err) ":" DBQ(timeout reading chunk));
		report(state);
		break;
	default:
		printf("in timeout_callback, unhandled cased\n");
	}
}

static void *httpget_init(int __attribute((unused)) argc, char *argv[],
	void (*done)(void *state))
{
	int c, i, opt_delete_file, do_get, do_head, do_post,
		max_headers, max_body, only_v4, only_v6,
		do_summary, do_append, do_http10;
	size_t newsiz;
	char *url, *check;
	char *post_dir, *post_file, *output_file, *post_footer, *post_header,
		*A_arg, *store_headers, *store_body;
	const char *user_agent;
	char *host, *port, *hostport, *path;
	struct hgstate *state;

	/* Arguments */
	do_http10= 0;
	do_append= 0;
	do_get= 1;
	do_head= 0;
	do_post= 0;
	post_dir= NULL; 
	post_file= NULL; 
	post_footer=NULL;
	post_header=NULL;
	output_file= NULL;
	opt_delete_file = 0;
	store_headers= NULL;
	store_body= NULL;
	A_arg= NULL;
	only_v4= 0;
	only_v6= 0;
	do_summary= 0;
	user_agent= "httpget for atlas.ripe.net";

	if (!hg_base)
	{
		hg_base= httpget_base_new(EventBase);
		if (!hg_base)
			crondlog(DIE9 "httpget_base_new failed");
	}


	/* Allow us to be called directly by another program in busybox */
	optind= 0;
	while (c= getopt_long(argc, argv, "01A:O:46?", longopts, NULL), c != -1)
	{
		switch(c)
		{
		case '0':
			do_http10= 1;
			break;
		case '1':
			do_http10= 0;
			break;
		case 'a':				/* --append */
			do_append= 1;
			break;
		case 'A':
			A_arg= optarg;
			break;
		case 'O':
			output_file= optarg;
			break;
		case 'd':
			opt_delete_file = 1;
			break;
		case 'g':				/* --get */
			do_get = 1;
			do_head = 0;
			do_post = 0;
			break;
		case 'E':				/* --head */
			do_get = 0;
			do_head = 1;
			do_post = 0;
			break;
		case 'P':				/* --post */
			do_get = 0;
			do_head = 0;
			do_post = 1;
			break;
		case 'D':
			post_dir = optarg;		/* --post-dir */
			break;
		case 'h':				/* --post-header */
			post_header= optarg;
			break;
		case 'f':				/* --post-footer */
			post_footer= optarg;
			break;

		case 'p':				/* --post-file */
			post_file= optarg;
			break;
		case 'H':				/* --store-headers */
			store_headers= optarg;
			break;
		case 'B':				/* --store-body */
			store_body= optarg;
			break;
		case 'S':				/* --summary */
			do_summary= 1;
			break;
		case '4':
			only_v4= 1;
			only_v6= 0;
			break;
		case '6':
			only_v6= 1;
			only_v4= 0;
			break;
		case 'u':				/* --user-agent */
			user_agent= optarg;
			break;
		case '?':
			bb_show_usage();
			return NULL;
		default:
			crondlog(DIE9 "bad option '%c'", c);
		}
	}

	if (optind != argc-1)
		crondlog(DIE9 "exactly one url expected");
	url= argv[optind];

	max_headers= 0;
	max_body= UINT_MAX;	/* default is to write out the entire body */
	if (do_summary)
		max_body= 0;	/* default to no body if we want a summary */

	if (store_headers)
	{
		max_headers= strtoul(store_headers, &check, 10);
		if (check[0] != '\0')
		{
			crondlog(DIE9 "unable to parse argument '%s'",
				store_headers);
			return NULL;
		}
	}

	if (store_body)
	{
		max_body= strtoul(store_body, &check, 10);
		if (check[0] != '\0')
		{
			crondlog(DIE9 "unable to parse argument '%s'",
				store_body);
			return NULL;
		}
	}

	if (!parse_url(url, &host, &port, &hostport, &path))
	{
		/* Do we need to report an error? */
		return NULL;
	}

	//printf("host: %s\n", host);
	//printf("port: %s\n", port);
	//printf("hostport: %s\n", hostport);
	//printf("path: %s\n", path);

	state= xzalloc(sizeof(*state));
	state->base= hg_base;
	state->atlas= A_arg ? strdup(A_arg) : NULL;
	state->host= host;
	state->port= port;
	state->hostport= hostport;
	state->path= path;
	state->do_get= do_get;
	state->do_head= do_head;
	state->do_post= do_post;
	state->do_http10= do_http10;
	state->user_agent= user_agent;
	state->max_headers= max_headers;
	state->max_body= max_body;

	evtimer_assign(&state->timer, state->base->event_base,
		timeout_callback, state);

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

static void report(struct hgstate *state)
{
	int done;
	FILE *fh;
	char namebuf[NI_MAXHOST];

	event_del(&state->timer);

	if (state->out_filename)
	{
		fh= fopen(state->out_filename, "a");
		if (!fh)
			crondlog(DIE9 "unable to append to '%s'",
				state->out_filename);
	}
	else
		fh= stdout;

	fprintf(fh, "RESULT { ");
	if (state->atlas)
	{
		fprintf(fh, "\"id\":\"%s\", \"time\":%ld, ",
			state->atlas, (long)time(NULL));
	}

	fprintf(fh, DBQ(mode) ":" DBQ(%s%c/%c),
		state->do_get ? "GET" : state->do_head ? "HEAD" : "POST", 
		state->sin6.sin6_family == AF_INET6 ? '6' : '4',
		state->do_http10 ? '0' : '1');

	if (!state->dnserr)
	{
		getnameinfo((struct sockaddr *)&state->sin6, state->socklen,
			namebuf, sizeof(namebuf), NULL, 0, NI_NUMERICHOST);

		fprintf(fh, ", " DBQ(addr) ":" DBQ(%s), namebuf);
	}

	done= (state->readstate == READ_DONE);
	if (done)
	{
		namebuf[0]= '\0';
		getnameinfo((struct sockaddr *)&state->loc_sin6,
			state->loc_socklen, namebuf, sizeof(namebuf),
			NULL, 0, NI_NUMERICHOST);

		fprintf(fh, ", \"srcaddr\":\"%s\"", namebuf);

		fprintf(fh, ", " DBQ(rt) ":%f", state->resptime);
		fprintf(fh, ", " DBQ(res) ":%d", state->http_result);
		fprintf(fh, ", " DBQ(hsize) ":%d", state->headers_size);
		fprintf(fh, ", " DBQ(bsize) ":%d", state->content_offset);
	}

	fprintf(fh, "%s }\n", state->result);
	free(state->result);
	state->result= NULL;
	state->resmax= 0;
	state->reslen= 0;
	state->busy= 0;

	if (state->dns_res)
	{
		evutil_freeaddrinfo(state->dns_res);
		state->dns_res= NULL;
		state->dns_curr= NULL;
	}
	if (state->bev)
	{
		bufferevent_free(state->bev);
		state->bev= NULL;
	}

	if (state->out_filename)
		fclose(fh);

	if (state->base->done)
		state->base->done(state);
}

static int get_input(struct hgstate *state)
{
	int n;

	/* Assume that we always end up with a full buffer anyway */
	if (state->linemax == 0)
	{
		state->linemax= MAX_LINE_LEN;
		state->line= xmalloc(state->linemax);
	}

	if (state->lineoffset)
	{
		if (state->linelen > state->lineoffset)
		{
			memmove(state->line, &state->line[state->lineoffset],
				state->linelen-state->lineoffset);
			state->linelen -= state->lineoffset;
		}
		else
		{
			state->linelen= 0;
		}
		state->lineoffset= 0;
	}
	if (state->linelen >= state->linemax)
	{
		return -1;	/* We cannot get more data */
	}

	n= bufferevent_read(state->bev,
		&state->line[state->linelen],
		state->linemax-state->linelen);
	if (n < 0)
		return -1;
	state->linelen += n;
	return 0;
}

static void skip_spaces(const char *cp, char **ncp)
{
	const unsigned char *ucp;

	ucp= (const unsigned char *)cp;
	while (ucp[0] != '\0' && isspace(ucp[0]))
		ucp++;
	*ncp= (char *)ucp;
}

static void add_str(struct hgstate *state, const char *str)
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

static void err_status(struct hgstate *state, const char *reason)
{
	char line[80];
	snprintf(line, sizeof(line), ", "
		DBQ(err) ":" DBQ(bad status line: %s),
		reason);
	add_str(state, line);
	report(state);
}

static void err_header(struct hgstate *state, const char *reason)
{
	char line[80];
	snprintf(line, sizeof(line), " ], "
		DBQ(err) ":" DBQ(bad header line: %s),
		reason);
	add_str(state, line);
	report(state);
}

static void err_chunked(struct hgstate *state, const char *reason)
{
	char line[80];
	snprintf(line, sizeof(line), ", "
		DBQ(err) ":" DBQ(bad chunk line: %s),
		reason);
	add_str(state, line);
	report(state);
}

static void readcb(struct bufferevent *bev UNUSED_PARAM, void *ptr)
{
	int r, major, minor, need_line, no_body;
	size_t len;
	char *cp, *ncp, *check, *line;
	const char *prefix, *kw;
	struct hgstate *state;
	struct timeval endtime;

	state= ptr;

	for (;;)
	{
		switch(state->readstate)
		{
		case READ_STATUS:
		case READ_HEADER:
		case READ_CHUNKED:
		case READ_CHUNK_END:
		case READ_CHUNKED_TRAILER:
			need_line= 1;
			break;
		default:
			need_line= 0;
			break;
		}

		if (need_line)
		{
			/* Wait for a complete line */
			if (state->linemax == 0 ||
				memchr(&state->line[state->lineoffset], '\n',
				state->linelen-state->lineoffset) == NULL)
			{
				r= get_input(state);
				if (r == -1)
				{
					printf(
			"readcb: get_input failed, should do something\n");
					return;
				}

				/* Did we get what we want? */
				if (memchr(&state->line[state->lineoffset],
					'\n', state->linelen-state->lineoffset)
					== NULL)
				{
					/* No */
					if (state->linelen-state->lineoffset >=
						MAX_LINE_LEN)
					{
						add_str(state, ", " DBQ(err)
							":" DBQ(line too long));
						report(state);
					}
					return;
				}
			}
		}

		switch(state->readstate)
		{
		case READ_STATUS:
			line= &state->line[state->lineoffset];
			cp= strchr(line, '\n');
			if (cp == NULL)
			{
				/* Contains nul */
				err_status(state, "contains nul");
				return;
			}

			state->lineoffset += (cp-line+1);

			cp[0]= '\0';
			if (cp > line && cp[-1] == '\r')
				cp[-1]= '\0';

			/* Check http version */
			prefix= "http/";
			len= strlen(prefix);
			if (strncasecmp(prefix, line, len) != 0)
			{
				err_status(state, "bad prefix");
				return;
			}
			cp= line+len;

			major= strtoul(cp, &check, 10);
			if (check == cp || check[0] != '.')
			{
				err_status(state, "bad major");
				return;
			}

			cp= check+1;
			minor= strtoul(cp, &check, 10);
			if (check == cp || check[0] == '\0' ||
				!isspace(*(unsigned char *)check))
			{
				err_status(state, "bad minor");
				return;
			}

			skip_spaces(check, &cp);

			if (!isdigit(*(unsigned char *)cp))
			{
				err_status(state, "bad status code");
				return;
			}
			state->http_result= strtoul(cp, NULL, 10);

			state->readstate= READ_HEADER;
			state->content_length= -1;

			if (state->max_headers)
			{
				add_str(state, ", " DBQ(header) ": [");
			}

			continue;

		case READ_HEADER:
			line= &state->line[state->lineoffset];
			cp= strchr(line, '\n');
			if (cp == NULL)
			{
				err_header(state, "contains nul");
				return;
			}

			len= (cp-line+1);
			state->lineoffset += len;

			cp[0]= '\0';
			if (cp > line && cp[-1] == '\r')
				cp[-1]= '\0';

			if (line[0] == '\0')
			{
				if (state->tot_headers <= state->max_headers &&
					state->max_headers != 0)
				{
					if (state->tot_headers != 0)
						add_str(state, ",");
					add_str(state, " \"\"");
				}
				add_str(state, " ]");
				state->readstate= READ_BODY;
				continue;
			}

			state->headers_size += len;

			len= strlen(line);
			if (state->tot_headers+len+1 <= state->max_headers)
			{
				if (state->tot_headers != 0)
					add_str(state, ",");
				add_str(state, " \"");
				add_str(state, line);
				add_str(state, "\"");
				state->tot_headers += len;
			} else if (state->tot_headers <= state->max_headers &&
				state->max_headers != 0)
			{
				/* Fill up remaining space and report
				 * truncation */
				if (state->tot_headers != 0)
					add_str(state, ",");
				add_str(state, " \"");
				if (state->tot_headers < state->max_headers)
				{
					line[state->max_headers-
						state->tot_headers]= '\0';
					add_str(state, line);
				}
				add_str(state, "[...]\"");

				state->tot_headers += len+1;
			}

			cp= line;
			skip_spaces(cp, &ncp);
			if (ncp != line)
				continue;	/* Continuation line */

			cp= ncp;
			while (ncp[0] != '\0' && ncp[0] != ':' &&
				!isspace((unsigned char)ncp[0]))
			{
				ncp++;
			}

			kw= "Transfer-Encoding";
			len= strlen(kw);
			if (strncasecmp(cp, kw, len) == 0)
			{
				/* Skip optional white space */
				cp= ncp;
				skip_spaces(cp, &cp);

				if (cp[0] != ':')
				{
					err_header(state,
					"malformed transfer-encoding");
					return;
				}
				cp++;

				/* Skip more white space */
				skip_spaces(cp, &cp);

				/* Should have the value by now */
				kw= "chunked";
				len= strlen(kw);
				if (strncasecmp(cp, kw, len) != 0)
					continue;
				/* make sure we have end of line or white
				 * space */
				if (cp[len] != '\0' &&
					isspace((unsigned char)cp[len]))
				{
					continue;
				}
				state->chunked= 1;
				continue;
			}

			kw= "Content-length";
			len= strlen(kw);
			if (strncasecmp(cp, kw, len) != 0)
				continue;

			/* Skip optional white space */
			cp= ncp;
			skip_spaces(cp, &cp);

			if (cp[0] != ':')
			{
				err_header(state,
					"malformed content-length");
				return;
			}
			cp++;

			/* Skip more white space */
			skip_spaces(cp, &cp);

			/* Should have the value by now */
			state->content_length= strtoul(cp, &check, 10);
			if (check == cp)
			{
				err_header(state,
					"malformed content-length");
				return;
			}

			/* And after that we should have just white space */
			cp= check;
			skip_spaces(cp, &cp);

			if (cp[0] != '\0')
			{
				err_header(state,
					"malformed content-length");
				return;
			}
			continue;

		case READ_BODY:
			no_body= (state->do_head || state->http_result == 204 ||
				state->http_result == 304 ||
				state->http_result/100 == 1);

			if (no_body)
			{
				/* This reply will not have a body even if
				 * there is a content-length line.
				 */
				state->readstate= READ_DONE;
			}
			else if (state->chunked)
				state->readstate= READ_CHUNKED;
			else
			{
				state->readstate= READ_SIMPLE;
				state->content_offset= 0;
			}

			continue;

		case READ_CHUNKED:
			line= &state->line[state->lineoffset];
			cp= strchr(line, '\n');
			if (cp == NULL)
			{
				err_chunked(state, "contains nul");
				return;
			}

			len= (cp-line+1);
			state->lineoffset += len;

			cp[0]= '\0';
			if (cp > line && cp[-1] == '\r')
				cp[-1]= '\0';

			len= strtoul(line, &check, 16);
			if (check == line || (check[0] != '\0' &&
				!isspace(*(unsigned char *)check)))
			{
				err_chunked(state, "not a number");
				return;
			}

			if (!len)
			{
				state->readstate= READ_CHUNKED_TRAILER;
				continue;
			}

			state->tot_chunked += len;
			state->readstate= READ_CHUNK_BODY;
			continue;

		case READ_CHUNK_BODY:
			if (state->content_offset >= state->tot_chunked)
			{
				state->readstate= READ_CHUNK_END;
				continue;
			}

			/* Do we need more input? */
			if (state->linemax == 0 ||
				state->lineoffset >= state->linelen)
			{
				r= get_input(state);
				if (r == -1)
				{
					printf(
			"readcb: get_input failed, should do something\n");
					return;
				}

				/* Did we get what we want? */
				if (state->lineoffset >= state->linelen)
				{
					/* No */
					return;
				}
			}

			len= state->linelen-state->lineoffset;
			if (state->content_offset+len > state->tot_chunked)
				len= state->tot_chunked-state->content_offset;

			if (state->content_offset+len <= state->max_body)
			{
#if 0
				printf(
			"readcb: should report %ld bytes worth of content\n",
					len);
#endif
			}
			else if (state->content_offset <= state->max_body &&
				state->max_body != 0)
			{
				/* Fill up remaining space and report
				 * truncation */
				if (state->content_offset < state->max_body)
				{
					len= state->max_body -
						state->content_offset;
#if 0
					printf(
			"readcb: should report %ld bytes worth of content\n",
						len);
#endif

				}
				printf(
				"readcb: should add truncation indicator\n");
			}

			state->content_offset += len;
			state->lineoffset += len;

			continue;

		case READ_CHUNK_END:
			line= &state->line[state->lineoffset];
			cp= strchr(line, '\n');
			if (cp == NULL)
			{
				err_chunked(state, "contains nul");
				return;
			}

			len= (cp-line+1);
			state->lineoffset += len;

			cp[0]= '\0';
			if (cp > line && cp[-1] == '\r')
				cp[-1]= '\0';

			if (strlen(line) != 0)
			{
				err_chunked(state,
					"garbage at the end of chunk");
				return;
			}

			state->readstate= READ_CHUNKED;
			continue;

		case READ_CHUNKED_TRAILER:
			line= &state->line[state->lineoffset];
			cp= strchr(line, '\n');
			if (cp == NULL)
			{
				err_chunked(state, "contains nul");
				return;
			}

			len= (cp-line+1);
			state->lineoffset += len;

			cp[0]= '\0';
			if (cp > line && cp[-1] == '\r')
				cp[-1]= '\0';

			if (line[0] == '\0')
			{
				state->readstate= READ_DONE;
				continue;
			}
			continue;

		case READ_SIMPLE:
			if (state->content_length >= 0 &&
				state->content_offset >= state->content_length)
			{
				state->readstate= READ_DONE;
				continue;
			}

			/* Do we need more input? */
			if (state->linemax == 0 ||
				state->lineoffset >= state->linelen)
			{
				r= get_input(state);
				if (r == -1)
				{
					printf(
			"readcb: get_input failed, should do something\n");
					return;
				}

				/* Did we get what we want? */
				if (state->lineoffset >= state->linelen)
				{
					/* No */
					return;
				}
			}

			len= state->linelen-state->lineoffset;
			if (state->content_offset+len <= state->max_body)
			{
#if 0
				printf(
			"readcb: should report %ld bytes worth of content\n",
					len);
#endif
			}
			else if (state->content_offset <= state->max_body &&
				state->max_body != 0)
			{
				/* Fill up remaining space and report
				 * truncation */
				if (state->content_offset < state->max_body)
				{
					len= state->max_body -
						state->content_offset;
#if 0
					printf(
			"readcb: should report %ld bytes worth of content\n",
						len);
#endif

				}
				printf(
				"readcb: should add truncation indicator\n");
			}

			state->content_offset += len;
			state->lineoffset += len;

			continue;

		case READ_DONE:
			if (state->bev)
			{
				bufferevent_free(state->bev);
				state->bev= NULL;

				gettimeofday(&endtime, NULL);
				state->resptime=
					(endtime.tv_sec-
					state->start.tv_sec)*1e3 +
					(endtime.tv_usec-
					state->start.tv_usec)/1e3;
				report(state);
			}
			return;
		default:
			printf("readcb: readstate = %d\n", state->readstate);
			return;
		}
	}
}

static void writecb(struct bufferevent *bev, void *ptr)
{
	struct hgstate *state;
	struct evbuffer *output;
	off_t cLength;

	state= ptr;
	if (state->writestate == WRITE_HEADER)
	{
		output= bufferevent_get_output(bev);
		evbuffer_add_printf(output, "%s %s HTTP/1.%c\r\n",
			state->do_get ? "GET" :
			state->do_head ? "HEAD" : "POST", state->path,
			state->do_http10 ? '0' : '1');
		evbuffer_add_printf(output, "Host: %s\r\n", state->host);
		evbuffer_add_printf(output, "Connection: close\r\n");
		evbuffer_add_printf(output, "User-Agent: %s\r\n",
			state->user_agent);
		if (state->do_post)
		{
			evbuffer_add_printf(output,
			"Content-Type: application/x-www-form-urlencoded\r\n");
		}

		cLength= 0;
#if 0
		if( post_header != NULL )
			cLength  +=  sbH.st_size;

		if (post_file)
			cLength  += sbS.st_size;

		if (post_dir)
			cLength += dir_length;

		if( post_footer != NULL )
			cLength  +=  sbF.st_size;
#endif

		if (state->do_post)
		{
			evbuffer_add_printf(output, "Content-Length: %lu\r\n",
				(unsigned long)cLength);
		}
		evbuffer_add_printf(output, "\r\n");
		state->writestate = WRITE_DONE;
	}

}


static void create_bev(struct hgstate *state)
{
	struct bufferevent *bev;
	struct hgbase *base;

	base= state->base;

	bev= bufferevent_socket_new(base->event_base, -1,
		BEV_OPT_CLOSE_ON_FREE);
	if (!bev)
	{
		crondlog(DIE9 "bufferevent_socket_new failed");
	}
	bufferevent_setcb(bev, readcb, writecb, eventcb, state);
	bufferevent_enable(bev, EV_READ|EV_WRITE);
	state->bev= bev;
}

static void err_reading(struct hgstate *state)
{
	struct timeval endtime;
	switch(state->readstate)
	{
	case READ_STATUS:
		add_str(state, ", " DBQ(err) ":" DBQ(error reading status));
		report(state);
		break;
	case READ_HEADER:
		if (state->max_headers)
			add_str(state, " ]");
		add_str(state, ", " DBQ(err) ":" DBQ(error reading headers));
		report(state);
		break;
	case READ_SIMPLE:
#if 0
		if (state->max_body)
			add_str(state, " ]");
#endif
		if (state->content_length == -1)
		{
			/* EOF is normal */
			state->readstate= READ_DONE;
		}
		else
		{
			add_str(state, ", " DBQ(err) ":"
				DBQ(error reading body));
		}
		gettimeofday(&endtime, NULL);
		state->resptime= (endtime.tv_sec-state->start.tv_sec)*1e3 +
			(endtime.tv_usec-state->start.tv_usec)/1e3;
		report(state);
		break;
	default:
		printf("in err_reading, unhandled case\n");
	}
}

static void eventcb(struct bufferevent *bev, short events, void *ptr)
{
	struct hgstate *hgstate;
	char line[80];

	hgstate= ptr;
	if (hgstate->connecting)
	{
		/* Clear some events we don't want to see */
		events &= ~(BEV_EVENT_READING|BEV_EVENT_ERROR);
	}

	if (events & BEV_EVENT_READING)
	{
		err_reading(hgstate);
		events &= ~BEV_EVENT_READING;
		return;
	}
	if (events & BEV_EVENT_ERROR)
	{
		printf("eventcb: unrecoverable error encountered\n");
		events &= ~BEV_EVENT_ERROR;
	}
	if (events & BEV_EVENT_CONNECTED)
	{
		if (errno != EINPROGRESS)
		{
			snprintf(line, sizeof(line),
				", " DBQ(err) ":" DBQ(connect: %s),
				strerror(errno));
			add_str(hgstate, line);

			restart_connect(hgstate);

			return;
		}
		events &= ~BEV_EVENT_CONNECTED;
		hgstate->connecting= 0;

		hgstate->loc_socklen= sizeof(hgstate->loc_sin6);
		getsockname(bufferevent_getfd(bev),	
			&hgstate->loc_sin6, &hgstate->loc_socklen);

		writecb(bev, ptr);
	}
	if (events)
		printf("events = 0x%x\n", events);
}

static void dns_cb(int result, struct evutil_addrinfo *res, void *state)
{
	struct hgstate *hgstate;
	struct hgbase *base;
	struct bufferevent *bev;
	struct timeval interval;
	char line[80];

	hgstate= state;
	base= hgstate->base;

	if (result != 0)
	{
		snprintf(line, sizeof(line), ", " DBQ(dnserr) ":" DBQ(%s),
			evutil_gai_strerror(result));
		add_str(state, line);
		hgstate->dnserr= 1;
		report(state);
		return;
	}

	hgstate->dns_res= res;
	hgstate->dns_curr= res;

	create_bev(hgstate);
	bev= hgstate->bev;

	while (hgstate->dns_curr)
	{
		hgstate->socklen= hgstate->dns_curr->ai_addrlen;
		memcpy(&hgstate->sin6, hgstate->dns_curr->ai_addr,
			hgstate->socklen);

		interval.tv_sec= CONN_TO;
		interval.tv_usec= 0;
		evtimer_add(&hgstate->timer, &interval);

		gettimeofday(&hgstate->start, NULL);
		if (bufferevent_socket_connect(bev,
			hgstate->dns_curr->ai_addr,
			hgstate->dns_curr->ai_addrlen) == 0)
		{
			/* Connecting, wait for callback */
			return;
		}

		/* Immediate error? */
		printf("connect error\n");
		hgstate->dns_curr= hgstate->dns_curr->ai_next;
	}

	/* Something went wrong */
	printf("Connect failed\n");
	hgstate->bev= NULL;
	bufferevent_free(bev);
	evutil_freeaddrinfo(hgstate->dns_res);
	hgstate->dns_res= NULL;
	report(state);
}

static void httpget_start(void *state)
{
	struct hgstate *hgstate;
	struct evdns_getaddrinfo_request *evdns_req;
	struct evutil_addrinfo hints;

	hgstate= state;

	if (hgstate->busy)
	{
		printf("httget_start: busy\n");
		return;
	}
	hgstate->busy= 1;

	hgstate->connecting= 1;
	hgstate->readstate= READ_STATUS;
	hgstate->writestate= WRITE_HEADER;

	hgstate->linelen= 0;
	hgstate->lineoffset= 0;
	hgstate->headers_size= 0;
	hgstate->tot_headers= 0;

	memset(&hints, '\0', sizeof(hints));
	hints.ai_socktype= SOCK_STREAM;
	evdns_req= evdns_getaddrinfo(DnsBase, hgstate->host, hgstate->port,
		&hints, dns_cb, state);

#if 0
	if (post_dir)
	{
		filelist= do_dir(post_dir, &dir_length);
		if (!filelist)
		{
			/* Something went wrong. */
			goto err;
		}
		if (debug)
		{
			fprintf(stderr, "total size in dir: %ld\n",
				(long)dir_length);
		}
	}

	if(post_header != NULL )
	{	
		fdH = open(post_header, O_RDONLY);
		if(fdH == -1 )
		{
			report_err("unable to open header '%s'", post_header);
			goto err;
		}
		if (fstat(fdH, &sbH) == -1)
		{
			report_err("fstat failed on header file '%s'",
				post_header);
			goto err;
		}
		if (!S_ISREG(sbH.st_mode))
		{
			report("'%s' header is not a regular file",
				post_header);
			goto err;
		}
	}

	if(post_footer != NULL )
	{	
		fdF = open(post_footer, O_RDONLY);
		if(fdF == -1 )
		{
			report_err("unable to open footer '%s'", post_footer);
			goto err;
		}
		if (fstat(fdF, &sbF) == -1)
		{
			report_err("fstat failed on footer file '%s'",
				post_footer);
			goto err;
		}
		if (!S_ISREG(sbF.st_mode))
		{
			report("'%s' footer is not a regular file",
				post_footer);
			goto err;
		}
	}

	/* Try to open the file before trying to connect */
	if (post_file != NULL)
	{
		fdS= open(post_file, O_RDONLY);
		if (fdS == -1)
		{
			report_err("unable to open '%s'", post_file);
			goto err;
		}
		if (fstat(fdS, &sbS) == -1)
		{
			report_err("fstat failed");
			goto err;
		}
		if (!S_ISREG(sbS.st_mode))
		{
			report("'%s' is not a regular file", post_file);
			goto err;
		}
	}

	sa.sa_flags= 0;
	sa.sa_handler= got_alarm;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGALRM, &sa, NULL);
	if (debug) fprintf(stderr, "setting alarm\n");
	alarm(10);
	signal(SIGPIPE, SIG_IGN);

	if (output_file)
	{
		out_file= fopen(output_file, do_append ? "a" : "w");
		if (!out_file)
		{
			report_err("unable to create '%s'", output_file);
			goto err;
		}
		out_file_needs_closing= 1;
	}
	else
		out_file= stdout;


	/* Stdio makes life easy */
	tcp_file= fdopen(tcp_fd, "r+");
	if (tcp_file == NULL)
	{
		report("fdopen failed");
		goto err;
	}
	tcp_fd= -1;

	if (debug) fprintf(stderr, "httpget: sending request\n");
	fprintf(tcp_file, "%s %s HTTP/1.%c\r\n",
		do_get ? "GET" : do_head ? "HEAD" : "POST", path,
		do_http10 ? '0' : '1');
	fprintf(tcp_file, "Host: %s\r\n", host);
	fprintf(tcp_file, "Connection: close\r\n");
	fprintf(tcp_file, "User-Agent: %s\r\n", user_agent);
	if (do_post)
	{
		fprintf(tcp_file,
			"Content-Type: application/x-www-form-urlencoded\r\n");
	}

	cLength= 0;
	if( post_header != NULL )
		cLength  +=  sbH.st_size;

	if (post_file)
		cLength  += sbS.st_size;

	if (post_dir)
		cLength += dir_length;

	if( post_footer != NULL )
		cLength  +=  sbF.st_size;

	fprintf(tcp_file, "Content-Length: %lu\r\n", (unsigned long)cLength);
	fprintf(tcp_file, "\r\n");

	if( post_header != NULL )
	{
		 if (!write_to_tcp_fd(fdH, tcp_file))
		 {
		 	printf("write_to_tcp_fd failed\n");
		 	goto fail;
		}
	}

	if (post_file != NULL)
	{
		if (!write_to_tcp_fd(fdS, tcp_file))
		{
		 	printf("write_to_tcp_fd failed\n");
		 	goto fail;
		}
	}

	if (post_dir)
	{
		for (p= filelist; p[0] != 0; p += strlen(p)+1)
		{
			if (debug) fprintf(stderr, "posting file '%s'\n", p);
			fd= open(p, O_RDONLY);
			if (fd == -1)
			{
				report_err("unable to open '%s'", p);
				goto err;
			}
			r= write_to_tcp_fd(fd, tcp_file);
			close(fd);
			fd= -1;
			if (!r)
			{
				printf("write_to_tcp_fd failed\n");
				goto fail;
			}
		}
	}

	if( post_footer != NULL)
	{
		if (!write_to_tcp_fd(fdF, tcp_file))
		{
			printf("write_to_tcp_fd failed\n");
			goto fail;
		}
	}

	if (debug) fprintf(stderr, "httpget: writing output\n");
	do_multiline= (A_arg && (max_headers != 0 || max_body != 0));
	if (do_multiline)
	{
		fd= open("/dev/urandom", O_RDONLY);
		read(fd, rndbuf, sizeof(rndbuf));
		close(fd);
		fprintf(out_file, "BEGINRESULT ");
		for (i= 0; i<sizeof(rndbuf); i++)
			fprintf(out_file, "%02x", (unsigned char)rndbuf[i]);
		fprintf(out_file, " %s %ld\n", A_arg, (long)time(NULL));
	}

	if (debug) fprintf(stderr, "httpget: getting result\n");
	if (!check_result(tcp_file, &http_result))
	{
		printf("check_result failed\n");
		goto fail;
	}
	if (debug) fprintf(stderr, "httpget: getting reply headers \n");
	if (!eat_headers(tcp_file, &chunked, &content_length, &headers_size,
		out_file, max_headers))
	{
		printf("eat_headers failed\n");
		goto fail;
	}
	
	no_body= (do_head || http_result == 204 || http_result == 304 ||
		http_result/100 == 1);

	if (max_headers != 0 && max_body != 0)
		fprintf(out_file, "\n");	/* separate headers from body */

	if (no_body)
	{
		/* This reply will not have a body even if there is a
		 * content-length line.
		 */
	}
	else if (chunked)
	{
		if (!copy_chunked(tcp_file, out_file, &content_length,
			max_body))
		{
			printf("copy_chunked failed\n");
			goto fail;
		}
	}
	else
	{
		if (!copy_bytes(tcp_file, out_file, &content_length, max_body))
		{
			printf("copy_bytes failed\n");
			goto fail;
		}
	}

fail:
	gettimeofday(&tv_end, NULL);

	tv_end.tv_sec -= tv_start.tv_sec;
	tv_end.tv_usec -= tv_start.tv_usec;
	if (tv_end.tv_usec < 0)
	{
		tv_end.tv_usec += 1000000;
		tv_end.tv_sec--;
	}

	if (do_multiline)
	{
		fprintf(out_file, "ENDRESULT ");
		for (i= 0; i<sizeof(rndbuf); i++)
			fprintf(out_file, "%02x", (unsigned char)rndbuf[i]);
		fprintf(out_file, "\n");
	}

	if (A_arg && do_summary)
	{
		fprintf(out_file, "%s %ld ",
			A_arg, (long)time(NULL));
	}
	if (do_summary)
	{
		const char *v, *cmd;

		if (do_get)
			cmd= "GET";
		else if (do_head)
			cmd= "HEAD";
		else
			cmd= "POST";
		if (family == AF_INET)
			v= "4";
		else if (family == AF_INET6)
			v= "6";
		else
			v= "?";

		fprintf(out_file, "%s%s %s %d.%06d %03u %d %d\n",
			cmd, v, 
			host_addr, (int)tv_end.tv_sec, (int)tv_end.tv_usec,
			http_result, headers_size, content_length);
	}

	if (debug) fprintf(stderr, "httpget: deleting files\n");
	if ( opt_delete_file == 1 )
	{
		if (post_file)
			unlink (post_file);
		if (post_dir)
		{
			for (p= filelist; p[0] != 0; p += strlen(p)+1)
			{
				if (debug)
				{
					fprintf(stderr,
						"unlinking file '%s'\n", p);
				}
				if (unlink(p) != 0)
					report_err("unable to unlink '%s'", p);
			}
		}
	}
	if (debug) fprintf(stderr, "httpget: done\n");

	result= 0;

leave:
	if (fdH != -1) close(fdH);
	if (fdF != -1) close(fdF);
	if (fdS != -1) close(fdS);
	if (fd != -1) close(fd);
	if (tcp_file) fclose(tcp_file);
	if (tcp_fd != -1) close(tcp_fd);
	if (out_file && out_file_needs_closing) fclose(out_file);
	if (host) free(host);
	if (port) free(port);
	if (hostport) free(hostport);
	if (path) free(path);
	if (filelist) free(filelist);

	printf("clearing alarm\n");
	alarm(0);
	signal(SIGPIPE, SIG_DFL);

	return result; 

err:
	result= 1;
	goto leave;
#endif
}

static int httpget_delete(void *state)
{
	int ind;
	struct hgstate *hgstate;
	struct hgbase *base;

	hgstate= state;

	printf("httpget_delete: state %p, index %d, busy %d\n",
		state, hgstate->index, hgstate->busy);

	if (hgstate->busy)
		return 0;

	base= hgstate->base;
	ind= hgstate->index;

	if (base->table[ind] != hgstate)
		crondlog(DIE9 "strange, state not in table");
	base->table[ind]= NULL;

	event_del(&hgstate->timer);

	free(hgstate->atlas);
	hgstate->atlas= NULL;
	free(hgstate->hostport);
	hgstate->hostport= NULL;
	free(hgstate->path);
	hgstate->path= NULL;

	free(hgstate);

	return 1;
}

struct testops httpget_ops = { httpget_init, httpget_start,
	httpget_delete };

