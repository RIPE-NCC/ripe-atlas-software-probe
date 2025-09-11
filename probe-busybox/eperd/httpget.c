/*
 * Copyright (c) 2013-2014 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * httpget.c -- libevent-based version of httpget
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
#include "atlas_path.h"

#define SAFE_PREFIX_IN_REL ATLAS_DATA_OUT_REL
#define SAFE_PREFIX_OUT_REL ATLAS_DATA_NEW_REL

#define CONN_TO		   5000		/* Timeout in milliseconds */

#define ENV2STATE(env) \
	((struct hgstate *)((char *)env - offsetof(struct hgstate, tu_env)))

#define DBQ(str) "\"" #str "\""

#define MAX_LINE_LEN	2048	/* We don't deal with lines longer than this */
#define POST_BUF_SIZE	2048	/* Big enough to be efficient? */

#define RESP_PACKET	1
#define RESP_SOCKNAME	2
#define RESP_DSTADDR	3
#define RESP_READ_ERROR	4

static struct option longopts[]=
{
	{ "all",	no_argument, NULL, 'a' },
	{ "combine",	no_argument, NULL, 'c' },
	{ "get",	no_argument, NULL, 'g' },
	{ "head",	no_argument, NULL, 'E' },
	{ "host",	required_argument, NULL, 'n' },
	{ "post",	no_argument, NULL, 'P' },
	{ "post-file",	required_argument, NULL, 'p' },
	{ "post-header", required_argument, NULL, 'h' },
	{ "post-footer", required_argument, NULL, 'f' },
	{ "read-limit",	required_argument, NULL, 'r' },
	{ "store-headers", required_argument, NULL, 'H' },
	{ "store-body",	required_argument, NULL, 'B' },
	{ "user-agent",	required_argument, NULL, 'u' },
	{ "sni",	required_argument, NULL, 's' },
	{ "timeout",	required_argument, NULL, 'S' },
	{ "etim",	no_argument, NULL, 't' },
	{ "eetim",	no_argument, NULL, 'T' },
	{ NULL, }
};

enum readstate { READ_FIRST, READ_STATUS, READ_HEADER, READ_BODY, READ_SIMPLE,
	READ_CHUNKED, READ_CHUNK_BODY, READ_CHUNK_END, READ_CHUNKED_TRAILER,
	READ_DONE };
enum writestate { WRITE_FIRST, WRITE_HEADER, WRITE_POST_HEADER,
	WRITE_POST_FILE, WRITE_POST_FOOTER, WRITE_DONE };

struct hgbase
{
	struct event_base *event_base;

	struct hgstate **table;
	size_t tabsiz;

	/* For standalone httpget. Called when a httpget instance is
	 * done. Just one pointer for all instances. It is up to the caller
	 * to keep it consistent.
	 */
	void (*done)(void *state, int error);
};

struct hgstate
{
	/* Parameters */
	char *output_file;
	char *atlas;
	char *bundle;
	char do_all;
	char do_combine;
	char only_v4;
	char only_v6;
	char do_get;
	char do_head;
	char do_post;
	bool do_tls;
	char do_http10;
	char *user_agent;
	char *post_header;
	char *post_file;
	char *post_footer;
	int max_headers;
	int max_body;
	int etim;
	size_t read_limit;
	unsigned timeout;
	char *infname;
	char *response_in;	/* Fuzzing */
	char *response_out;

	/* State */
	char busy;
	struct tu_env tu_env;
	char dnserr;
	char connecting;
	char in_writecb;
	char *host;
	char *port;
	char *hostport;
	char *path;
	char *sni;
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
	struct timespec start;
	double resptime;
	double ttr;		/* Time to resolve */
	double ttc;		/* Time to connect */
	double ttfb;		/* Time to first byte */
	int roffset;
	int report_roffset;
	int first_connect;
	int read_truncated;
	FILE *post_fh;
	char *post_buf;

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

	char *result2;
	size_t reslen2;
	size_t resmax2;

	FILE *resp_file;	/* Fuzzing */
};

static struct hgbase *hg_base;

static void report(struct hgstate *state);
static void add_str(struct hgstate *state, const char *str);
static void add_str_quoted(struct hgstate *state, char *str);
static void add_str2(struct hgstate *state, const char *str);

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
	char **pathp, bool *do_tls)
{
	char *item;
	const char *cp, *np, *prefix;
	size_t len;
#if ENABLE_FEATURE_EVHTTPGET_HTTPS
	const char *prefixs;
       	size_t lens;
#endif

	*hostp= NULL;
	*portp= NULL;
	*hostportp= NULL;
	*pathp= NULL;
	*do_tls = 0;

	/* the url must start with 'http://' */
	prefix= "http://";
#if ENABLE_FEATURE_EVHTTPGET_HTTPS
	prefixs = "https://";
	lens= strlen(prefixs);
#endif
	len= strlen(prefix);
	if (strncasecmp(prefix, url, len) == 0) 
	{
		*do_tls = 0;
	}
#if ENABLE_FEATURE_EVHTTPGET_HTTPS	
	else if (strncasecmp(prefixs, url, lens) == 0)
	{
		len = lens;
		*do_tls = 1;
	}
#endif
	else
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
	if ((cp[0] == '\0') && *do_tls)
		cp= "443";
	else if ((cp[0] == '\0') && !*do_tls)
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

static void timeout_callback(int __attribute((unused)) unused,
	const short __attribute((unused)) event, void *s)
{
	struct hgstate *state;
	char errline[256];

	state= ENV2STATE(s);

	if (state->connecting)
	{
		add_str(state, DBQ(err) ":" DBQ(connect: timeout) ", ");
		if (state->do_all)
			report(state);
		else
			tu_restart_connect(&state->tu_env);
		return;
	}
	switch(state->readstate)
	{
	case READ_FIRST:
	case READ_STATUS:
		add_str(state, DBQ(err) ":" DBQ(timeout reading status) ", ");
		report(state);
		break;
	case READ_HEADER:
		if (state->max_headers)
			add_str(state, " ], ");
		add_str(state, ", " DBQ(err) ":" DBQ(timeout reading headers));
		report(state);
		break;
	case READ_SIMPLE:
#if 0	/* Enable when adding storing bodies */
		if (state->max_body)
			add_str(s, " ]");
#endif
		add_str(state, DBQ(err) ":" DBQ(timeout reading body) ", ");
		report(state);
		break;
	case READ_CHUNKED:
	case READ_CHUNK_BODY:
#if 0	/* Enable when adding storing bodies */
		if (state->max_body)
			add_str(s, " ]");
#endif
#if 1
		snprintf(errline, sizeof(errline), 
			DBQ(err) ":"
	DBQ(timeout reading chunk: state %ld linelen %ld lineoffset %ld)
			", ",
			(long)state->readstate,
			(long)state->linelen,
			(long)state->lineoffset);
		add_str(state, errline);
#else
		add_str(state, DBQ(err) ":" DBQ(timeout reading chunk) ", ");
#endif
		report(state);
		break;
	default:
		printf("in timeout_callback, unhandled cased: %d\n",
			state->readstate);
	}
}

static void *httpget_init(int __attribute((unused)) argc, char *argv[],
	void (*done)(void *state, int error))
{
	int c, do_combine, do_get, do_head, do_post,
		max_headers, max_body, only_v4, only_v6,
		do_all, do_http10, do_etim, do_eetim;
	bool do_tls;
	size_t i, newsiz, read_limit;
	unsigned timeout;
	char *url, *check;
	char *host_arg, *post_file, *output_file, *post_footer, *post_header,
		*A_arg, *b_arg, *store_headers, *store_body, *read_limit_str,
		*timeout_str, *infname, *response_in, *response_out;
	char *validated_response_in= NULL;
	char *validated_response_out= NULL;
	char *validated_output_file= NULL;
	char *validated_post_header= NULL;
	char *validated_post_file= NULL;
	char *validated_post_footer= NULL;
	const char *sni, *user_agent;
	char *host, *port, *hostport, *path;
	struct hgstate *state;
	FILE *fh;

	/* Arguments */
	do_http10= 0;
	do_all= 0;
	do_combine= 0;
	do_get= 1;
	do_head= 0;
	do_post= 0;
	do_tls = 0;
	host_arg= NULL;
	post_file= NULL; 
	post_footer=NULL;
	post_header=NULL;
	output_file= NULL;
	store_headers= NULL;
	store_body= NULL;
	read_limit_str= NULL;
	timeout_str= NULL;
	A_arg= NULL;
	b_arg= NULL;
	infname= NULL;
	response_in= NULL;
	response_out= NULL;
	only_v4= 0;
	only_v6= 0;
	sni= NULL;
	do_etim= 0;
	do_eetim= 0;
	user_agent= "httpget for atlas.ripe.net";

	if (!hg_base)
	{
		hg_base= httpget_base_new(EventBase);
		if (!hg_base)
			crondlog(DIE9 "httpget_base_new failed");
	}


	/* Allow us to be called directly by another program in busybox */
	optind= 0;
	while (c= getopt_long(argc, argv, "01ab:A:cI:O:R:W:46", longopts, NULL),
		c != -1)
	{
		switch(c)
		{
		case '0':
			do_http10= 1;
			break;
		case '1':
			do_http10= 0;
			break;
		case '4':
			only_v4= 1;
			only_v6= 0;
			break;
		case '6':
			only_v6= 1;
			only_v4= 0;
			break;
		case 'A':
			A_arg= optarg;
			break;
		case 'R':
			response_in= optarg;
			break;
		case 'W':
			response_out= optarg;
			break;
		case 'a':				/* --all */
			do_all= 1;
			break;
		case 'b':
			b_arg= optarg;
			break;
		case 'B':				/* --store-body */
			store_body= optarg;
			break;
		case 'c':				/* --combine */
			do_combine= 1;
			break;
		case 'E':				/* --head */
			do_get = 0;
			do_head = 1;
			do_post = 0;
			break;
		case 'g':				/* --get */
			do_get = 1;
			do_head = 0;
			do_post = 0;
			break;
		case 'f':				/* --post-footer */
			post_footer= optarg;
			break;
		case 'H':				/* --store-headers */
			store_headers= optarg;
			break;
		case 'h':				/* --post-header */
			post_header= optarg;
			break;
		case 'I':
			infname= optarg;
			break;
		case 'n':
			host_arg= optarg;		/* --host */
			break;
		case 'O':
			output_file= optarg;
			break;
		case 'P':				/* --post */
			do_get = 0;
			do_head = 0;
			do_post = 1;
			break;
		case 'p':				/* --post-file */
			post_file= optarg;
			break;
		case 'r':
			read_limit_str= optarg;		/* --read-limit */
			break;
		case 'T':				/* --etim */
			do_eetim= 1;
			break;
		case 't':				/* --etim */
			do_etim= 1;
			break;
		case 's':
			sni= optarg;			/* --sni */
			break;
		case 'S':
			timeout_str= optarg;		/* --timeout */
			break;
		case 'u':				/* --user-agent */
			user_agent= optarg;
			break;
		default:
			crondlog(LVL8 "bad option '%c'", c);
			return NULL;
		}
	}

	if (optind != argc-1)
	{
		crondlog(LVL8 "exactly one url expected");
		return NULL;
	}
	url= argv[optind];

	if (response_in)
	{
		validated_response_in= rebased_validated_filename(ATLAS_SPOOLDIR,
			response_in, ATLAS_FUZZING_REL);
		if (validated_response_in == NULL)
		{
			crondlog(LVL8 "insecure fuzzing file '%s'",
				response_in);
			goto err;
		}
	}
	if (response_out)
	{
		validated_response_out= rebased_validated_filename(ATLAS_SPOOLDIR,
			response_out, ATLAS_FUZZING_REL);
		if (validated_response_out == NULL)
		{
			crondlog(LVL8 "insecure fuzzing file '%s'",
				response_out);
			goto err;
		}
	}

	if (output_file)
	{
		validated_output_file= rebased_validated_filename(ATLAS_SPOOLDIR,
			output_file, SAFE_PREFIX_OUT_REL);
		if (validated_output_file == NULL)
		{
			crondlog(LVL8 "insecure file '%s'", output_file);
			goto err;
		}
		fh= fopen(validated_output_file, "a");
		if (!fh)
		{
			crondlog(LVL8 "httpget: unable to append to '%s'",
				validated_output_file);
			goto err;
		}
		fclose(fh);
	}

	if (A_arg)
	{
		if (!validate_atlas_id(A_arg))
		{
			crondlog(LVL8 "bad atlas ID '%s'", A_arg);
			goto err;
		}
	}
	if (b_arg)
	{
		if (!validate_atlas_id(b_arg))
		{
			crondlog(LVL8 "bad bundle ID '%s'", b_arg);
			goto err;
		}
	}

	if (post_header)
	{
		validated_post_header= rebased_validated_filename(ATLAS_SPOOLDIR,
			post_header, SAFE_PREFIX_IN_REL);
		if (validated_post_header == NULL)
		{
			crondlog(LVL8 "insecure file '%s'", post_header);
			goto err;
		}
	}
	if (post_file)
	{
		validated_post_file= rebased_validated_filename(ATLAS_SPOOLDIR,
			post_file, SAFE_PREFIX_IN_REL);
		if (validated_post_file == NULL)
		{
			crondlog(LVL8 "insecure file '%s'", post_file);
			goto err;
		}
	}
	if (post_footer)
	{
		validated_post_footer= rebased_validated_filename(ATLAS_SPOOLDIR,
			post_footer, SAFE_PREFIX_IN_REL);
		if (validated_post_footer == NULL)
		{
			crondlog(LVL8 "insecure file '%s'", post_footer);
			goto err;
		}
	}

	max_headers= 0;
	max_body= UINT_MAX;	/* default is to write out the entire body */

	if (store_headers)
	{
		max_headers= strtoul(store_headers, &check, 10);
		if (check[0] != '\0')
		{
			crondlog(LVL8
			"unable to parse argument (--store-headers) '%s'",
				store_headers);
			return NULL;
		}
	}

	if (store_body)
	{
		max_body= strtoul(store_body, &check, 10);
		if (check[0] != '\0')
		{
			crondlog(LVL8
				"unable to parse argument (--store-body) '%s'",
				store_body);
			return NULL;
		}
	}

	read_limit= 0;
	if (read_limit_str)
	{
		read_limit= strtoul(read_limit_str, &check, 10);
		if (check[0] != '\0')
		{
			crondlog(LVL8
				"unable to parse argument (--read-limit) '%s'",
				read_limit_str);
			return NULL;
		}
	}

	timeout= CONN_TO;
	if (timeout_str)
	{
		timeout= strtoul(timeout_str, &check, 10);
		if (check[0] != '\0')
		{
			crondlog(LVL8
				"unable to parse argument (--timeout) '%s'",
				timeout_str);
			return NULL;
		}
	}

	if (!parse_url(url, &host, &port, &hostport, &path, &do_tls))
	{
		/* Do we need to report an error? */
		return NULL;
	}

	if (host_arg)
	{
		/* Replace hostport from the URL with host_arg */
		free(hostport);
		hostport= strdup(host_arg);
	}

	//printf("host: %s\n", host);
	//printf("port: %s\n", port);
	//printf("hostport: %s\n", hostport);
	//printf("path: %s\n", path);

	state= xzalloc(sizeof(*state));
	state->base= hg_base;
	state->atlas= A_arg ? strdup(A_arg) : NULL;
	state->bundle= b_arg ? strdup(b_arg) : NULL;
	state->output_file= validated_output_file;
		validated_output_file= NULL;
	state->response_in= validated_response_in;
		validated_response_in= NULL;
	state->response_out= validated_response_out;
		validated_response_out= NULL;
	state->host= host;
	state->port= port;
	state->hostport= hostport;
	state->path= path;
	state->do_all= do_all;
	state->do_combine= !!do_combine;
	state->do_get= do_get;
	state->do_head= do_head;
	state->do_post= do_post;
	state->do_tls= do_tls;
	state->post_header= validated_post_header;
		validated_post_header= NULL;
	state->post_file= validated_post_file;
		validated_post_file= NULL;
	state->post_footer= validated_post_footer;
		validated_post_footer= NULL;
	state->do_http10= do_http10;
	state->user_agent= user_agent ? strdup(user_agent) : NULL;
	state->max_headers= max_headers;
	state->max_body= max_body;
	state->read_limit= read_limit;
	state->sni= sni ? strdup(sni) : strdup(host);
	state->timeout= timeout;
	state->infname= infname ? strdup(infname) : NULL;

	state->only_v4= 2;

	state->only_v4= !!only_v4;	/* Gcc bug? */
	state->only_v6= !!only_v6;
	
	if (do_eetim)
		state->etim= 2;
	else if (do_etim)
		state->etim= 1;
	else
		state->etim= 0;


	//evtimer_assign(&state->timer, state->base->event_base,
	//	timeout_callback, state);

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

err:
	if (validated_response_in) free(validated_response_in);
	if (validated_response_out) free(validated_response_out);
	if (validated_output_file) free(validated_output_file);
	if (validated_post_header) free(validated_post_header);
	if (validated_post_file) free(validated_post_file);
	if (validated_post_footer) free(validated_post_footer);
	return NULL;
}

static void report(struct hgstate *state)
{
	int done, do_output;
	FILE *fh;
	char namebuf[NI_MAXHOST];
	char line[160];

	//event_del(&state->timer);

	state->subid++;

	do_output= 1;
	if (state->do_all && state->do_combine && state->subid<state->submax)
	{
		do_output= 0;
	}

	fh= NULL;
	if (do_output)
	{
		if (state->output_file)
		{
			fh= fopen(state->output_file, "a");
			if (!fh)
				crondlog(DIE9 "httpget: unable to append to '%s'",
					state->output_file);
		}
		else
			fh= stdout;

		fprintf(fh, "RESULT { ");
		if (state->atlas)
		{
			fprintf(fh, DBQ(id) ":" DBQ(%s) ", "
				"%s, "
				DBQ(lts) ":%d, "
				DBQ(time) ":%llu, ",
				state->atlas, atlas_get_version_json_str(),
				get_timesync(),
				(unsigned long long)state->gstart);
			if (state->bundle)
			{
				fprintf(fh, DBQ(bundle) ":%s, ",
					state->bundle);
			}
			if (!state->tu_env.host_is_literal)
			{
				fprintf(fh, DBQ(ttr) ":%f, ",
					state->tu_env.ttr);
			}

		}
		fprintf(fh, DBQ(result) ":[ ");
	}

	if (state->do_all && !state->dnserr)
	{
		if (state->do_combine)
		{
			snprintf(line, sizeof(line), DBQ(time) ":%llu, ",
				(unsigned long long)state->start.tv_sec);
		}
		else
		{
			snprintf(line, sizeof(line), DBQ(subid) ":%d, "
				DBQ(submax) ":%d, ",
				state->subid, state->submax);
		}
		add_str(state, line);
	}

	if (!state->dnserr)
	{
		snprintf(line, sizeof(line), 
			DBQ(method) ":" DBQ(%s) ", " DBQ(af) ": %d",
			state->do_get ? "GET" : state->do_head ? "HEAD" :
			"POST", 
			state->sin6.sin6_family == AF_INET6 ? 6 : 4);
		add_str(state, line);

		if (state->read_truncated)
			add_str(state, ", " DBQ(read-truncated) ": true");

		if (state->socklen != 0)
		{
			namebuf[0] = '\0';  // Initialize the buffer
			getnameinfo((struct sockaddr *)&state->sin6,
				state->socklen, namebuf, sizeof(namebuf),
				NULL, 0, NI_NUMERICHOST);

					/* Ensure we don't overflow the line buffer */
		{
			/* Truncate the address if it's too long */
			char truncated[sizeof(line) - 50];
			size_t max_len = sizeof(truncated) - 1;
			strncpy(truncated, namebuf, max_len);
			truncated[max_len] = '\0';
			snprintf(line, sizeof(line),
				", " DBQ(dst_addr) ":" DBQ(%s), truncated);
		}
			add_str(state, line);
		}

		/* End of readtiming */
		if (state->etim >= 2)
		{
			add_str2(state, " ]");
			add_str(state, state->result2);
			free(state->result2);
			state->result2= NULL;
			state->resmax2= 0;
			state->reslen2= 0;
		}
	}

	if (!state->connecting && !state->dnserr)
	{
		namebuf[0]= '\0';
		getnameinfo((struct sockaddr *)&state->loc_sin6,
			state->loc_socklen, namebuf, sizeof(namebuf),
			NULL, 0, NI_NUMERICHOST);

		/* Ensure we don't overflow the line buffer */
		{
			/* Truncate the address if it's too long */
			char truncated[sizeof(line) - 50];
			size_t max_len = sizeof(truncated) - 1;
			strncpy(truncated, namebuf, max_len);
			truncated[max_len] = '\0';
			snprintf(line, sizeof(line), ", " DBQ(src_addr) ":" DBQ(%s),
				truncated);
		}
		add_str(state, line);
	}

	done= (state->readstate == READ_DONE);
	if (done)
	{
		snprintf(line, sizeof(line),
			", " DBQ(rt) ":%f"
			", " DBQ(res) ":%d"
			", " DBQ(ver) ":" DBQ(%d.%d)
			", " DBQ(hsize) ":%d"
			", " DBQ(bsize) ":%d",
			state->resptime,
			state->http_result,
			state->res_major, state->res_minor,
			state->headers_size,
			state->content_offset);
		add_str(state, line);
		if (state->etim >= 1)
		{
			snprintf(line, sizeof(line),
				", " DBQ(ttr) ":%f"
				", " DBQ(ttc) ":%f"
				", " DBQ(ttfb) ":%f",
				state->ttr,
				state->ttc,
				state->ttfb);
			add_str(state, line);
		}
	}

	if (!state->dnserr)
	{
		add_str(state, " }");
	}
	if (!do_output)
		add_str(state, ", ");
	else
		add_str(state, " ]");

	if (do_output)
	{
		fprintf(fh, "%s }\n", state->result);
		free(state->result);
		state->result= NULL;
		state->resmax= 0;
		state->reslen= 0;

		if (state->output_file)
			fclose(fh);
	}

	free(state->post_buf);
	state->post_buf= NULL;

	if (state->do_all && state->subid < state->submax)
	{
		tu_restart_connect(&state->tu_env);
		return;
	}
	if (state->linemax)
	{
		state->linemax= 0;
		free(state->line);
		state->line= NULL;
	}

	state->bev= NULL;

	if (!state->response_in)
		tu_cleanup(&state->tu_env);

	if (state->resp_file)
	{
		fclose(state->resp_file);
		state->resp_file= NULL;
	}

	state->busy= 0;
	if (state->base->done)
		state->base->done(state, 0);
}

static int get_input(struct hgstate *state)
{
	int n;
	double t;
	struct timespec endtime;
	char line[80];

	/* Assume that we always end up with a full buffer anyway */
	if (state->linemax == 0)
	{
		if (state->line)
			crondlog(DIE9 "line is not empty");

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

	if (state->etim >= 2 && state->report_roffset)
	{
		gettime_mono(&endtime);
		t= (endtime.tv_sec-state->start.tv_sec)*1e3 +
			(endtime.tv_nsec-state->start.tv_nsec)/1e6;
		if (state->roffset != 0)
			add_str2(state, ",");
		snprintf(line, sizeof(line),
			" { " DBQ(o) ": %d, "
			DBQ(t) ": %f }", state->roffset, t);
		add_str2(state, line);
		state->report_roffset= 0;
	}

	if (state->response_in)
	{
		size_t tmplen;

		tmplen= state->linemax-state->linelen;
		read_response_file(state->resp_file, RESP_PACKET,
			&tmplen, &state->line[state->linelen]);
		n= tmplen;
	}
	else
	{
		n= bufferevent_read(state->bev,
			&state->line[state->linelen],
			state->linemax-state->linelen);
	}
	if (n < 0)
		return -1;
	if (state->response_out)
	{
		write_response(state->resp_file, RESP_PACKET,
				n, &state->line[state->linelen]);
	}
	state->linelen += n;
	state->roffset += n;
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

static void add_str_quoted(struct hgstate *state, char *str)
{
	char c;
	char *p;
	char buf[20];

	for (p= str; *p; p++)
	{
		c= *p;
		if (c == '"' || c == '\\')
			snprintf(buf, sizeof(buf), "\\%c", c);
		else if (isprint_asciionly((unsigned char)c))
		{
			buf[0]= c;
			buf[1]= '\0';
		}
		else
		{
			snprintf(buf, sizeof(buf), "\\u%04x",
				(unsigned char)c);
		}
		add_str(state, buf);
	}
}

static void add_str2(struct hgstate *state, const char *str)
{
	size_t len;

	len= strlen(str);
	if (state->reslen2 + len+1 > state->resmax2)
	{
		state->resmax2= 2*state->reslen2 + len+1 + 80;
		state->result2= xrealloc(state->result2, state->resmax2);
	}
	memcpy(state->result2+state->reslen2, str, len+1);
	state->reslen2 += len;
}

static void err_status(struct hgstate *state, const char *reason)
{
	char line[80];

	snprintf(line, sizeof(line),
		DBQ(err) ":" DBQ(bad status line: %s) ", ", 
		reason);
	add_str(state, line);
	report(state);
}

static void err_header(struct hgstate *state, const char *reason)
{
	char line[80];

	if (state->max_headers != 0)
		add_str(state, " ], ");
	snprintf(line, sizeof(line),
		DBQ(err) ":" DBQ(bad header line: %s) ", ", reason);
	add_str(state, line);
	report(state);
}

static void err_chunked(struct hgstate *state, const char *reason)
{
	char line[80];
	snprintf(line, sizeof(line), DBQ(err) ":" DBQ(bad chunk line: %s) ", ",
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
	struct timespec endtime;

	state= ENV2STATE(ptr);

	state->report_roffset= 1;
	for (;;)
	{
		if (state->read_limit > 0 &&
			(size_t)state->roffset >= state->read_limit)
		{
			state->read_truncated= 1;
			switch(state->readstate)
			{
			case READ_FIRST:
			case READ_STATUS:
				err_status(state, "read truncated");
				return;
			case READ_HEADER:
				err_header(state, "read truncated");
				return;
			default:
				state->readstate= READ_DONE;
				break;
			}
		}
		switch(state->readstate)
		{
		case READ_FIRST:
			gettime_mono(&endtime);
			state->ttfb= (endtime.tv_sec-
				state->start.tv_sec)*1e3 +
				(endtime.tv_nsec-state->start.tv_nsec)/1e6;
			state->readstate= READ_STATUS;
			state->roffset= 0;
			if (state->etim >= 2)
				add_str2(state, ", " DBQ(readtiming) ": [");
			continue;
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
						add_str(state, DBQ(err) ":"
							DBQ(line too long)
							", ");
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
			state->res_major= major;
			state->res_minor= minor;

			state->readstate= READ_HEADER;
			state->content_length= -1;

			if (state->max_headers)
			{
				add_str(state, DBQ(header) ": [");
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
				if (state->max_headers)
					add_str(state, " ], ");
				state->readstate= READ_BODY;
				continue;
			}

			state->headers_size += len;

			len= strlen(line);
			if (state->tot_headers+(int)len+1 <= state->max_headers)
			{
				if (state->tot_headers != 0)
					add_str(state, ",");
				add_str(state, " \"");
				add_str_quoted(state, line);
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
					add_str_quoted(state, line);
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
			{
				state->readstate= READ_CHUNKED;
				state->content_offset= 0;
				state->tot_chunked= 0;
			}
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
			if (state->content_offset+(int)len > state->tot_chunked)
				len= state->tot_chunked-state->content_offset;

			if (state->content_offset+(int)len <= state->max_body)
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
				fprintf(stderr,
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
			if (state->content_offset+(int)len <= state->max_body)
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
				fprintf(stderr,
				"readcb: should add truncation indicator\n");
			}

			state->content_offset += len;
			state->lineoffset += len;

			continue;

		case READ_DONE:
			if (state->bev || state->response_in)
			{
				state->bev= NULL;
				gettime_mono(&endtime);
				state->resptime=
					(endtime.tv_sec-
					state->start.tv_sec)*1e3 +
					(endtime.tv_nsec-
					state->start.tv_nsec)/1e6;
				report(state);
			}
			return;
		default:
			printf("readcb: readstate = %d\n", state->readstate);
			return;
		}
	}
}

static int post_file(struct hgstate *state, const char *filename)
{
	int r;
	FILE *fh;

	if (!state->post_fh)
	{
		fh= fopen(filename, "r");
		if (fh == NULL)
		{
			printf("post_file: unable to open '%s': %s\n",
				filename, strerror(errno));
			return -1;
		}
		state->post_fh= fh;
	}
	if (!state->post_buf)
		state->post_buf= xmalloc(POST_BUF_SIZE);
	r= fread(state->post_buf, 1, POST_BUF_SIZE, state->post_fh);
	if (r == -1)
	{
		printf("post_file: error reading from '%s': %s\n",
			filename, strerror(errno));
		return -1;
	}
	if (r == 0)
	{
		fclose(state->post_fh);
		state->post_fh= NULL;
		return 1;
	}
	r= bufferevent_write(state->bev, state->post_buf, r);
	if (r == -1)
	{
		printf("post_file: bufferevent_write failed\n");
	}
	return r;
}

static void writecb(struct bufferevent *bev, void *ptr)
{
	int r;
	struct hgstate *state;
	struct evbuffer *output;
	off_t cLength;
	struct stat sb;
	struct timespec endtime;

	state= ENV2STATE(ptr);

	if (state->in_writecb)
		return;	/* Recursive call */
	state->in_writecb= 1;

	for(;;)
	{
		switch(state->writestate)
		{
		case WRITE_FIRST:
			gettime_mono(&endtime);
			state->ttc= (endtime.tv_sec-
				state->start.tv_sec)*1e3 +
				(endtime.tv_nsec-state->start.tv_nsec)/1e6;
			state->writestate= WRITE_HEADER;
			continue;
		case WRITE_HEADER:
			if (state->response_in)
			{
				state->writestate = WRITE_DONE;
				continue;
			}
			output= bufferevent_get_output(bev);
			evbuffer_add_printf(output, "%s %s HTTP/1.%c\r\n",
				state->do_get ? "GET" :
				state->do_head ? "HEAD" : "POST", state->path,
				state->do_http10 ? '0' : '1');
			evbuffer_add_printf(output, "Host: %s\r\n",
				state->hostport);
			evbuffer_add_printf(output, "Connection: close\r\n");
			evbuffer_add_printf(output, "User-Agent: %s\r\n",
				state->user_agent);
			if (state->do_post)
			{
				evbuffer_add_printf(output,
			"Content-Type: application/x-www-form-urlencoded\r\n");
			}

			cLength= 0;
			if (state->do_post)
			{
				if (state->post_header)
				{
					if (stat(state->post_header, &sb) == 0)
						cLength  +=  sb.st_size;
				}
				if (state->post_file)
				{
					if (stat(state->post_file, &sb) == 0)
						cLength  +=  sb.st_size;
				}
				if (state->post_footer)
				{
					if (stat(state->post_footer, &sb) == 0)
						cLength  +=  sb.st_size;
				}
				evbuffer_add_printf(output,
					"Content-Length: %lu\r\n",
					(unsigned long)cLength);
			}

			evbuffer_add_printf(output, "\r\n");
			if (state->do_post)
				state->writestate = WRITE_POST_HEADER;
			else
				state->writestate = WRITE_DONE;
			goto out;
		case WRITE_POST_HEADER:
			if (!state->post_header)
			{
				state->writestate= WRITE_POST_FILE;
				continue;
			}
			r= post_file(state, state->post_header);
			if (r != 1)
				goto out;

			/* Done */
			state->writestate= WRITE_POST_FILE;
			continue;

		case WRITE_POST_FILE:
			if (!state->post_file)
			{
				state->writestate= WRITE_POST_FOOTER;
				continue;
			}
			r= post_file(state, state->post_file);
			if (r != 1)
				goto out;

			/* Done */
			state->writestate= WRITE_POST_FOOTER;
			continue;
		case WRITE_POST_FOOTER:
			if (!state->post_footer)
			{
				state->writestate= WRITE_DONE;
				continue;
			}
			r= post_file(state, state->post_footer);
			if (r != 1)
				goto out;

			/* Done */
			state->writestate= WRITE_DONE;
			continue;
		case WRITE_DONE:
			goto out;
		default:
			printf("writecb: unknown write state: %d\n",
				state->writestate);
			goto out;
		}
	}

out:
	state->in_writecb= 0;
}

static void err_reading(struct hgstate *state)
{
	struct timespec endtime;

	write_response(state->resp_file, RESP_READ_ERROR, 0, NULL);

	switch(state->readstate)
	{
	case READ_STATUS:
		add_str(state, ", " DBQ(err) ":" DBQ(error reading status));
		report(state);
		break;
	case READ_HEADER:
		if (state->max_headers)
			add_str(state, " ], ");
		add_str(state, DBQ(err) ":" DBQ(error reading headers) ", ");
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
			add_str(state, DBQ(err) ":" DBQ(error reading body)
				", ");
		}
		gettime_mono(&endtime);
		state->resptime= (endtime.tv_sec-state->start.tv_sec)*1e3 +
			(endtime.tv_nsec-state->start.tv_nsec)/1e6;
		report(state);
		break;
	default:
		printf("in err_reading, unhandled case %d\n", state->readstate);
	}
}

static void dnscount(struct tu_env *env, int count)
{
	struct hgstate *state;

	state= ENV2STATE(env);
	state->subid= 0;
	state->submax= count;
}

static void beforeconnect(struct tu_env *env,
	struct sockaddr *addr, socklen_t addrlen)
{
	struct hgstate *state;
	struct timespec endtime;

	state= ENV2STATE(env);

	state->socklen= addrlen;
	memcpy(&state->sin6, addr, state->socklen);
	if (state->response_out)
	{
		write_response(state->resp_file, RESP_DSTADDR,
			addrlen, addr);
	}

	state->connecting= 1;
	state->in_writecb= 0;
	state->readstate= READ_FIRST;
	state->writestate= WRITE_FIRST;

	state->linelen= 0;
	state->lineoffset= 0;
	state->headers_size= 0;
	state->tot_headers= 0;
	state->roffset= 0;
	state->read_truncated= 0;

	/* Clear result */
	if (!state->do_all || !state->do_combine)
		state->reslen= 0;

	add_str(state, "{ ");

	if (state->first_connect)
	{
		gettime_mono(&endtime);
		state->ttr= (endtime.tv_sec-state->start.tv_sec)*1e3 +
			(endtime.tv_nsec-state->start.tv_nsec)/1e6;
		state->first_connect= 0;
	}
	gettime_mono(&state->start);
}


static void reporterr(struct tu_env *env, enum tu_err cause,
		const char *str)
{
	struct hgstate *state;
	char namebuf[NI_MAXHOST];
	char line[160];

	state= ENV2STATE(env);

	if (env != &state->tu_env) abort();

	switch(cause)
	{
	case TU_DNS_ERR:
		snprintf(line, sizeof(line),
			"{ " DBQ(dnserr) ":" DBQ(%s) " }", str);
		add_str(state, line);
		state->dnserr= 1;
		report(state);
		break;

	case TU_READ_ERR:
		err_reading(state);
		break;

	case TU_SOCKET_ERR:
		snprintf(line, sizeof(line),
			"{ " DBQ(sockerr) ":" DBQ(%s) ", ", str);
		add_str(state, line);
		report(state);
		break;

	case TU_CONNECT_ERR:
		fprintf(stderr, "reporterr: str %s\n", str);
		snprintf(line, sizeof(line),
			DBQ(err) ":" DBQ(connect: %s) ", ", str);
		add_str(state, line);

		if (state->do_all)
			report(state);
		else
			tu_restart_connect(&state->tu_env);
		break;

	case TU_OUT_OF_ADDRS:
		report(state);
		break;

	case TU_BAD_ADDR:
		add_str(state, "{ " DBQ(error) ": "
			DBQ(address not allowed));

		getnameinfo(env->dns_curr->ai_addr,
			env->dns_curr->ai_addrlen, namebuf, sizeof(namebuf),
			NULL, 0, NI_NUMERICHOST);

		/* Ensure we don't overflow the line buffer */
		{
			/* Truncate the address if it's too long */
			char truncated[sizeof(line) - 50];
			size_t max_len = sizeof(truncated) - 1;
			strncpy(truncated, namebuf, max_len);
			truncated[max_len] = '\0';
			snprintf(line, sizeof(line),
				", " DBQ(dst_addr) ":" DBQ(%s) " }", truncated);
		}
		add_str(state, line);

		state->dnserr= 1;
		report(state);
		break;

	default:
		crondlog(DIE9 "reporterr: bad cause %d", cause);
	}
}

static void connected(struct tu_env *env, struct bufferevent *bev)
{
	struct hgstate *state;

	state= ENV2STATE(env);

	if (env != &state->tu_env) abort();

	state->connecting= 0;
	state->bev= bev;

	state->loc_socklen= sizeof(state->loc_sin6);
	if (state->response_in)
	{
		size_t len;

		len= state->loc_socklen;
		read_response_file(state->resp_file, RESP_SOCKNAME,
				&len, &state->loc_sin6);
		state->loc_socklen= len;
	}
	else
	{
		getsockname(bufferevent_getfd(bev),	
			(struct sockaddr *)&state->loc_sin6,
			&state->loc_socklen);
		if (state->response_out)
		{
			write_response(state->resp_file, RESP_SOCKNAME,
				state->loc_socklen, &state->loc_sin6);
		}
	}
}

static void httpget_start(void *state)
{
	int type;
	size_t len;
	struct hgstate *hgstate;
	struct evutil_addrinfo hints;
	struct timeval interval;
	struct timespec endtime;

	hgstate= state;

	if (hgstate->busy)
	{
		printf("httget_start: busy\n");
		return;
	}
	hgstate->busy= 1;

	hgstate->dnserr= 0;
	hgstate->connecting= 0;
	hgstate->readstate= READ_STATUS;
	hgstate->writestate= WRITE_HEADER;
	hgstate->gstart= atlas_time();
	gettime_mono(&hgstate->start);
	hgstate->first_connect= 1;

	if (hgstate->response_out)
	{
		hgstate->resp_file= fopen(hgstate->response_out, "w");
		if (!hgstate->resp_file)
		{
			crondlog(DIE9 "unable to write to '%s'",
				hgstate->response_out);
		}
	}

	memset(&hints, '\0', sizeof(hints));
	hints.ai_socktype= SOCK_STREAM;
	if (hgstate->only_v4)
		hints.ai_family= AF_INET;
	else if (hgstate->only_v6)
		hints.ai_family= AF_INET6;
	interval.tv_sec= hgstate->timeout / 1000;
	interval.tv_usec= (hgstate->timeout % 1000) * 1000;

	if (hgstate->response_in)
	{
		hgstate->resp_file= fopen(hgstate->response_in, "r");
		if (!hgstate->resp_file)
		{
			crondlog(DIE9 "unable to read from '%s'",
				hgstate->response_in);
		}
		/* Emulate ttr */
		tu_fake_ttr(&hgstate->tu_env, hgstate->host);

		len= sizeof(hgstate->sin6);
		read_response_file(hgstate->resp_file, RESP_DSTADDR,
			&len, &hgstate->sin6);
		hgstate->socklen= len;

		add_str(hgstate, "{ ");
		if (hgstate->first_connect)
		{
			gettime_mono(&endtime);
			hgstate->ttr= (endtime.tv_sec-hgstate->start.tv_sec)*
				1e3 + (endtime.tv_nsec-hgstate->start.tv_nsec)/
				1e6;
			hgstate->first_connect= 0;
		}

		/* Start time */
		gettime_mono(&hgstate->start);

		gettime_mono(&endtime);
		hgstate->ttc= (endtime.tv_sec- hgstate->start.tv_sec)*1e3 +
			(endtime.tv_nsec-hgstate->start.tv_nsec)/1e6;

		hgstate->readstate= READ_FIRST;

		connected(&hgstate->tu_env, NULL);

		writecb(NULL, &hgstate->tu_env);
		while(hgstate->resp_file != NULL)
		{
			peek_response_file(hgstate->resp_file, &type);
			if (type == RESP_READ_ERROR)
			{
				len= 0;
				read_response_file(hgstate->resp_file,
					RESP_READ_ERROR, &len, NULL);
				err_reading(hgstate);
				break;
			}
			readcb(NULL, &hgstate->tu_env);
		}
		report(hgstate);
	}
	else
	{
		tu_connect_to_name(&hgstate->tu_env, hgstate->host,
			hgstate->do_tls, 0, hgstate->port,
			&interval, &hints, hgstate->infname,
			hgstate->sni, NULL,
			timeout_callback,
			reporterr, dnscount, beforeconnect,
			connected, readcb, writecb);
	}
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

	if (hgstate->line)
		crondlog(DIE9 "line is not empty");

	base= hgstate->base;
	ind= hgstate->index;

	if (base->table[ind] != hgstate)
		crondlog(DIE9 "strange, state not in table");
	base->table[ind]= NULL;

	//event_del(&hgstate->timer);

	free(hgstate->atlas);
	hgstate->atlas= NULL;
	free(hgstate->bundle);
	hgstate->bundle= NULL;
	free(hgstate->output_file);
	hgstate->output_file= NULL;
	free(hgstate->infname);
	hgstate->infname= NULL;
	free(hgstate->host);
	hgstate->host= NULL;
	free(hgstate->hostport);
	hgstate->hostport= NULL;
	free(hgstate->port);
	hgstate->port= NULL;
	free(hgstate->path);
	hgstate->path= NULL;
	free(hgstate->sni);
	hgstate->sni= NULL;
	free(hgstate->user_agent);
	hgstate->user_agent= NULL;
	free(hgstate->post_header);
	hgstate->post_header= NULL;
	free(hgstate->post_file);
	hgstate->post_file= NULL;
	free(hgstate->post_footer);
	hgstate->post_footer= NULL;

	free(hgstate);

	return 1;
}

struct testops httpget_ops = { httpget_init, httpget_start,
	httpget_delete };

