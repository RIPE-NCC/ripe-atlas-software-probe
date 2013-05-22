/*
 * Copyright (c) 2011-2013 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * httpget.c -- Simple program that uses the HTTP GET command
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "libbb.h"

#define SAFE_PREFIX_OUT ATLAS_DATA_OUT
#define SAFE_PREFIX_NEW ATLAS_DATA_NEW

#define debug 0

static struct option longopts[]=
{
	{ "append",	no_argument, NULL, 'a' },
	{ "get",	no_argument, NULL, 'g' },
	{ "head",	no_argument, NULL, 'E' },
	{ "post",	no_argument, NULL, 'P' },
	{ "post-file",	required_argument, NULL, 'p' },
	{ "post-dir",	required_argument, NULL, 'D' },
	{ "post-header", required_argument, NULL, 'h' },
	{ "post-footer", required_argument, NULL, 'f' },
	{ "set-time",	required_argument, NULL, 's' },
	{ "store-headers", required_argument, NULL, 'H' },
	{ "store-body",	required_argument, NULL, 'B' },
	{ "summary",	no_argument, NULL, 'S' },
	{ "user-agent",	required_argument, NULL, 'u' },
	{ NULL, }
};

static char *time_tolerance;
static char buffer[1024];
static char host_addr[INET6_ADDRSTRLEN];
static sa_family_t family;
static const char *user_agent= "httpget for atlas.ripe.net";
static int tcp_fd= -1;

static int parse_url(char *url, char **hostp, char **portp, char **hostportp,
	char **pathp);
static int check_result(FILE *tcp_file, int *result);
static int eat_headers(FILE *tcp_file, int *chunked, int *content_length,
	int *headers_size, FILE *out_file, int max_headers);
static int connect_to_name(char *host, char *port, int only_v4, int only_v6, 
	struct timeval *start_time, int *gerr);
static char *do_dir(char *dir_name, off_t *lenp);
static int copy_chunked(FILE *in_file, FILE *out_file, int *length,
	int max_body);
static int copy_bytes(FILE *in_file, FILE *out_file, int *length,
	int max_body);
static void got_alarm(int sig);
static void fatal(const char *fmt, ...);
static void fatal_err(const char *fmt, ...);
static void report(const char *fmt, ...);
static void report_err(const char *fmt, ...);
static int write_to_tcp_fd (int fd, FILE *tcp_file);
static void skip_spaces(const char *cp, char **ncp);

int httpget_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int httpget_main(int argc, char *argv[])
{
	int c,  i, r, fd, fdF, fdH, fdS, chunked, content_length,
		result, http_result, do_get, do_head, do_post,
		max_headers, max_body, do_multiline, only_v4, only_v6,
		do_summary, headers_size, no_body, do_append, do_http10, gerr,
		out_file_needs_closing;
	char *url, *host, *port, *hostport, *path, *filelist, *p, *check;
	char *post_dir, *post_file, *output_file, *post_footer, *post_header,
		*A_arg, *store_headers, *store_body;
	FILE *tcp_file, *out_file;
	struct timeval tv_start, tv_end;
	struct stat sbF, sbH, sbS;
	off_t     cLength, dir_length;
	struct sigaction sa;
	char rndbuf[16];

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
	time_tolerance= NULL;
	store_headers= NULL;
	store_body= NULL;
	A_arg= NULL;
	only_v4= 0;
	only_v6= 0;
	do_summary= 0;

	/* Used in cleanup */
	fd= -1;
	fdH= -1;
	fdF= -1;
	fdS= -1;
	tcp_fd= -1;
	tcp_file= NULL;
	out_file= NULL;
	out_file_needs_closing= 0;
	host= NULL;
	port= NULL;
	hostport= NULL;
	path= NULL;
	filelist= NULL;

	/* Others */
	do_multiline= 0;
	http_result= -1;
	dir_length= 0;
	headers_size= 0;

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
		case 's':				/* --set-time */
			time_tolerance= optarg;
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
			return 1;
		default:
			fatal("bad option '%c'", c);
		}
	}

	if (optind != argc-1)
		fatal("exactly one url expected");
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
			report("unable to parse argument '%s'", store_headers);
			return 1;
		}
	}

	if (store_body)
	{
		max_body= strtoul(store_body, &check, 10);
		if (check[0] != '\0')
		{
			report("unable to parse argument '%s'", store_body);
			return 1;
		}
	}

	if (!parse_url(url, &host, &port, &hostport, &path))
	{
		goto err;
	}

	//printf("host: %s\n", host);
	//printf("port: %s\n", port);
	//printf("hostport: %s\n", hostport);
	//printf("path: %s\n", path);

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
		if (!validate_filename(post_header, SAFE_PREFIX_OUT))
		{
			report("insecure file '%s'", post_header);
			goto err;
		}
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
		if (!validate_filename(post_footer, SAFE_PREFIX_OUT))
		{
			report("insecure file '%s'", post_footer);
			goto err;
		}
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
		if (!validate_filename(post_file, SAFE_PREFIX_OUT))
		{
			report("insecure file '%s'", post_file);
			goto err;
		}
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
		if (!validate_filename(output_file, SAFE_PREFIX_NEW))
		{
			report("insecure output file '%s'", output_file);
			goto err;
		}
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


	tcp_fd= connect_to_name(host, port, only_v4, only_v6, &tv_start,
		&gerr);
	if (tcp_fd == -1)
	{
		int s_errno= errno;

		if (A_arg && do_summary)
		{
			fprintf(out_file, "%s %ld ",
				A_arg, (long)time(NULL));
			if (gerr != 0)
			{
				fprintf(out_file, "bad-hostname %s\n",
					gai_strerror(gerr));
			}
			else
			{
				fprintf(out_file, "connect error %d\n",
					s_errno);
			}
		}
		report("unable to connect to '%s'", host);
		goto err;
	}

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
			if (!validate_filename(p, SAFE_PREFIX_OUT))
			{
				report("insecure file '%s'", p);
				goto err;
			}
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
}

static int write_to_tcp_fd (int fd, FILE *tcp_file)
{
	int r;
	/* Copy file */
	while(r= read(fd, buffer, sizeof(buffer)), r > 0)
	{
		if (fwrite(buffer, r, 1, tcp_file) != 1)
		{
			report_err("error writing to tcp connection");
			return 0;
		}
	}
	if (r == -1)
		fatal_err("error reading from file");
	return 1;
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
		report("bad prefix in url '%s'", url);
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
		report("missing host part in url '%s'", url);
		return 0;
	}
	item= malloc(len+1);
	if (!item) fatal("out of memory");
	memcpy(item, cp, len);
	item[len]= '\0';
	*hostportp= item;

	/* The remainder is the path */
	cp= np;
	if (cp[0] == '\0')
		cp= "/";
	len= strlen(cp);
	item= malloc(len+1);
	if (!item) fatal("out of memory");
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
			report("malformed IPv6 address literal in url '%s'",
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
		report("missing host part in url '%s'", url);
		goto fail;
	}
	item= malloc(len+1);
	if (!item) fatal("out of memory");
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
	item= malloc(len+1);
	if (!item) fatal("out of memory");
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

static int check_result(FILE *tcp_file, int *result)
{
	int major, minor;
	size_t len;
	char *cp, *check, *line;
	const char *prefix;

	*result= -1;	/* Signal error actually getting a result */

	if (fgets(buffer, sizeof(buffer), tcp_file) == NULL)
	{
		if (feof(tcp_file))
			report("got unexpected EOF from server");
		else
			report_err("error reading from server");
		return 0;
	}

	line= buffer;
	cp= strchr(line, '\n');
	if (cp == NULL)
	{
		report("line too long");
		return 0;
	}
	cp[0]= '\0';
	if (cp > line && cp[-1] == '\r')
		cp[-1]= '\0';

	/* Check http version */
	prefix= "http/";
	len= strlen(prefix);
	if (strncasecmp(prefix, line, len) != 0)
	{
		report("bad prefix in response '%s'", line);
		return 0;
	}
	cp= line+len;
	major= strtoul(cp, &check, 10);
	if (check == cp || check[0] != '.')
	{
		report("bad major version in response '%s'", line);
		return 0;
	}
	cp= check+1;
	minor= strtoul(cp, &check, 10);
	if (check == cp || check[0] == '\0' ||
		!isspace(*(unsigned char *)check))
	{
		report("bad major version in response '%s'", line);
		return 0;
	}

	skip_spaces(check, &cp);

	if (!isdigit(*(unsigned char *)cp))
	{
		report("bad status code in response '%s'", line);
		return 0;
	}
	*result= strtoul(cp, NULL, 10);

	return 1;
}

static int eat_headers(FILE *tcp_file, int *chunked, int *content_length,
	int *headers_size, FILE *out_file, int max_headers)
{
	int tot_headers;
	char *line, *cp, *ncp, *check;
	size_t len;
	const char *kw;

	*chunked= 0;
	*content_length= -1;
	tot_headers= 0;
	*headers_size= 0;
	while (fgets(buffer, sizeof(buffer), tcp_file) != NULL)
	{
		line= buffer;
		len=strlen(line);
		cp= strchr(line, '\n');
		if (cp == NULL)
		{
			report("line too long");
			return 0;
		}
		cp[0]= '\0';
		if (cp > line && cp[-1] == '\r')
			cp[-1]= '\0';

		if (line[0] == '\0')
			return 1;		/* End of headers */

		*headers_size += len;

		if (debug) fprintf(stderr, "httpget: got line '%s'\n", line);

		len= strlen(line);
		if (tot_headers+len+1 <= max_headers)
		{
			fprintf(out_file, "%s\n", line);
			tot_headers += len+1;
		} else if (tot_headers <= max_headers && max_headers != 0)
		{
			/* Fill up remaining space and report truncation */
			if (tot_headers < max_headers)
			{
				fprintf(out_file, "%.*s\n", max_headers-tot_headers,
					line);
			}
			fprintf(out_file, "[...]\n");

			tot_headers += len+1;
		}

		if (time_tolerance && strncmp(line, "Date: ", 6) == 0)
		{
			/* Try to set time from server */
			time_t now, tim, tolerance;
			struct tm tm;

			tolerance= strtoul(time_tolerance, &cp, 10);
			if (cp[0] != '\0')
			{
				fatal("unable to parse tolerance '%s'",
					time_tolerance);
			}
			cp= strptime(line+6, "%a, %d %b %Y %H:%M:%S ", &tm);
			if (!cp || strcmp(cp, "GMT") != 0)
			{
				if (debug) 
				{
					fprintf(stderr,
					"unable to parse time '%s'\n",
						line+6);
				}
			}
			tim= timegm(&tm);
			now= time(NULL);
			if (now < tim-tolerance || now > tim+tolerance)
			{
				if (debug)
				{	fprintf(stderr,
				"setting time, time difference is %d\n",
						(int)(tim-now));
				}
				stime(&tim);
			}
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
				report("malformed content-length header", line);
				return 0;
			}
			cp++;

			/* Skip more white space */
			skip_spaces(cp, &cp);

			/* Should have the value by now */
			kw= "chunked";
			len= strlen(kw);
			if (strncasecmp(cp, kw, len) != 0)
				continue;
			/* make sure we have end of line or white space */
			if (cp[len] != '\0' && isspace((unsigned char)cp[len]))
				continue;
			*chunked= 1;
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
			report("malformed content-length header", line);
			return 0;
		}
		cp++;

		/* Skip more white space */
		skip_spaces(cp, &cp);

		/* Should have the value by now */
		*content_length= strtoul(cp, &check, 10);
		if (check == cp)
		{
			report("malformed content-length header", line);
			return 0;
		}

		/* And after that we should have just white space */
		cp= check;
		skip_spaces(cp, &cp);

		if (cp[0] != '\0')
		{
			report("malformed content-length header", line);
			return 0;
		}
	}
	if (feof(tcp_file))
		report("got unexpected EOF from server");
	else
		report_err("error reading from server");
	return 0;
}

static int connect_to_name(char *host, char *port, int only_v4, int only_v6,
	struct timeval *start_time, int *gerr)
{
	int r, s, s_errno;
	struct addrinfo *res, *aip;
	struct addrinfo hints;

	if (debug) fprintf(stderr, "httpget: before getaddrinfo\n");
	memset(&hints, '\0', sizeof(hints));
	hints.ai_socktype= SOCK_STREAM;
	if (only_v4)
		hints.ai_family= AF_INET;
	if (only_v6)
		hints.ai_family= AF_INET6;
	r= getaddrinfo(host, port, &hints, &res);
	*gerr= r;
	if (r != 0)
	{
		report("unable to resolve '%s': %s", host, gai_strerror(r));
		return -1;
	}

	s_errno= 0;
	s= -1;
	for (aip= res; aip != NULL; aip= aip->ai_next)
	{
		family= res->ai_family;
		getnameinfo(res->ai_addr, res->ai_addrlen, host_addr,
			sizeof(host_addr), NULL, 0, NI_NUMERICHOST);

		gettimeofday(start_time, NULL);
		s= socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s == -1)
		{	
			s_errno= errno;
			continue;
		}

		if (debug) fprintf(stderr, "httpget: before connect\n");
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

char *do_dir(char *dir_name, off_t *lenp)
{
	size_t currsize, allocsize, dirlen, len;
	char *list, *tmplist, *path;
	DIR *dir;
	struct dirent *de;
	struct stat sb;

	/* Scan a directory for files. Return the filenames asa list of 
	 * strings. An empty string terminates the list. Also compute the
	 * total size of the files
	 */
	*lenp= 0;
	currsize= 0;
	allocsize= 0;
	list= NULL;
	dir= opendir(dir_name);
	if (dir == NULL)
	{
		report_err("opendir failed for '%s'", dir_name);
		return NULL;
	}

	dirlen= strlen(dir_name);
	while (de= readdir(dir), de != NULL)
	{
		/* Concat dir and entry */
		len= dirlen + 1 + strlen(de->d_name) + 1;
		if (currsize+len > allocsize)
		{
			allocsize += 4096;
			tmplist= realloc(list, allocsize);
			if (!tmplist)
			{
				free(list);
				report("realloc failed for %d bytes",
					allocsize);
				closedir(dir);
				return NULL;
			}
			list= tmplist;
		}
		path= list+currsize;

		strlcpy(path, dir_name, allocsize-currsize);
		strlcat(path, "/", allocsize-currsize);
		strlcat(path, de->d_name, allocsize-currsize);

		if (stat(path, &sb) != 0)
		{
			report_err("stat '%s' failed", path);
			free(list);
			closedir(dir);
			return NULL;
		}

		if (!S_ISREG(sb.st_mode))
			continue;	/* Just skip entry */

		currsize += len;
		*lenp += sb.st_size;
	}
	closedir(dir);

	/* Add empty string to terminate the list */
	len= 1;
	if (currsize+len > allocsize)
	{
		allocsize += 4096;
		tmplist= realloc(list, allocsize);
		if (!tmplist)
		{
			free(list);
			report("realloc failed for %d bytes", allocsize);
			return NULL;
		}
		list= tmplist;
	}
	path= list+currsize;

	*path= '\0';

	return list;
}

static int copy_chunked(FILE *in_file, FILE *out_file, int *length, int max_body)
{
	int need_nl;
	size_t len, offset, size, tot_body;
	char *cp, *line, *check;

	*length= 0;
	need_nl= 0;
	tot_body= 0;
	for (;;)
	{
		/* Get a chunk size */
		if (fgets(buffer, sizeof(buffer), in_file) == NULL)
		{
			report("error reading input");
			return 0;
		}

		line= buffer;
		cp= strchr(line, '\n');
		if (cp == NULL)
		{
			report("line too long");
			return 0;
		}
		cp[0]= '\0';
		if (cp > line && cp[-1] == '\r')
			cp[-1]= '\0';

		if (debug)
		{	
			fprintf(stderr, "httpget: got chunk line '%s'\n", line);
		}
		len= strtoul(line, &check, 16);
		if (check[0] != '\0' && !isspace(*(unsigned char *)check))
		{
			report("bad chunk line '%s'", line);
			return 0;
		}
		if (!len)
			break;

		*length += len;

		offset= 0;

		while (offset < len)
		{
			size= len-offset;
			if (size > sizeof(buffer))
				size= sizeof(buffer);
			if (fread(buffer, size, 1, in_file) != 1)
			{
				report("error reading input");
				return 0;
			}

			if (tot_body+size <= max_body)
			{
				if (fwrite(buffer, size, 1, out_file) != 1)
					fatal_err("error writing output");
				need_nl= (buffer[size-1] != '\n');
				tot_body += len;
			} else if (tot_body <= max_body && max_body != 0)
			{
				/* Fill up remaining space and report truncation */
				if (tot_body < max_body)
				{
					if (fwrite(buffer, max_body-tot_body, 1,
						out_file) != 1)
					{
						fatal_err(
							"error writing output");
					}
				}
				fprintf(out_file, "\n[...]\n");
				need_nl= 0;
				tot_body += len;
			}

			offset += size;
		}

		/* Expect empty line after data */
		if (fgets(buffer, sizeof(buffer), in_file) == NULL)
		{
			report("error reading input");
			return 0;
		}

		line= buffer;
		cp= strchr(line, '\n');
		if (cp == NULL)
		{
			report("line too long");
			return 0;
		}
		cp[0]= '\0';
		if (cp > line && cp[-1] == '\r')
			cp[-1]= '\0';
		if (line[0] != '\0')
		{
			report("Garbage after chunk data");
			return 0;
		}
	}

	if (max_body && need_nl)
		fprintf(out_file, "\n");

	for (;;)
	{
		/* Get an end-of-chunk line */
		if (fgets(buffer, sizeof(buffer), in_file) == NULL)
		{
			report("error reading input");
			return 0;
		}

		line= buffer;
		cp= strchr(line, '\n');
		if (cp == NULL)
		{
			report("line too long");
			return 0;
		}
		cp[0]= '\0';
		if (cp > line && cp[-1] == '\r')
			cp[-1]= '\0';
		if (line[0] == '\0')
			break;

		if (debug)
		{
			fprintf(stderr,
				"httpget: got end-of-chunk line '%s'\n", line);
		}
	}
	return 1;
}

static int copy_bytes(FILE *in_file, FILE *out_file, int *length,
	int max_body)
{
	int len, need_nl;
	size_t offset, size;

	offset= 0;

	need_nl= 0;
	len= *length;
	while (len == -1 || offset < len)
	{
		if (len == -1)
		{
			size= sizeof(buffer);

			size= fread(buffer, 1, sizeof(buffer), in_file);
			if (size == 0)
			{
				if (feof(in_file))
					break;	/* Got EOF */
				report_err("error reading input");

				if (max_body && need_nl)
					fprintf(out_file, "\n");
				return 0;
			}
		}
		else
		{
			size= len-offset;
			if (size > sizeof(buffer))
				size= sizeof(buffer);

			if (fread(buffer, size, 1, in_file) != 1)
			{
				report_err("error reading input");

				if (max_body && need_nl)
					fprintf(out_file, "\n");
				return 0;
			}
		}

		if (offset+size <= max_body)
		{
			if (fwrite(buffer, size, 1, out_file) != 1)
				fatal_err("error writing output");
			need_nl= (buffer[size-1] != '\n');
		}
		else if (offset <= max_body && max_body != 0)
		{
			/* Fill up remaining space and report truncation */
			if (offset < max_body)
			{
				if (fwrite(buffer, max_body-offset, 1,
					out_file) != 1)
				{
					fatal_err("error writing output");
				}
			}
			fprintf(out_file, "\n[...]\n");
			need_nl= 0;
		}

		offset += size;
	}

	if (max_body && need_nl)
		fprintf(out_file, "\n");
	if (len == -1)
		*length= offset;
	return 1;
}

static void skip_spaces(const char *cp, char **ncp)
{
	const unsigned char *ucp;

	ucp= (const unsigned char *)cp;
	while (ucp[0] != '\0' && isspace(ucp[0]))
		ucp++;
	*ncp= (char *)ucp;
}

static void got_alarm(int sig __attribute__((unused)) )
{
	// printf("got alarm\n");
	// printf("switching tcp_fd to nonblocking\n");
	if (tcp_fd != -1)
		fcntl(tcp_fd, F_SETFL, fcntl(tcp_fd, F_GETFL) | O_NONBLOCK);
	//printf("setting alarm again\n");
	alarm(1);
}

static void usage(void)
{
	fprintf(stderr,
"Usage: httpget\n"); 
	fprintf(stderr,
"         [--post-header <file-to-post>] [--post-file <file-to-post>]\n");
	fprintf(stderr, 
"        [--post-footer  <file-to-post>] \n");

	fprintf(stderr, 
"        [--post-footer  <file-to-post>] [-O <output-file>] <url>\n");
	exit(1);
}

static void fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	fprintf(stderr, "httpget: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");

	va_end(ap);

	exit(1);
}

static void fatal_err(const char *fmt, ...)
{
	int s_errno;
	va_list ap;

	s_errno= errno;

	va_start(ap, fmt);

	fprintf(stderr, "httpget: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, ": %s\n", strerror(s_errno));

	va_end(ap);

	exit(1);
}

static void report(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	fprintf(stderr, "httpget: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");

	va_end(ap);
}

static void report_err(const char *fmt, ...)
{
	int s_errno;
	va_list ap;

	s_errno= errno;

	va_start(ap, fmt);

	fprintf(stderr, "httpget: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, ": %s\n", strerror(s_errno));

	va_end(ap);
}
