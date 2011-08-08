/*
httpport.c -- Simple program that uses the HTTP POST command

Created:	Jun 2011 by Philip Homburg for RIPE NCC
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

struct option longopts[]=
{
	{ "delete-file", no_argument, NULL, 'd' },
	{ "get",	no_argument, NULL, 'g' },
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
char host_addr[INET6_ADDRSTRLEN];
const char *user_agent= "httppost for atlas.ripe.net";

static void parse_url(char *url, char **hostp, char **portp, char **hostportp,
	char **pathp);
static void check_result(FILE *tcp_file, int *result);
static void eat_headers(FILE *tcp_file, int *chunked, int *content_length,
	FILE *out_file, int max_headers);
static int connect_to_name(char *host, char *port, int only_v4, int only_v6, 
	struct timeval *start_time);
char *do_dir(char *dir_name, off_t *lenp);
static void copy_chunked(FILE *in_file, FILE *out_file, int *length, int max_body);
static void copy_bytes(FILE *in_file, FILE *out_file, size_t len, int max_body);
static void usage(void);
static void fatal(const char *fmt, ...);
static void fatal_err(const char *fmt, ...);
static void report(const char *fmt, ...);
static void report_err(const char *fmt, ...);
static void write_to_tcp_fd (int fd, FILE *tcp_file);
static void skip_spaces(const char *cp, char **ncp);

int httppost_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int httppost_main(int argc, char *argv[])
{
	int c,  i, fd, fdF, fdH, fdS, tcp_fd, chunked, content_length, result,
		http_result, opt_delete_file, do_get, max_headers, max_body,
		do_multiline, only_v4, only_v6, do_summary;
	char *url, *host, *port, *hostport, *path, *filelist, *p, *check;
	char *post_dir, *post_file, *output_file, *post_footer, *post_header,
		*A_arg, *store_headers, *store_body;
	FILE *tcp_file, *out_file;
	struct timeval tv_start, tv_end;
	struct stat sbF, sbH, sbS;
	off_t     cLength, dir_length;
	char rndbuf[16];

	do_get= 0;
	post_dir= NULL; 
	post_file= NULL; 
	post_footer=NULL;
	post_header=NULL;
	output_file= NULL;
	opt_delete_file = 0;
	time_tolerance= NULL;
	store_headers= NULL;
	store_body= NULL;
	A_arg= NULL;
	only_v4= 0;
	only_v6= 0;
	do_summary= 0;

	fd= -1;
	fdH= -1;
	fdF= -1;
	fdS= -1;
	tcp_fd= -1;
	tcp_file= NULL;
	out_file= NULL;
	host= NULL;
	port= NULL;
	hostport= NULL;
	path= NULL;
	filelist= NULL;

	/* Allow us to be called directly by another program in busybox */
	optind= 0;
	while (c= getopt_long(argc, argv, "A:O:46?", longopts, NULL), c != -1)
	{
		switch(c)
		{
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
			usage();
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

	parse_url(url, &host, &port, &hostport, &path);

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
		fprintf(stderr, "total size in dir: %ld\n", (long)dir_length);
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

	tcp_fd= connect_to_name(host, port, only_v4, only_v6, &tv_start);
	if (tcp_fd == -1)
	{
		report_err("unable to connect to '%s'", host);
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

	fprintf(stderr, "httppost: sending request\n");
	fprintf(tcp_file, "%s %s HTTP/1.1\r\n", do_get ? "GET" : "POST", path);
	fprintf(tcp_file, "Host: %s\r\n", host);
	fprintf(tcp_file, "Connection: close\r\n");
	fprintf(tcp_file, "User-Agent: %s\r\n", user_agent);
	fprintf(tcp_file,
			"Content-Type: application/x-www-form-urlencoded\r\n");

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
		 write_to_tcp_fd(fdH, tcp_file); 

	if (post_file != NULL)
		write_to_tcp_fd(fdS, tcp_file);

	if (post_dir)
	{
		for (p= filelist; p[0] != 0; p += strlen(p)+1)
		{
			fprintf(stderr, "posting file '%s'\n", p);
			fd= open(p, O_RDONLY);
			if (fd == -1)
			{
				report_err("unable to open '%s'", p);
				goto err;
			}
			write_to_tcp_fd(fd, tcp_file);
			close(fd);
			fd= -1;
		}
	}

	if( post_footer != NULL)
		write_to_tcp_fd(fdF, tcp_file);

	fprintf(stderr, "httppost: writing output\n");
	if (output_file)
	{
		out_file= fopen(output_file, "w");
		if (!out_file)
		{
			report_err("unable to create '%s'", out_file);
			goto err;
		}
	}
	else
		out_file= stdout;

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

	fprintf(stderr, "httppost: getting result\n");
	check_result(tcp_file, &http_result); 
	fprintf(stderr, "httppost: getting reply headers \n");
	eat_headers(tcp_file, &chunked, &content_length, out_file, max_headers);
	if (max_headers != 0 && max_body != 0)
		fprintf(out_file, "\n");	/* separate headers from body */

	if (chunked)
	{
		copy_chunked(tcp_file, out_file, &content_length, max_body);
	}
	else if (content_length)
	{
		copy_bytes(tcp_file, out_file, content_length, max_body);
	}
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
		fprintf(out_file, "RESULT %s %ld ",
			A_arg, (long)time(NULL));
	}
	if (do_summary)
	{
		const char *v, *cmd;

		cmd= "POST";
		if (do_get)
			cmd= "GET";
		if (only_v4)
			v= "4";
		else if (only_v6)
			v= "6";
		else
			v= "46";

		fprintf(out_file, "%s%s %s %d.%06d %03u %d\n",
			cmd, v, 
			host_addr, (int)tv_end.tv_sec, (int)tv_end.tv_usec,
			http_result, content_length);
	}

	fprintf(stderr, "httppost: deleting files\n");
	if ( opt_delete_file == 1 )
	{
		if (post_file)
			unlink (post_file);
		if (post_dir)
		{
			for (p= filelist; p[0] != 0; p += strlen(p)+1)
			{
				fprintf(stderr, "unlinking file '%s'\n", p);
				if (unlink(p) != 0)
					report_err("unable to unlink '%s'", p);
			}
		}
	}
	fprintf(stderr, "httppost: done\n");

	result= 0;

leave:
	if (fdH != -1) close(fdH);
	if (fdF != -1) close(fdF);
	if (fdS != -1) close(fdS);
	if (fd != -1) close(fd);
	if (tcp_file) fclose(tcp_file);
	if (tcp_fd != -1) close(tcp_fd);
	if (out_file) fclose(out_file);
	if (host) free(host);
	if (port) free(port);
	if (hostport) free(hostport);
	if (path) free(path);
	if (filelist) free(filelist);

	return result; 

err:
	result= 1;
	goto leave;
}

static void write_to_tcp_fd (int fd, FILE *tcp_file)
{
	int r;
	/* Copy file */
	while(r= read(fd, buffer, sizeof(buffer)), r > 0)
	{
		if (fwrite(buffer, r, 1, tcp_file) != 1)
			fatal_err("error writing to tcp connection");
	}
	if (r == -1)
		fatal_err("error reading from file");

}


static void parse_url(char *url, char **hostp, char **portp, char **hostportp,
	char **pathp)
{
	char *item;
	const char *cp, *np, *prefix;
	size_t len;

	/* the url must start with 'http://' */
	prefix= "http://";
	len= strlen(prefix);
	if (strncasecmp(prefix, url, len) != 0)
		fatal("bad prefix in url '%s'", url);

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
		fatal("missing host part in url '%s'", url);
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
			fatal("malformed IPv6 address literal in url '%s'",
				url);
		}
	}
	/* Should handle IPv6 address literals */
	np= strchr(np, ':');
	if (np != NULL)
		len= np-cp;
	else
	{
		len= strlen(cp);
		np= cp+len;
	}
	if (len == 0)
		fatal("missing host part in url '%s'", url);
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
}

static void check_result(FILE *tcp_file, int *result)
{
	int major, minor;
	size_t len;
	char *cp, *check, *line;
	const char *prefix;

	if (fgets(buffer, sizeof(buffer), tcp_file) == NULL)
	{
		if (feof(tcp_file))
			fatal("got unexpected EOF from server");
		else
			fatal_err("error reading from server");
	}

	line= buffer;
	cp= strchr(line, '\n');
	if (cp == NULL)
		fatal("line too long");
	cp[0]= '\0';
	if (cp > line && cp[-1] == '\r')
		cp[-1]= '\0';

	/* Check http version */
	prefix= "http/";
	len= strlen(prefix);
	if (strncasecmp(prefix, line, len) != 0)
		fatal("bad prefix in response '%s'", line);
	cp= line+len;
	major= strtoul(cp, &check, 10);
	if (check == cp || check[0] != '.')
		fatal("bad major version in response '%s'", line);
	cp= check+1;
	minor= strtoul(cp, &check, 10);
	if (check == cp || check[0] == '\0' ||
		!isspace(*(unsigned char *)check))
	{
		fatal("bad major version in response '%s'", line);
	}

	skip_spaces(check, &cp);

	if (!isdigit(*(unsigned char *)cp))
		fatal("bad status code in response '%s'", line);
	*result= strtoul(cp, NULL, 10);

	if (cp[0] != '2')
		fatal("POST command failed: '%s'", cp);
}

static void eat_headers(FILE *tcp_file, int *chunked, int *content_length,
	FILE *out_file, int max_headers)
{
	int tot_headers;
	char *line, *cp, *ncp, *check;
	size_t len;
	const char *kw;

	*chunked= 0;
	*content_length= 0;
	tot_headers= 0;
	while (fgets(buffer, sizeof(buffer), tcp_file) != NULL)
	{
		line= buffer;
		cp= strchr(line, '\n');
		if (cp == NULL)
			fatal("line too long");
		cp[0]= '\0';
		if (cp > line && cp[-1] == '\r')
			cp[-1]= '\0';

		if (line[0] == '\0')
			return;		/* End of headers */

		fprintf(stderr, "httppost: got line '%s'\n", line);

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
				fprintf(stderr, "unable to parse time '%s'\n",
					line+6);
			}
			tim= timegm(&tm);
			now= time(NULL);
			if (now < tim-tolerance || now > tim+tolerance)
			{
				fprintf(stderr, "setting time, time difference is %d\n",
					(int)(tim-now));
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
				fatal("malformed content-length header", line);
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
			fatal("malformed content-length header", line);
		cp++;

		/* Skip more white space */
		skip_spaces(cp, &cp);

		/* Should have the value by now */
		*content_length= strtoul(cp, &check, 10);
		if (check == cp)
			fatal("malformed content-length header", line);

		/* And after that we should have just white space */
		cp= check;
		skip_spaces(cp, &cp);

		if (cp[0] != '\0')
			fatal("malformed content-length header", line);
	}
	if (feof(tcp_file))
		fatal("got unexpected EOF from server");
	else
		fatal_err("error reading from server");
}

static int connect_to_name(char *host, char *port, int only_v4, int only_v6,
	struct timeval *start_time)
{
	int r, s, s_errno;
	struct addrinfo *res, *aip;
	struct addrinfo hints;

	fprintf(stderr, "httppost: before getaddrinfo\n");
	memset(&hints, '\0', sizeof(hints));
	hints.ai_socktype= SOCK_STREAM;
	if (only_v4)
		hints.ai_family= AF_INET;
	if (only_v6)
		hints.ai_family= AF_INET6;
	r= getaddrinfo(host, port, &hints, &res);
	if (r != 0)
		fatal("unable to resolve '%s': %s", host, gai_strerror(r));

	s_errno= 0;
	s= -1;
	for (aip= res; aip != NULL; aip= aip->ai_next)
	{
		getnameinfo(res->ai_addr, res->ai_addrlen, host_addr, sizeof(host_addr),
			NULL, 0, NI_NUMERICHOST);
		gettimeofday(start_time, NULL);
		s= socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s == -1)
		{	
			s_errno= errno;
			continue;
		}

		fprintf(stderr, "httppost: before connect\n");
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

static void copy_chunked(FILE *in_file, FILE *out_file, int *length, int max_body)
{
	int need_nl;
	size_t len, offset, size, tot_body;
	char *cp, *line, *check;

	*length= 0;
	need_nl= 0;
	for (;;)
	{
		/* Get a chunk size */
		if (fgets(buffer, sizeof(buffer), in_file) == NULL)
			fatal("error reading input");

		line= buffer;
		cp= strchr(line, '\n');
		if (cp == NULL)
			fatal("line too long");
		cp[0]= '\0';
		if (cp > line && cp[-1] == '\r')
			cp[-1]= '\0';

		fprintf(stderr, "httppost: got chunk line '%s'\n", line);
		len= strtoul(line, &check, 16);
		if (check[0] != '\0' && !isspace(*(unsigned char *)check))
			fatal("bad chunk line '%s'", line);
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
				fatal_err("error reading input");

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
						fatal_err("error writing output");
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
			fatal("error reading input");

		line= buffer;
		cp= strchr(line, '\n');
		if (cp == NULL)
			fatal("line too long");
		cp[0]= '\0';
		if (cp > line && cp[-1] == '\r')
			cp[-1]= '\0';
		if (line[0] != '\0')
			fatal("Garbage after chunk data");
	}

	if (max_body && need_nl)
		fprintf(out_file, "\n");

	for (;;)
	{
		/* Get an end-of-chunk line */
		if (fgets(buffer, sizeof(buffer), in_file) == NULL)
			fatal("error reading input");

		line= buffer;
		cp= strchr(line, '\n');
		if (cp == NULL)
			fatal("line too long");
		cp[0]= '\0';
		if (cp > line && cp[-1] == '\r')
			cp[-1]= '\0';
		if (line[0] == '\0')
			break;

		fprintf(stderr, "httppost: got end-of-chunk line '%s'\n", line);
	}
}

static void copy_bytes(FILE *in_file, FILE *out_file, size_t len, int max_body)
{
	size_t offset, size, tot_body;
	int need_nl;

	offset= 0;

	need_nl= 0;
	while (offset < len)
	{
		size= len-offset;
		if (size > sizeof(buffer))
			size= sizeof(buffer);
		if (fread(buffer, size, 1, in_file) != 1)
			fatal_err("error reading input");

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
					fatal_err("error writing output");
				}
			}
			fprintf(out_file, "\n[...]\n");
			need_nl= 0;
			tot_body += len;
		}

		offset += size;
	}
	if (max_body && need_nl)
		fprintf(out_file, "\n");
}

static void skip_spaces(const char *cp, char **ncp)
{
	const unsigned char *ucp;

	ucp= (const unsigned char *)cp;
	while (ucp[0] != '\0' && isspace(ucp[0]))
		ucp++;
	*ncp= (char *)ucp;
}

static void usage(void)
{
	fprintf(stderr,
"Usage: httppost\n"); 
	fprintf(stderr,
"         [--post-header <file-to-post>] [--post-file <file-to-post>]\n");
	fprintf(stderr, 
"        [--post-footer  <file-to-post>] \n");

	fprintf(stderr, 
"        [--delete-file 'delete the upon success, not header and footer'\n");

	fprintf(stderr, 
"        [--post-footer  <file-to-post>] [-O <output-file>] <url>\n");
	exit(1);
}

static void fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	fprintf(stderr, "httppost: ");
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

	fprintf(stderr, "httppost: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, ": %s\n", strerror(s_errno));

	va_end(ap);

	exit(1);
}

static void report(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	fprintf(stderr, "httppost: ");
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

	fprintf(stderr, "httppost: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, ": %s\n", strerror(s_errno));

	va_end(ap);
}
