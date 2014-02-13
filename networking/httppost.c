/*
 * Copyright (c) 2011-2013 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * httppost.c -- Simple program that uses the HTTP POST command
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

#define SAFE_PREFIX_DATA_OUT ATLAS_DATA_OUT
#define SAFE_PREFIX_DATA_OOQ_OUT ATLAS_DATA_OOQ_OUT
#define SAFE_PREFIX_DATA_NEW ATLAS_DATA_NEW
#define SAFE_PREFIX_STATUS ATLAS_STATUS

struct option longopts[]=
{
	{ "delete-file", no_argument, NULL, 'd' },
	{ "maxpostsize", required_argument, NULL, 'm' },
	{ "post-file", required_argument, NULL, 'p' },
	{ "post-dir", required_argument, NULL, 'D' },
	{ "post-header", required_argument, NULL, 'h' },
	{ "post-footer", required_argument, NULL, 'f' },
	{ "set-time", required_argument, NULL, 's' },
	{ "timeout", required_argument, NULL, 't' },
	{ NULL, }
};

static int tcp_fd;
static struct timeval start_time;
static time_t timeout = 300;

/* Result sent by controller when input is acceptable. */
#define OK_STR	"OK\n"

static int parse_url(char *url, char **hostp, char **portp, char **hostportp,
	char **pathp);
static int check_result(FILE *tcp_file);
static int eat_headers(FILE *tcp_file, int *chunked, int *content_length, time_t *timep);
static int connect_to_name(char *host, char *port);
char *do_dir(char *dir_name, off_t curr_size, off_t max_size, off_t *lenp);
static int copy_chunked(FILE *in_file, FILE *out_file, int *found_okp);
static int copy_bytes(FILE *in_file, FILE *out_file, size_t len,
	int *found_okp);
static int copy_all(FILE *in_file, FILE *out_file, int *found_okp);
static void fatal(const char *fmt, ...);
// static void fatal_err(const char *fmt, ...);
static void report(const char *fmt, ...);
static void report_err(const char *fmt, ...);
static int write_to_tcp_fd (int fd, FILE *tcp_file);
static void skip_spaces(const char *cp, char **ncp);
static void got_alarm(int sig);
static void kick_watchdog(void);

int httppost_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int httppost_main(int argc, char *argv[])
{
	int c,  r, fd, fdF, fdH, fdS, chunked, content_length, result;
	int opt_delete_file, found_ok;
	char *url, *host, *port, *hostport, *path, *filelist, *p, *check;
	char *post_dir, *post_file, *atlas_id, *output_file,
		*post_footer, *post_header, *maxpostsizestr, *timeoutstr;
	char *time_tolerance;
	FILE *tcp_file, *out_file, *fh;
	time_t server_time, tolerance;
	struct stat sbF, sbH, sbS;
	off_t cLength, dir_length, maxpostsize;
	struct sigaction sa;

	post_dir= NULL; 
	post_file= NULL; 
	post_footer=NULL;
	post_header=NULL;
	atlas_id= NULL;
	output_file= NULL;
	opt_delete_file = 0;
	time_tolerance = NULL;
	maxpostsizestr= NULL;
	timeoutstr= NULL;

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
	maxpostsize= 1000000;

	/* Allow us to be called directly by another program in busybox */
	optind= 0;
	while (c= getopt_long(argc, argv, "A:O:?", longopts, NULL), c != -1)
	{
		switch(c)
		{
		case 'A':
			atlas_id= optarg;
			break;
		case 'O':
			output_file= optarg;
			break;
		case 'd':
			opt_delete_file = 1;
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
		case 'm':				/* --maxpostsize */
			maxpostsizestr= optarg;
			break;
		case 'p':				/* --post-file */
			post_file= optarg;
			break;
		case 's':				/* --set-time */
			time_tolerance= optarg;
			break;
		case 't':				/* --timeout */
			timeoutstr= optarg;
			break;
		case '?':
			fprintf(stderr, "bad option\n");
			return 1;
		default:
			fatal("bad option '%c'", c);
		}
	}

	if (optind != argc-1)
	{
		fprintf(stderr, "exactly one url expected\n");
		return 1;
	}
	url= argv[optind];

	if (atlas_id)
	{
		if (!validate_atlas_id(atlas_id))
		{
			fprintf(stderr, "bad atlas ID '%s'", atlas_id);
			return 1;
		}
	}

	if (maxpostsizestr)
	{
		maxpostsize= strtoul(maxpostsizestr, &check, 0);
		if (check[0] != 0)
		{
			report("unable to parse maxpostsize '%s'",
				maxpostsizestr);
			goto err;
		}
	}

	if (timeoutstr)
	{
		timeout= strtoul(timeoutstr, &check, 0);
		if (check[0] != 0)
		{
			report("unable to parse timeout '%s'",
				timeoutstr);
			goto err;
		}
	}

	tolerance= 0;
	if (time_tolerance)
	{
		tolerance= strtoul(time_tolerance, &p, 10);
		if (p[0] != '\0')
		{
			fprintf(stderr, "unable to parse tolerance '%s'\n",
				time_tolerance);
			return 1;
		}
	}

	if (parse_url(url, &host, &port, &hostport, &path) == -1)
		return 1;

	//printf("host: %s\n", host);
	//printf("port: %s\n", port);
	//printf("hostport: %s\n", hostport);
	//printf("path: %s\n", path);

	cLength= 0;

	if(post_header != NULL )
	{	
		if (!validate_filename(post_header, SAFE_PREFIX_DATA_OUT) &&
			!validate_filename(post_header, SAFE_PREFIX_STATUS))
		{
			report("protected file (for header) '%s'", post_header);
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
		cLength  +=  sbH.st_size;
	}

	if(post_footer != NULL )
	{	
		if (!validate_filename(post_footer, SAFE_PREFIX_DATA_OUT) &&
			!validate_filename(post_footer, SAFE_PREFIX_STATUS))
		{
			report("pretected file (for footer) '%s'", post_footer);
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
		cLength  +=  sbF.st_size;
	}

	/* Try to open the file before trying to connect */
	if (post_file != NULL)
	{
		if (!validate_filename(post_file, SAFE_PREFIX_DATA_OUT) &&
			!validate_filename(post_file, SAFE_PREFIX_STATUS))
		{
			report("protected file (post) '%s'", post_file);
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
		cLength  += sbS.st_size;
	}

	if (post_dir)
	{
		filelist= do_dir(post_dir, cLength, maxpostsize, &dir_length);
		if (!filelist)
		{
			/* Something went wrong. */
			goto err;
		}
		fprintf(stderr, "total size in dir: %ld\n", (long)dir_length);
		cLength += dir_length;
	}

	gettimeofday(&start_time, NULL);

	sa.sa_flags= 0;
	sa.sa_handler= got_alarm;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGALRM, &sa, NULL);
	alarm(10);
	signal(SIGPIPE, SIG_IGN);

	tcp_fd= connect_to_name(host, port);
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

	fprintf(stderr, "httppost: sending request\n");
	fprintf(tcp_file, "POST %s HTTP/1.1\r\n", path);
	//fprintf(tcp_file, "GET %s HTTP/1.1\r\n", path);
	fprintf(tcp_file, "Host: %s\r\n", host);
	fprintf(tcp_file, "Connection: close\r\n");
	fprintf(tcp_file, "User-Agent: httppost for atlas.ripe.net\r\n");
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
	{
		if (!write_to_tcp_fd(fdH, tcp_file))
			goto err;
	}

	if (post_file != NULL)
	{
		if (!write_to_tcp_fd(fdS, tcp_file))
			goto err;
	}

	if (post_dir)
	{
		for (p= filelist; p[0] != 0; p += strlen(p)+1)
		{
			fprintf(stderr, "posting file '%s'\n", p);
			if (!validate_filename(p, SAFE_PREFIX_DATA_OUT) &&
				!validate_filename(p, SAFE_PREFIX_DATA_OOQ_OUT))
			{
				report("protected file (post dir) '%s'", p);
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
				goto err;
		}
	}

	if( post_footer != NULL)
	{
		if (!write_to_tcp_fd(fdF, tcp_file))
			goto err;
	}

	fprintf(stderr, "httppost: getting result\n");
	if (!check_result(tcp_file))
		goto err;
	fprintf(stderr, "httppost: getting reply headers \n");
	server_time= 0;
	content_length= -1;
	if (!eat_headers(tcp_file, &chunked, &content_length, &server_time))
		goto err;

	if (tolerance && server_time > 0)
	{
		/* Try to set time from server */
		struct timeval now;
		double rtt;

		gettimeofday(&now, NULL);
		rtt= now.tv_sec-start_time.tv_sec;
		rtt += (now.tv_usec-start_time.tv_usec)/1e6;
		if (rtt < 0) rtt= 0;
		if (now.tv_sec < server_time-tolerance-rtt ||
			now.tv_sec > server_time+tolerance+rtt)
		{
			fprintf(stderr,
				"setting time, time difference is %ld\n",
				(long)server_time-now.tv_sec);
			stime(&server_time);
			if (atlas_id)
			{
				printf(
	"RESULT %s ongoing %ld httppost setting time, local %ld, remote %ld\n",
					atlas_id, (long)time(NULL),
					(long)now.tv_sec,
					(long)server_time);
			}
		}
		else if (rtt <= 1)
		{
			/* Time and network are fine. Record this fact */
			fh= fopen(ATLAS_TIMESYNC_FILE ".new", "wt");
			if (fh)
			{
				fprintf(fh, "%ld\n", (long)now.tv_sec);
				fclose(fh);
				rename(ATLAS_TIMESYNC_FILE ".new",
					ATLAS_TIMESYNC_FILE);
			}
		}
		else if (atlas_id)
		{
			printf("RESULT %s ongoing %ld httppost rtt %g ms\n",
				atlas_id, (long)time(NULL), rtt*1000);
		}
	}

	fprintf(stderr, "httppost: writing output\n");
	if (output_file)
	{
		if (!validate_filename(output_file, SAFE_PREFIX_DATA_NEW))
		{
			report("protected file (output) '%s'", output_file);
			goto err;
		}
		out_file= fopen(output_file, "w");
		if (!out_file)
		{
			report_err("unable to create '%s'", output_file);
			goto err;
		}
	}
	else
		out_file= stdout;

	fprintf(stderr, "httppost: chunked %d, content_length %d\n",
		chunked, content_length);
	found_ok= 0;
	if (chunked)
	{
		if (!copy_chunked(tcp_file, out_file, &found_ok))
			goto err;
	}
	else if (content_length >= 0)
	{
		if (!copy_bytes(tcp_file, out_file, content_length, &found_ok))
			goto err;
	}
	else
	{
		if (!copy_all(tcp_file, out_file, &found_ok))
			goto err;
	}
	if (!found_ok)
		fprintf(stderr, "httppost: reply text was not equal to OK\n");
	if ( opt_delete_file == 1  && found_ok)
	{
		fprintf(stderr, "httppost: deleting files\n");
		if (post_file)
		{
			if (!validate_filename(post_file, SAFE_PREFIX_DATA_OUT))
			{
				report("trying to delete protected file '%s'",
					post_file);
				goto err;
			}
			unlink (post_file);
		}
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
	if (tcp_file)
	{
		fclose(tcp_file);
		tcp_fd= -1;
	}
	if (tcp_fd != -1) close(tcp_fd);
	if (out_file) fclose(out_file);
	if (host) free(host);
	if (port) free(port);
	if (hostport) free(hostport);
	if (path) free(path);
	if (filelist) free(filelist);

	alarm(0);
	signal(SIGPIPE, SIG_DFL);

	return result; 

err:
	fprintf(stderr, "httppost: leaving with error\n");
	result= 1;
	goto leave;
}

static int write_to_tcp_fd (int fd, FILE *tcp_file)
{
	int r;
	char buffer[1024];

	/* Copy file */
	while(r= read(fd, buffer, sizeof(buffer)), r > 0)
	{
		if (fwrite(buffer, r, 1, tcp_file) != 1)
		{
			report_err("error writing to tcp connection");
			return 0;
		}
		alarm(10);
	}
	if (r == -1)
	{
		report_err("error reading from file");
		return 0;
	}
	return 1;
}


static int parse_url(char *url, char **hostp, char **portp, char **hostportp,
	char **pathp)
{
	char *item;
	const char *cp, *np, *prefix;
	size_t len;

	*hostportp= NULL;
	*pathp= NULL;
	*hostp= NULL;
	*portp= NULL;

	/* the url must start with 'http://' */
	prefix= "http://";
	len= strlen(prefix);
	if (strncasecmp(prefix, url, len) != 0)
	{
		fprintf(stderr, "bad prefix in url '%s'\n", url);
		return -1;
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
		fprintf(stderr, "missing host part in url '%s'\n", url);
		return -1;
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
			fprintf(stderr,
				"malformed IPv6 address literal in url '%s'\n",
				url);
			goto error;
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
		fprintf(stderr, "missing host part in url '%s'\n", url);
		goto error;
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

	return 0;
error:
	free(*hostportp); *hostportp= NULL;
	free(*pathp); *pathp= NULL;
	free(*hostp); *hostp= NULL;
	free(*portp); *portp= NULL;

	return -1;
}

static int check_result(FILE *tcp_file)
{
	int major, minor;
	size_t len;
	char *cp, *check, *line;
	const char *prefix;
	char buffer[1024];
	
	while (fgets(buffer, sizeof(buffer), tcp_file) == NULL)
	{
		if (feof(tcp_file))
		{
			report("got unexpected EOF from server");
			return 0;
		}
		if (errno == EINTR)
		{
			report("timeout");
			sleep(10);
		}
		else
		{
			report_err("error reading from server");
			return 0;
		}
	}

	line= buffer;
	cp= strchr(line, '\n');
	if (cp == NULL)
	{
		fprintf(stderr, "line too long\n");
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
		fprintf(stderr, "bad prefix in response '%s'\n", line);
		return 0;
	}
	cp= line+len;
	major= strtoul(cp, &check, 10);
	if (check == cp || check[0] != '.')
	{
		fprintf(stderr, "bad major version in response '%s'\n", line);
		return 0;
	}
	cp= check+1;
	minor= strtoul(cp, &check, 10);
	if (check == cp || check[0] == '\0' ||
		!isspace(*(unsigned char *)check))
	{
		fprintf(stderr, "bad major version in response '%s'\n", line);
		return 0;
	}

	skip_spaces(check, &cp);

	if (!isdigit(*(unsigned char *)cp))
	{
		fprintf(stderr, "bad status code in response '%s'\n", line);
		return 0;
	}

	if (cp[0] != '2')
	{
		report("POST command failed: '%s'", cp);
		return 0;
	}

	return 1;
}

static int eat_headers(FILE *tcp_file, int *chunked, int *content_length, time_t *timep)
{
	char *line, *cp, *ncp, *check;
	size_t len;
	const char *kw;
	char buffer[1024];

	*chunked= 0;
	while (fgets(buffer, sizeof(buffer), tcp_file) != NULL)
	{
		line= buffer;
		cp= strchr(line, '\n');
		if (cp == NULL)
		{
			fprintf(stderr, "line too long\n");
			return 0;
		}
		cp[0]= '\0';
		if (cp > line && cp[-1] == '\r')
			cp[-1]= '\0';

		if (line[0] == '\0')
			return 1;		/* End of headers */

		fprintf(stderr, "httppost: got line '%s'\n", line);

		if (strncmp(line, "Date: ", 6) == 0)
		{
			/* Parse date header */
			struct tm tm;

			cp= strptime(line+6, "%a, %d %b %Y %H:%M:%S ", &tm);
			if (!cp || strcmp(cp, "GMT") != 0)
			{
				fprintf(stderr, "unable to parse time '%s'\n",
					line+6);
			}
			*timep= timegm(&tm);
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
				fprintf(stderr,
					"malformed transfer-encoding header");
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
			fprintf(stderr, "malformed content-length header");
			return 0;
		}
		cp++;

		/* Skip more white space */
		skip_spaces(cp, &cp);

		/* Should have the value by now */
		*content_length= strtoul(cp, &check, 10);
		if (check == cp)
		{
			fprintf(stderr, "malformed content-length header\n");
			return 0;
		}

		/* And after that we should have just white space */
		cp= check;
		skip_spaces(cp, &cp);

		if (cp[0] != '\0')
		{
			fprintf(stderr, "malformed content-length header\n");
			return 0;
		}
	}
	if (feof(tcp_file))
		report("got unexpected EOF from server");
	else
		report_err("error reading from server");
	return 0;
}

static int connect_to_name(char *host, char *port)
{
	int r, s, s_errno;
	struct addrinfo *res, *aip;
	struct addrinfo hints;

	fprintf(stderr, "httppost: before getaddrinfo\n");
	memset(&hints, '\0', sizeof(hints));
	hints.ai_socktype= SOCK_STREAM;
	r= getaddrinfo(host, port, &hints, &res);
	if (r != 0)
	{
		fprintf(stderr, "unable to resolve '%s': %s\n",
			host, gai_strerror(r));
		errno= ENOENT;	/* Need something */
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

char *do_dir(char *dir_name, off_t curr_tot_size, off_t max_size, off_t *lenp)
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

		if (curr_tot_size + sb.st_size > max_size)
		{
			/* File is too big to fit this time. */
			if (sb.st_size > max_size/2)
			{
				/* File just too big in general */
				report("deleting file '%s', size %d",
					path, sb.st_size);
				unlink(path);
			}
			continue;
		}

		currsize += len;
		curr_tot_size += sb.st_size;
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

static int copy_chunked(FILE *in_file, FILE *out_file, int *found_okp)
{
	int i;
	size_t len, offset, size;
	char *cp, *line, *check;
	const char *okp;
	char buffer[1024];

	okp= OK_STR;

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
			fprintf(stderr, "line too long");
			return 0;
		}
		cp[0]= '\0';
		if (cp > line && cp[-1] == '\r')
			cp[-1]= '\0';

		fprintf(stderr, "httppost: got chunk line '%s'\n", line);
		len= strtoul(line, &check, 16);
		if (check[0] != '\0' && !isspace(*(unsigned char *)check))
		{
			fprintf(stderr, "bad chunk line '%s'", line);
			return 0;
		}
		if (!len)
			break;

		offset= 0;

		while (offset < len)
		{
			size= len-offset;
			if (size > sizeof(buffer))
				size= sizeof(buffer);
			if (fread(buffer, size, 1, in_file) != 1)
			{
				report_err("error reading input");
				return 0;
			}
			if (fwrite(buffer, size, 1, out_file) != 1)
			{
				fprintf(stderr, "error writing output");
				return 0;
			}
			offset += size;

			fprintf(stderr, "httppost: chunk data '%.*s'\n", 
				(int)size, buffer);
			for (i= 0; i<size; i++)
			{
				if (!okp)
					break;
				if (*okp != buffer[i] || *okp == '\0')
				{
					okp= NULL;
					break;
				}
				okp++;
			}
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
			fprintf(stderr, "line too long");
			return 0;
		}
		cp[0]= '\0';
		if (cp > line && cp[-1] == '\r')
			cp[-1]= '\0';
		if (line[0] != '\0')
		{
			fprintf(stderr, "Garbage after chunk data");
			return 0;
		}
	}

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
			fprintf(stderr, "line too long");
			return 0;
		}
		cp[0]= '\0';
		if (cp > line && cp[-1] == '\r')
			cp[-1]= '\0';
		if (line[0] == '\0')
			break;

		fprintf(stderr, "httppost: got end-of-chunk line '%s'\n", line);
	}
	*found_okp= (okp != NULL && *okp == '\0');
	return 1;
}

static int copy_bytes(FILE *in_file, FILE *out_file, size_t len, int *found_okp)
{
	int i;
	size_t offset, size;
	const char *okp;
	char buffer[1024];

	okp= OK_STR;

	offset= 0;

	while (offset < len)
	{
		size= len-offset;
		if (size > sizeof(buffer))
			size= sizeof(buffer);
		if (fread(buffer, size, 1, in_file) != 1)
		{
			report_err("error reading input");
			return 0;
		}
		if (fwrite(buffer, size, 1, out_file) != 1)
		{
			report_err("error writing output");
			return 0;
		}
		offset += size;

		fprintf(stderr, "httppost: normal data '%.*s'\n", 
				(int)size, buffer);

		for (i= 0; i<size; i++)
		{
			if (!okp)
				break;
			if (*okp != buffer[i] || *okp == '\0')
			{
				okp= NULL;
				break;
			}
			okp++;
		}
	}
	*found_okp= (okp != NULL && *okp == '\0');
	return 1;
}

static int copy_all(FILE *in_file, FILE *out_file, int *found_okp)
{
	int i, size;
	const char *okp;
	char buffer[1024];

	okp= OK_STR;

	while (!feof(in_file) && !ferror(in_file))
	{
		size= fread(buffer, 1, sizeof(buffer), in_file);
		if (size <= 0)
			break;
		if (fwrite(buffer, size, 1, out_file) != 1)
		{
			report_err("error writing output");
			return 0;
		}

		fprintf(stderr, "httppost: all data '%.*s'\n", 
				(int)size, buffer);

		for (i= 0; i<size; i++)
		{
			if (!okp)
				break;
			if (*okp != buffer[i] || *okp == '\0')
			{
				okp= NULL;
				break;
			}
			okp++;
		}
	}
	if  (ferror(in_file))
	{
		report_err("error reading input");
		return 0;
	}
	*found_okp= (okp != NULL && *okp == '\0');
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
	if (tcp_fd != -1 && time(NULL) > start_time.tv_sec+timeout)
	{
		report("setting tcp_fd to nonblock");
		fcntl(tcp_fd, F_SETFL, fcntl(tcp_fd, F_GETFL) | O_NONBLOCK);
	}
	kick_watchdog();
	report("got alarm, setting alarm again");
	alarm(1);
}

static void kick_watchdog(void)
{
	int fdwatchdog = open("/dev/watchdog", O_RDWR);
	if (fdwatchdog != -1)
	{
		write(fdwatchdog, "1", 1);
		close(fdwatchdog);
	}
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

#if 0
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
#endif

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
