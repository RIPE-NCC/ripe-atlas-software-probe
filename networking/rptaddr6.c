/*
 * rptaddr6.c
 * Copyright (c) 2013 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <net/route.h>
#include <inet_common.h>
#include "../eperd/eperd.h"

#include "libbb.h"

#define IF_INET6_FILE	"/proc/net/if_inet6"
#define IPV6_ROUTE_FILE	"/proc/net/ipv6_route"
#define SUFFIX		".new"

#define SAFE_PREFIX_O ATLAS_DATA_OUT
#define SAFE_PREFIX_N ATLAS_DATA_NEW

#define OPT_STRING      "A:O:c:"

#define DBQ(str) "\"" #str "\""
#define JS(key, val) fprintf(fh, "\"" #key"\" : \"%s\" , ",  val);
#define JS1(key, fmt, val) fprintf(fh, "\"" #key"\" : "#fmt" , ",  val);

#ifndef IPV6_MASK
#define IPV6_MASK (RTF_GATEWAY|RTF_HOST|RTF_DEFAULT|RTF_ADDRCONF|RTF_CACHE)
#endif

#define IPV6_ADDR_LOOPBACK      0x0010U
#define IPV6_ADDR_LINKLOCAL     0x0020U
#define IPV6_ADDR_SITELOCAL     0x0040U

#define IPV6_ADDR_COMPATv4      0x0080U

#define IPV6_ADDR_SCOPE_MASK    0x00f0U

enum { 
	OPT_a =  (1 << 0),
};

static int setup_ipv6_rpt(char *cache_name, int *need_report);
static int rpt_ipv6(char *cache_name, char *out_name, char *opt_atlas, int opt_append);
static void report(const char *fmt, ...);
static void report_err(const char *fmt, ...); 

int rptaddr6_main(int argc, char *argv[])
{
	int r, need_report;
	unsigned opt;
	char *opt_atlas;
       	char *cache_name;	/* temp file in an intermediate format */
	char *out_name;		/* output file in json: timestamp opt_atlas */
	int opt_append;

	opt_atlas= NULL;
	out_name = NULL;
	cache_name = NULL;
	opt_atlas = NULL;
	opt_complementary= NULL;
	opt_append = FALSE;

	opt= getopt32(argv, OPT_STRING, &opt_atlas, &out_name, &cache_name);

	if (out_name && !validate_filename(out_name, SAFE_PREFIX_O))
	{
		crondlog(LVL8 "insecure file '%s' : allowed '%s'", out_name, 
				SAFE_PREFIX_O);
		return 1;
	}
	if (cache_name && !validate_filename(cache_name, SAFE_PREFIX_N))
	{
		crondlog(LVL8 "insecure file '%s' allowed %s", cache_name,
				SAFE_PREFIX_N);
		return 1;
	}

	if (!cache_name)  {
		crondlog(LVL8 "missing requried option, -c <cache_file>");
		return 1;
	}

	if (opt & OPT_a) 
		opt_append = TRUE;

	r= setup_ipv6_rpt(cache_name, &need_report);
	if (r != 0)
		return r;
	if (need_report)
	{
		r = rpt_ipv6(cache_name, out_name, opt_atlas, opt_append);
		if (r != 0)
			return r;
	}

	return 0;
}
static int setup_ipv6_rpt(char *cache_name, int *need_report)
{
	int i, r, n;
	char *cp, *cp1;
	char filename[80];
	char dst6in[INET6_ADDRSTRLEN];
	char nh6in[INET6_ADDRSTRLEN]; /* next hop */
	char *dst6out = NULL;
	char *nh6out = NULL;
	char dst6p[8][5];
	char nh6p[8][5];
	char iface[16], flags[16];
	char Scope[32];
	int scope, dad_status, if_idx;
	int iflags, metric, refcnt, use, prefix_len, slen;
	struct sockaddr_in6 sdst6, snh6;

	char buf1[1024];
	char buf2[1024];
	FILE *in_file, *out_file, *cache_file;

	*need_report= 0;

	if (strlen(cache_name) + strlen(SUFFIX) + 1 > sizeof(filename))
	{
		report("cache name '%s' too long", cache_name);
		return 1;
	}

	strlcpy(filename, cache_name, sizeof(filename));
	strlcat(filename, SUFFIX, sizeof(filename));

	out_file= fopen(filename, "w");
	if (out_file == NULL)
	{
		report_err("unable to create '%s'", filename);
		return 1;
	}

	/* Copy IF_INET6_FILE */
	in_file= fopen(IF_INET6_FILE, "r");
	if (in_file == NULL)
	{
		report_err("unable to open '%s'", IF_INET6_FILE);
		fclose(out_file);
		return 1;
	}
	n = 0;
	while ((r = fscanf(in_file, "%4s%4s%4s%4s%4s%4s%4s%4s %08x %02x %02x %02x %20s\n",
					dst6p[0], dst6p[1], dst6p[2]
					, dst6p[3], dst6p[4], dst6p[5]
					, dst6p[6], dst6p[7], &if_idx, &prefix_len
					, &scope, &dad_status, iface)) != EOF) {

		snprintf(dst6in, sizeof(dst6in), "%s:%s:%s:%s:%s:%s:%s:%s",
				dst6p[0], dst6p[1], dst6p[2], dst6p[3],
				dst6p[4], dst6p[5], dst6p[6], dst6p[7]);

		inet_pton(AF_INET6, dst6in, (struct sockaddr *) &sdst6.sin6_addr);
		sdst6.sin6_family = AF_INET6;
		dst6out = INET6_rresolve((struct sockaddr_in6 *) &sdst6, 0x0fff);

		switch (scope & IPV6_ADDR_SCOPE_MASK) {
			case 0:
				snprintf(Scope, sizeof(Scope), "Global");
				break;
			case IPV6_ADDR_LINKLOCAL:
				snprintf(Scope, sizeof(Scope), "Link");
				break;
			case IPV6_ADDR_SITELOCAL:
				snprintf(Scope, sizeof(Scope), "Site");
				break;
			case IPV6_ADDR_COMPATv4:
				snprintf(Scope, sizeof(Scope), "Compat");
				break;
			case IPV6_ADDR_LOOPBACK:
				snprintf(Scope, sizeof(Scope), "Host");
				break;
			default:
				snprintf(Scope, sizeof(Scope), "Unknown %d", scope);
		}
		r = snprintf(buf2, sizeof(buf2), "%s %s{" DBQ(inet6 addr) " : "
				DBQ(%s) ", " DBQ(prefix length) " : %d,"
				DBQ(scope) " : " DBQ(%s) ", " DBQ(interface) 
				" : " DBQ(%s) "}",  
				n ? "" : "\"inet6 addresses\" : [", n ? ", " : ""
				, dst6out, prefix_len, Scope, iface);

		/* printf("%s\n", buf2); */

		if(dst6out) {
			free(dst6out);
			dst6out=NULL;
		}
		n++;
		if (fwrite(buf2, 1, r, out_file) != r)
		{
			report_err("error writing to '%s'", filename);
			fclose(in_file);
			fclose(out_file);
			return 1;
		}

		if (ferror(in_file))
		{
			report_err("error reading from '%s'", IF_INET6_FILE);
			fclose(in_file);
			fclose(out_file);
			return 1;
		}
	}	
	if ( n > 0 ) {
		r = snprintf(buf2, 2, "]");
	}		
	if (fwrite(buf2, 1, r, out_file) != r)
	{
		report_err("error writing to '%s'", filename);
		fclose(in_file);
		fclose(out_file);
		return 1;
	}

	fclose(in_file);

	/* Copy IPV6_ROUTE_FILE */
	in_file= fopen(IPV6_ROUTE_FILE, "r");
	if (in_file == NULL)
	{
		report_err("unable to open '%s'", IPV6_ROUTE_FILE);
		fclose(out_file);
		return 1;
	}

	n = 0;
	while ((r = fscanf (in_file, "%4s%4s%4s%4s%4s%4s%4s%4s%x%*s%x%4s%4s%4s%4s%4s%4s%4s%4s%x%x%x%x%s\n",
				dst6p[0], dst6p[1], dst6p[2], dst6p[3], dst6p[4],
				dst6p[5], dst6p[6], dst6p[7], &prefix_len, &slen, 
				nh6p[0], nh6p[1], nh6p[2], nh6p[3], nh6p[4],
				nh6p[5], nh6p[6], nh6p[7], &metric, &use, &refcnt, &iflags, iface)) != EOF) {

		if (r != 23) {
			if ((r < 0) && feof(in_file)) { /* EOF with no (nonspace) chars read. */
				break;
			}
			report_err("reading '%s'", IF_INET6_FILE);
			fclose(in_file);
			fclose(out_file);
			return 1;
		}

		/* skip some the stuff we don't want to report */
		if (!(iflags & RTF_UP)) { /* Skip interfaces that are down. */
			continue;
		}
		if ((iflags & RTF_ADDRCONF) && (iflags & RTF_CACHE)) { /* Skip interfaces that are down. */
			continue;
		}

		if ( strncmp (dst6p[0], "ff02", strlen("ff02")) == 0 ) {
			continue;
		}
		if ( strncmp (dst6p[0], "ff00", strlen("ff00")) == 0 ) {
			continue;
		}

		 snprintf(dst6in, sizeof(dst6in), "%s:%s:%s:%s:%s:%s:%s:%s",
                                                dst6p[0], dst6p[1], dst6p[2], dst6p[3],
                                                dst6p[4], dst6p[5], dst6p[6], dst6p[7]);

		 snprintf(nh6in, sizeof(nh6in), "%s:%s:%s:%s:%s:%s:%s:%s",
				 nh6p[0], nh6p[1], nh6p[2], nh6p[3],
				 nh6p[4], nh6p[5], nh6p[6], nh6p[7]);

		
		set_flags(flags, (iflags & IPV6_MASK));
		inet_pton(AF_INET6, dst6in, (struct sockaddr *) &sdst6.sin6_addr);
		sdst6.sin6_family = AF_INET6;
		dst6out = INET6_rresolve((struct sockaddr_in6 *) &sdst6, 0x0fff);

		inet_pton(AF_INET6, nh6in, (struct sockaddr *) &snh6.sin6_addr);
		snh6.sin6_family = AF_INET6;
		nh6out = INET6_rresolve((struct sockaddr_in6 *) &snh6, 0x0fff);
	
			
		r = snprintf(buf2, sizeof(buf2), "%s %s{" DBQ(destination) " : "
				DBQ(%s) ", " DBQ(prefix length) " : %d,"
				DBQ(next hop) " : " DBQ(%s) ", " DBQ(flags)
				" : " DBQ(%s) ", " DBQ(metric) " : %d , "
				DBQ(interface) " : " DBQ(%s) "}",
				n ? "" : ", \"inet6 routes\" : [", n ? ", " : ""
				, dst6out, prefix_len, nh6out, flags, metric
				, iface);

		/*
		r = snprintf(buf2, sizeof(buf2), "%s %s{" DBQ(destination) " : "
				DBQ(%s) ", " DBQ(prefix length) " : %d," 
				DBQ(next hop) " : " DBQ(%s) ", " DBQ(flags) 
				" : " DBQ(%s) ", " DBQ(metric) " : %d , "
				DBQ(interface) " : " DBQ(%s) "}",
				n ? " " : '"inet6 routes" ['
				, n ? ", " : ""
				, dst6out, prefix_len, nh6out, flags, metric
				, iface); 
				*/

		/* printf("%s\n", buf2); */
		
		if(dst6out) {
			free(dst6out);
			dst6out=NULL;
		}
		if(nh6out) {
			free(nh6out);
			nh6out=NULL;
		}

		if (fwrite(buf2, 1, r, out_file) != r)
		{
			report_err("error writing to '%s'", filename);
			fclose(in_file);
			fclose(out_file);
			return 1;
		}
		n++;
	}
	if ( n > 0 ) {
		r = snprintf(buf2, 2, "]");
	}		
	if (fwrite(buf2, 1, r, out_file) != r)
	{
		report_err("error writing to '%s'", filename);
		fclose(in_file);
		fclose(out_file);
		return 1;
	}


	if (ferror(in_file))
	{
		report_err("error reading from '%s'", IPV6_ROUTE_FILE);
		fclose(in_file);
		fclose(out_file);
		return 1;
	}
	fclose(in_file);

	/* Now check if the new file is different from the cache one */
	fclose(out_file);
	cache_file= fopen(cache_name, "r");
	if (cache_file == NULL)
	{
		/* Assume that any kind of error here calls for reporting */
		*need_report= 1;
	}

	if (cache_file)
	{
		in_file= fopen(filename, "r");
		if (in_file == NULL)
		{
			report_err("unable to open '%s'", filename);
			fclose(cache_file);
			return 1;
		}

		/* Compare them */
		while (r= fread(buf1, 1, sizeof(buf1), cache_file), r > 0)
		{
			if (fread(buf2, 1, sizeof(buf2), in_file) != r)
			{
				/* Ignore errors, just report */
				*need_report= 1;
				break;
			}

			if (memcmp(buf1, buf2, r) != 0)
			{
				/* Something changed, report */
				*need_report= 1;
				break;
			}
		}

		/* Maybe something got added */
		if (!*need_report)
		{
			if (fread(buf2, 1, sizeof(buf2), in_file) != 0)
			{
				*need_report= 1;
			}
		}
		fclose(cache_file);
		fclose(in_file);
	}

	if (*need_report)
	{
		if (rename(filename, cache_name) == -1)
		{
			report_err("renaming '%s' to '%s' failed",
				filename, cache_name);
			return 1;
		}
	}
	else
	{
		if (unlink(filename) == -1)
		{
			report_err("unlinking '%s' failed",
				filename);
		}
	}

	return 0;
}


static int rpt_ipv6(char *cache_name, char *out_name, char *opt_atlas, int opt_append)
{
	FILE *file;
	FILE *fh;
	char *cp;
	char buf[256];
	struct timeval now;

	file= fopen(cache_name, "r");
	if (!file)
	{
		report_err("unable to open cache file '%s'", cache_name);
		return 1;
	}

	if (out_name) {
		if(opt_append) 
			fh= fopen(out_name, "w");
		else 
			fh= fopen(out_name, "w");

		if (!fh)
			crondlog(DIE9 "unable to append to '%s'", out_name);
	}
	else
		fh = stdout;

	fprintf(fh, "RESULT { "); 
	if(opt_atlas)
	{
		JS(id,  opt_atlas);
	}
	gettimeofday(&now, NULL);
	JS1(time, %ld,  now.tv_sec);

	/* Copy all lines */
	while (fgets(buf, sizeof(buf), file) != NULL)
	{
		fputs(buf, fh);
	}
	fprintf(fh, "}\n"); 
	fclose(file);
	fclose(fh);

	return 0;
}

static void report(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	fprintf(stderr, "rptaddr6: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");

	va_end(ap);
}

static void report_err(const char *fmt, ...)
{
	int t_errno;
	va_list ap;

	t_errno= errno;

	va_start(ap, fmt);

	fprintf(stderr, "rptaddr6: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, ": %s\n", strerror(t_errno));

	va_end(ap);
}
