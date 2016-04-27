/*
 * rptaddrs.c
 * Copyright (c) 2013-2014 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include <errno.h>
#include <resolv.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <net/route.h>
#include <net/if.h>
#include <inet_common.h>
#include "../eperd/eperd.h"
#include "../eperd/readresolv.h"

#include "libbb.h"

#define IPV4_ROUTE_FILE	"/proc/net/route"
#define IF_INET6_FILE	"/proc/net/if_inet6"
#define IPV6_ROUTE_FILE	"/proc/net/ipv6_route"
#define SUFFIX		".new"

#define IPV4_STATIC	ATLAS_STATUS "/network_v4_static_info.json"
#define IPV6_STATIC	ATLAS_STATUS "/network_v6_static_info.json"
#define DNS_STATIC	ATLAS_STATUS "/network_dns_static_info.json"
#define NETWORK_INFO	ATLAS_STATUS "/network_v4_info.txt"

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

static FILE *setup_cache(char *cache_name);
static int setup_ipv4_rpt(FILE *of);
static int setup_dhcpv4(FILE *of);
static int setup_ipv6_rpt(FILE *of);
static int setup_dns(FILE *of);
static int setup_static_rpt(FILE *of);
static int report_line(FILE *of, const char *fn);
static int check_cache(char *cache_name);
static int rpt_ipv6(char *cache_name, char *out_name, char *opt_atlas, int opt_append);
static void report(const char *fmt, ...);
static void report_err(const char *fmt, ...); 

int rptaddrs_main(int argc, char *argv[]);

int rptaddrs_main(int argc UNUSED_PARAM, char *argv[])
{
	int r, need_report;
	unsigned opt;
	char *opt_atlas;
       	char *cache_name;	/* temp file in an intermediate format */
	char *out_name;		/* output file in json: timestamp opt_atlas */
	int opt_append;
	FILE *cf;

	opt_atlas= NULL;
	out_name = NULL;
	cache_name = NULL;
	opt_atlas = NULL;
	opt_complementary= NULL;
	opt_append = FALSE;

	opt= getopt32(argv, OPT_STRING, &opt_atlas, &out_name, &cache_name);

	if (out_name && !validate_filename(out_name, SAFE_PREFIX_N))
	{
		crondlog(LVL8 "insecure file '%s' : allowed '%s'", out_name, 
				SAFE_PREFIX_N);
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

	cf= setup_cache(cache_name);
	if (cf == NULL)
		return 1;

	r= setup_ipv4_rpt(cf);
	if (r == -1)
	{
		fclose(cf);
		return 1;
	}

	r= setup_dhcpv4(cf);
	if (r == -1)
	{
		fclose(cf);
		return 1;
	}

	r= setup_ipv6_rpt(cf);
	if (r == -1)
	{
		fclose(cf);
		return 1;
	}

	r= setup_dns(cf);
	if (r == -1)
	{
		fclose(cf);
		return 1;
	}

	r= setup_static_rpt(cf);
	if (r == -1)
	{
		fclose(cf);
		return 1;
	}
	fclose(cf);

	need_report= check_cache(cache_name);
	if (need_report)
	{
		r = rpt_ipv6(cache_name, out_name, opt_atlas, opt_append);
		if (r != 0)
			return r;
	}

	return 0;
}

static FILE *setup_cache(char *cache_name)
{
	FILE *out_file;
	char filename[80];

	if (strlen(cache_name) + strlen(SUFFIX) + 1 > sizeof(filename))
	{
		report("cache name '%s' too long", cache_name);
		return NULL;
	}

	strlcpy(filename, cache_name, sizeof(filename));
	strlcat(filename, SUFFIX, sizeof(filename));

	out_file= fopen(filename, "w");
	if (out_file == NULL)
	{
		report_err("unable to create '%s'", filename);
		return NULL;
	}

	return out_file;
}

#define MAX_INF	10

static int setup_ipv4_rpt(FILE *of)
{
	int i, r, s, first;
	unsigned dest, gateway, flags, refcnt, use, metric, mask;
	FILE *in_file;
	struct in_addr in_addr;
	struct ifconf ifconf;
	struct ifreq ifreq1;
	struct ifreq ifreq[MAX_INF];
	char infname[20];
	char line[256];

	s= socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (s == -1)
	{
		report_err("socket failed");
		return -1;
	}
	ifconf.ifc_len= sizeof(ifreq);
	ifconf.ifc_req= ifreq;
	r= ioctl(s, SIOCGIFCONF, &ifconf);
	if (r == -1)
	{
		report_err("SIOCGIFCONF failed");
		close(s);
		return -1;
	}

	fprintf(of, DBQ(inet-addresses) ": [ ");
	for (i= 0; i<ifconf.ifc_len/sizeof(ifreq[0]); i++)
	{
		memcpy(ifreq1.ifr_name, ifreq[i].ifr_name,
			sizeof(ifreq1.ifr_name));
		r= ioctl(s, SIOCGIFNETMASK, &ifreq1);
		if (r == -1)
		{
			report_err("SIOCGIFNETMASK failed");
			close(s);
			return -1;
		}
		fprintf(of, "%s{ " DBQ(inet-addr) ": " DBQ(%s) ", ",
			i == 0 ? "" : ", ",
			inet_ntoa(((struct sockaddr_in *)(&ifreq[i].ifr_addr))
				->sin_addr));
		fprintf(of, DBQ(netmask) ": " DBQ(%s) ", " 
			DBQ(interface) ": " DBQ(%s) " }",
			inet_ntoa(((struct sockaddr_in *)(&ifreq1.ifr_addr))->
				sin_addr),
			ifreq[i].ifr_name);
	}

	close(s);

	fprintf(of, " ]");

	in_file= fopen(IPV4_ROUTE_FILE, "r");
	if (in_file == NULL)
	{
		report_err("unable to open '%s'", IPV4_ROUTE_FILE);
		return -1;
	}
	
	/* Skip first line */
	fgets(line, sizeof(line), in_file);
	
	fprintf(of, ", " DBQ(inet-routes) ": [ ");
	first= 1;

	while (fgets(line, sizeof(line), in_file) != NULL)
	{
		sscanf(line, "%16s %x %x %x %d %d %d %x",
			infname, &dest, &gateway, &flags, &refcnt, &use, 
			&metric, &mask);
		in_addr.s_addr= dest;
		fprintf(of, "%s{ " DBQ(destination) ": " DBQ(%s) ", ",
			first ? "" : ", ", inet_ntoa(in_addr));
		in_addr.s_addr= mask;
		fprintf(of, DBQ(netmask) ": " DBQ(%s) ", ",
			inet_ntoa(in_addr));
		in_addr.s_addr= gateway;
		fprintf(of, DBQ(next-hop) ": " DBQ(%s) ", "
			DBQ(interface) ": " DBQ(%s) " }",
			inet_ntoa(in_addr), infname);
		first= 0;
	}

	fprintf(of, " ]");

	fclose(in_file);

	return 0;
}

static int setup_dhcpv4(FILE *of)
{
	int found;
	FILE *in_file;
	const char *value;
	char line[128];

	in_file= fopen(NETWORK_INFO, "r");
	if (in_file == NULL)
	{
		if (errno == ENOENT)
		{
			/* Probe is configure for DHCP but didn't get a 
			 * DHCP lease.
			 */
			fprintf(of, ", " DBQ(inet-dhcp) ": true");
			return 0;
		}
		report_err("unable to open '%s'", NETWORK_INFO);
		return -1;
	}
	found= 0;
	while (fgets(line, sizeof(line), in_file) != NULL)
	{
		if (strncmp(line, "DHCP ", 5) == 0)
		{
			value= NULL;
			if (strncmp(line+5, "True", 4) == 0)
				value= "true";
			else if (strncmp(line+5, "False", 5) == 0)
				value= "false";
			if (value)
			{
				fprintf(of, ", " DBQ(inet-dhcp) ": %s",
					value);
				found= 1; 
				break;
			}
		}
	}
	
	fclose(in_file);
	if (found)
		return 0;
	report("setup_dhcpv4: DHCP field not found");
	return -1;
}

static int setup_ipv6_rpt(FILE *of)
{
	int r, n;
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
	char buf2[1024];

	FILE *in_file;

	/* Copy IF_INET6_FILE */
	in_file= fopen(IF_INET6_FILE, "r");
	if (in_file == NULL)
	{
		report_err("unable to open '%s'", IF_INET6_FILE);
		return -1;
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
		r = snprintf(buf2, sizeof(buf2), "%s %s{" DBQ(inet6-addr) " : "
				DBQ(%s) ", " DBQ(prefix-length) " : %d,"
				DBQ(scope) " : " DBQ(%s) ", " DBQ(interface) 
				" : " DBQ(%s) "}",  
				n ? "" : ", \"inet6-addresses\" : [", n ? ", " : ""
				, dst6out, prefix_len, Scope, iface);

		/* printf("%s\n", buf2); */

		if(dst6out) {
			free(dst6out);
			dst6out=NULL;
		}
		n++;
		if (fwrite(buf2, 1, r, of) != r)
		{
			report_err("error writing to '%s'", filename);
			fclose(in_file);
			return -1;
		}

		if (ferror(in_file))
		{
			report_err("error reading from '%s'", IF_INET6_FILE);
			fclose(in_file);
			return -1;
		}
	}	
	if ( n > 0 ) {
		r = snprintf(buf2, 2, "]");
	}		
	if (fwrite(buf2, 1, r, of) != r)
	{
		report_err("error writing to '%s'", filename);
		fclose(in_file);
		return -1;
	}

	fclose(in_file);

	/* Copy IPV6_ROUTE_FILE */
	in_file= fopen(IPV6_ROUTE_FILE, "r");
	if (in_file == NULL)
	{
		report_err("unable to open '%s'", IPV6_ROUTE_FILE);
		return -1;
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
			return -1;
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

		if (prefix_len == 128)
			continue;	/* Skip host routes */

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
				DBQ(%s) ", " DBQ(prefix-length) " : %d,"
				DBQ(next-hop) " : " DBQ(%s) ", " DBQ(flags)
				" : " DBQ(%s) ", " DBQ(metric) " : %d , "
				DBQ(interface) " : " DBQ(%s) "}",
				n ? "" : ", \"inet6-routes\" : [", n ? ", " : ""
				, dst6out, prefix_len, nh6out, flags, metric
				, iface);

		/*
		r = snprintf(buf2, sizeof(buf2), "%s %s{" DBQ(destination) " : "
				DBQ(%s) ", " DBQ(prefix-length) " : %d," 
				DBQ(next-hop) " : " DBQ(%s) ", " DBQ(flags) 
				" : " DBQ(%s) ", " DBQ(metric) " : %d , "
				DBQ(interface) " : " DBQ(%s) "}",
				n ? " " : '"inet6-routes" ['
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

		if (fwrite(buf2, 1, r, of) != r)
		{
			report_err("error writing to '%s'", filename);
			fclose(in_file);
			return -1;
		}
		n++;
	}
	if ( n > 0 ) {
		r = snprintf(buf2, 2, "]");
	}		
	if (fwrite(buf2, 1, r, of) != r)
	{
		report_err("error writing to '%s'", filename);
		fclose(in_file);
		return -1;
	}


	if (ferror(in_file))
	{
		report_err("error reading from '%s'", IPV6_ROUTE_FILE);
		fclose(in_file);
		return -1;
	}
	fclose(in_file);

	return 0;
}

static int setup_dns(FILE *of)
{
	int i, resolv_max;
	char nslist[MAXNS][INET6_ADDRSTRLEN * 2];

	resolv_max= 0;

	get_local_resolvers_nocache(nslist, &resolv_max);

	fprintf(of, ", " DBQ(dns) ": [ ");
	for (i= 0; i<resolv_max; i++)
	{
		fprintf(of, "%s{ " DBQ(nameserver) ": " DBQ(%s) " }",
			i == 0 ? "" : ", ", 
			nslist[i]);
	}
	
	fprintf(of, " ]");
	
	return 0;
}

static int setup_static_rpt(FILE *of)
{
	int r;

	r= report_line(of, IPV4_STATIC);
	if (r == -1)
		return -1;
	r= report_line(of, IPV6_STATIC);
	if (r == -1)
		return -1;
	r= report_line(of, DNS_STATIC);
	if (r == -1)
		return -1;
	return 0;
}

static int report_line(FILE *of, const char *fn)
{
	FILE *f;
	char *nl;
	char line[512];

	f= fopen(fn, "r");
	if (f == NULL)
	{
		if (errno != ENOENT)
		{
			report_err("open '%s' failed", fn);
			return -1;
		}
	}
	else
	{
		if (fgets(line, sizeof(line), f) == NULL)
		{
			if (ferror(f))
			{
				report_err("error reading from '%s'", fn);
			}
			else
				report("error reading from '%s': EOF");
			fclose(f);
			return -1;
		}
		fclose(f);
		nl= strchr(line, '\n');
		if (nl == NULL)
		{
			report("line too long in '%s'", fn);
			return -1;
		}
		*nl= '\0';
		fprintf(of, ", %s", line);
	}

	return 0;
}

static int check_cache(char *cache_name)
{
	int r, need_report;
	struct stat sb;
	char filename[80];

	char buf1[1024];
	char buf2[1024];
	FILE *in_file, *cache_file;

	strlcpy(filename, cache_name, sizeof(filename));
	strlcat(filename, SUFFIX, sizeof(filename));

	need_report= 0;

	if (stat(cache_name, &sb) == 0 &&
		sb.st_mtime < time(NULL) - 3600)
	{
		/* This basically makes sure that this information gets
		 * reported regularly.
		 */
		need_report= 1;
	}

	/* Now check if the new file is different from the cache one */
	cache_file= fopen(cache_name, "r");
	if (cache_file == NULL)
	{
		/* Assume that any kind of error here calls for reporting */
		need_report= 1;
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
				need_report= 1;
				break;
			}

			if (memcmp(buf1, buf2, r) != 0)
			{
				/* Something changed, report */
				need_report= 1;
				break;
			}
		}

		/* Maybe something got added */
		if (!need_report)
		{
			if (fread(buf2, 1, sizeof(buf2), in_file) != 0)
			{
				need_report= 1;
			}
		}
		fclose(cache_file);
		fclose(in_file);
	}

	if (need_report)
	{
		if (rename(filename, cache_name) == -1)
		{
			report_err("renaming '%s' to '%s' failed",
				filename, cache_name);
			return 0;
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

	return need_report;
}

static int rpt_ipv6(char *cache_name, char *out_name, char *opt_atlas, int opt_append)
{
	FILE *file;
	FILE *fh;
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
			fh= fopen(out_name, "a");
		else 
			fh= fopen(out_name, "w");

		if (!fh)
		{
			report_err("unable to append to '%s'", out_name);
			return 1;
		}
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

	fprintf(stderr, "rptaddrs: ");
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

	fprintf(stderr, "rptaddrs: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, ": %s\n", strerror(t_errno));

	va_end(ap);
}
