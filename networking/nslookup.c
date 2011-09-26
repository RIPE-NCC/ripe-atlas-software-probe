/* vi: set sw=4 ts=4: */
/*
 * Mini nslookup implementation for busybox
 *
 * Copyright (C) 1999,2000 by Lineo, inc. and John Beppu
 * Copyright (C) 1999,2000,2001 by John Beppu <beppu@codepoet.org>
 *
 * Correct default name server display and explicit name server option
 * added by Ben Zeckel <bzeckel@hmc.edu> June 2001
 *
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include <resolv.h>
#include "libbb.h"

#define ATLAS 1
#define ENABLE_FEATURE_CLEAN_UP	1	/* Where does this come from? */

/*
 * I'm only implementing non-interactive mode;
 * I totally forgot nslookup even had an interactive mode.
 *
 * This applet is the only user of res_init(). Without it,
 * you may avoid pulling in _res global from libc.
 */

/* Examples of 'standard' nslookup output
 * $ nslookup yahoo.com
 * Server:         128.193.0.10
 * Address:        128.193.0.10#53
 *
 * Non-authoritative answer:
 * Name:   yahoo.com
 * Address: 216.109.112.135
 * Name:   yahoo.com
 * Address: 66.94.234.13
 *
 * $ nslookup 204.152.191.37
 * Server:         128.193.4.20
 * Address:        128.193.4.20#53
 *
 * Non-authoritative answer:
 * 37.191.152.204.in-addr.arpa     canonical name = 37.32-27.191.152.204.in-addr.arpa.
 * 37.32-27.191.152.204.in-addr.arpa       name = zeus-pub2.kernel.org.
 *
 * Authoritative answers can be found from:
 * 32-27.191.152.204.in-addr.arpa  nameserver = ns1.kernel.org.
 * 32-27.191.152.204.in-addr.arpa  nameserver = ns2.kernel.org.
 * 32-27.191.152.204.in-addr.arpa  nameserver = ns3.kernel.org.
 * ns1.kernel.org  internet address = 140.211.167.34
 * ns2.kernel.org  internet address = 204.152.191.4
 * ns3.kernel.org  internet address = 204.152.191.36
 */

#ifdef ATLAS
#define WATCHDOGDEV "/dev/watchdog"

static char *str_Atlas;

#define ATLAS_NEWLINE() \
	do \
	{ \
		if (str_Atlas) printf(" NEWLINE "); \
		else bb_putchar('\n'); \
	} while (0)

#endif

static int print_host(const char *hostname, const char *header)
{
	/* We can't use xhost2sockaddr() - we want to get ALL addresses,
	 * not just one */
	struct addrinfo *result = NULL;
	int rc;
	struct addrinfo hint;

	memset(&hint, 0 , sizeof(hint));
	/* hint.ai_family = AF_UNSPEC; - zero anyway */
	/* Needed. Or else we will get each address thrice (or more)
	 * for each possible socket type (tcp,udp,raw...): */
	hint.ai_socktype = SOCK_STREAM;
	// hint.ai_flags = AI_CANONNAME;
	rc = getaddrinfo(hostname, NULL /*service*/, &hint, &result);

	if (!rc) {
		struct addrinfo *cur = result;
		unsigned cnt = 0;

		printf("%-10s %s", header, hostname);
#ifdef ATLAS
		ATLAS_NEWLINE();
#else
		bb_putchar('\n');
#endif
		// puts(cur->ai_canonname); ?
		while (cur) {
			char *dotted, *revhost;
			dotted = xmalloc_sockaddr2dotted_noport(cur->ai_addr);
			revhost = xmalloc_sockaddr2hostonly_noport(cur->ai_addr);

			printf("Address %u: %s", ++cnt, dotted);
#ifdef ATLAS
			if (revhost)
				bb_putchar(' ');
			else
				ATLAS_NEWLINE();
#else
			printf("%c", revhost ? ' ' : '\n');
#endif
			if (revhost) {
				puts(revhost);
				if (ENABLE_FEATURE_CLEAN_UP)
					free(revhost);
			}
			if (ENABLE_FEATURE_CLEAN_UP)
				free(dotted);
			cur = cur->ai_next;
		}
	} else {
#ifdef ATLAS
		printf("Name: %s NEWLINE bad-hostname %s", hostname,
			gai_strerror(rc));
#endif
#if ENABLE_VERBOSE_RESOLUTION_ERRORS
		bb_error_msg("can't resolve '%s': %s", hostname, gai_strerror(rc));
#else
		bb_error_msg("can't resolve '%s'", hostname);
#endif
	}
	if (ENABLE_FEATURE_CLEAN_UP)
		freeaddrinfo(result);
	return (rc != 0);
}

/* lookup the default nameserver and display it */
static void server_print(void)
{
	char *server;

	server = xmalloc_sockaddr2dotted_noport((struct sockaddr*)&_res.nsaddr_list[0]);
	/* I honestly don't know what to do if DNS server has _IPv6 address_.
	 * Probably it is listed in
	 * _res._u._ext_.nsaddrs[MAXNS] (of type "struct sockaddr_in6*" each)
	 * but how to find out whether resolver uses
	 * _res.nsaddr_list[] or _res._u._ext_.nsaddrs[], or both?
	 * Looks like classic design from hell, BIND-grade. Hard to surpass. */
	print_host(server, "Server:");
	if (ENABLE_FEATURE_CLEAN_UP)
		free(server);
#ifdef ATLAS
	ATLAS_NEWLINE();
#else
	bb_putchar('\n');
#endif
}

/* alter the global _res nameserver structure to use
   an explicit dns server instead of what is in /etc/resolv.conf */
static void set_default_dns(char *server)
{
	struct in_addr server_in_addr;

	if (inet_pton(AF_INET, server, &server_in_addr) > 0) {
		_res.nscount = 1;
		_res.nsaddr_list[0].sin_addr = server_in_addr;
	}
}

#define OPT_STRING ("A:D")
enum {
	OPT_A = 1 << 0,
	OPT_D_WATCHDOG = 1 << 1,
};

int nslookup_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int nslookup_main(int argc, char **argv)
{
	int r, opt;

	opt = getopt32(argv, OPT_STRING, &str_Atlas);
	if(opt & OPT_D_WATCHDOG )
	{
		int fd = open(WATCHDOGDEV, O_RDWR);
		write(fd, "1", 1);
		close(fd);
	}
	if(opt & OPT_A) 
	{
	}	
	else 	
		str_Atlas = NULL;

	argc -= (optind-1);
	argv += (optind-1);

	/* We allow 1 or 2 arguments.
	 * The first is the name to be looked up and the second is an
	 * optional DNS server with which to do the lookup.
	 * More than 3 arguments is an error to follow the pattern of the
	 * standard nslookup */
	if (!argv[1] || argv[1][0] == '-' || argc > 3)
		bb_show_usage();

	/* initialize DNS structure _res used in printing the default
	 * name server and in the explicit name server option feature. */
	res_init();
	/* rfc2133 says this enables IPv6 lookups */
	/* (but it also says "may be enabled in /etc/resolv.conf") */
	/*_res.options |= RES_USE_INET6;*/

	if (argv[2])
		set_default_dns(argv[2]);

	if (str_Atlas)
	{
        	time_t mytime;
        	mytime = time(NULL);
		printf ("%s %lu ", str_Atlas, mytime);
	}

	server_print();
	r= print_host(argv[1], "Name:");
#ifdef ATLAS
	if (str_Atlas)
		bb_putchar('\n');
#endif
	return r;
}
