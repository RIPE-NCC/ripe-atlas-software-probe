/* 
 * Copyright (c) 2013 RIPE NCC <atlas@ripe.net>
 * Licensed under the GPL v2 or later, see the file LICENSE in this tarball.
 * Standalone version of the event-based httpget. 
 */
//config:config EVHTTPGET
//config:       bool "evhttpget"
//config:       default n
//config:       help
//config:               standalone version of event-driven httpget

//config:config FEATURE_EVHTTPGET_HTTPS
//config:       bool "Enable https support"
//config:       default n
//config:       depends on EVHTTPGET
//config:       help
//config:        Enable https:// support for httpget

//applet:IF_EVHTTPGET(APPLET(evhttpget, BB_DIR_BIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_EVHTTPGET) += evhttpget.o

//usage:#define evhttpget_trivial_usage
//usage:       "[-ac0146] [--all [--combine]] [--get|--head|--post] [--post-file <file>] [--post-header <file>] [--post-footer <file>] [--store-headers <bytes>] [--user-agent <string>] [-A <atlas id>] [-O <file>]"
//usage:#define evhttpget_full_usage "\n\n"
//usage:     "\nOptions:"
//usage:     "\n       -a --all                Report on all addresses"
//usage:     "\n       -c --combine            Combine the reports for all address in one JSON"
//usage:     "\n       --get                   GET method"
//usage:     "\n       --head                  HEAD method"
//usage:     "\n       --post                  POST mehod"
//usage:     "\n       --post-file <filename>  File to post"
//usage:     "\n       --post-header <fn>      File to post (comes first)"
//usage:     "\n       --post-footer <fn>      File to post (comes last)"
//usage:     "\n       --store-headers <bytes> Number of bytes of the header to store"
//usage:     "\n       --user-agent <string>   User agent header"
//usage:     "\n       -0                      HTTP/1.0"
//usage:     "\n       -1                      HTTP/1.1"
//usage:     "\n       -A <atlas id>           Atlas ID"
//usage:     "\n       -O <filename>           Output file"
//usage:     "\n       -4                      Only IPv4 addresses"
//usage:     "\n       -6                      Only IPv6 addresses"

#include "libbb.h"
#include <syslog.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/dns.h>

#include "eperd.h"

static void done(void *state UNUSED_PARAM, int error)
{
	exit(error);
}

int evhttpget_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int evhttpget_main(int argc UNUSED_PARAM, char **argv)
{
	int r;
	void *state;

	/* Create libevent event base */
	EventBase= event_base_new();
	if (!EventBase)
	{
		fprintf(stderr, "evhttpget_base_new failed\n");
		exit(1);
	}
	DnsBase= evdns_base_new(EventBase, 1 /*initialize*/);
	if (!DnsBase)
	{
		fprintf(stderr, "evdns_base_new failed\n");
		exit(1);
	}

	state= httpget_ops.init(argc, argv, done);
	if (!state)
	{
		fprintf(stderr, "evhttpget: httpget_ops.init failed\n");
		exit(1);
	}
	httpget_ops.start(state);

	r= event_base_loop(EventBase, 0);
	if (r != 0)
	{
		fprintf(stderr, "evhttpget: event_base_loop failed\n");
		exit(1);
	}
	return 0; /* not reached */
}

