/*
 * Copyright (c) 2013 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * Standalone version of the event-based traceroute. 
 */
//config:config EVTRACEROUTE
//config:       bool "evtraceroute"
//config:       default n
//config:       help
//config:               standalone version of event-driven traceroute

//applet:IF_EVTRACEROUTE(APPLET(evtraceroute, BB_DIR_ROOT, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_EVTRACEROUTE) += evtraceroute.o

//usage:#define evtraceroute_trivial_usage
//usage:       "-[46FIrTU] [-a <paris mod>] [-b <paris base>] [-c <count>]"
//usage:       "\n\t[-f <hop>] [-g <gap>] [-i <interface>] [-m <maxhops>] "
//usage:       "[-p <port>]\n\t[-t <tos>] [-w <ms>] [-z <ms>] [-A <string>] "
//usage:       "[-B <bundle>] [-O <file>]\n\t[-S <size>] [-H <hbh size>] "
//usage:       "[-D <dest. opt. size>] [-R <response in>]\n\t[-W <response out]"
//usage:#define evtraceroute_full_usage "\n"
//usage:     "\n       -4                      Use IPv4 (default)"
//usage:     "\n       -6                      Use IPv6"
//usage:     "\n       -F                      Don't fragment"
//usage:     "\n       -I                      Use ICMP"
//usage:     "\n       -r                      Name resolution during each run"
//usage:     "\n       -T                      Use TCP"
//usage:     "\n       -U                      Use UDP (default)"
//usage:     "\n       -a <paris modulus>      Enables Paris-traceroute"
//usage:     "\n       -b <paris base>	       Base for Paris ID"
//usage:     "\n       -c <count>              #packets per hop"
//usage:     "\n       -f <hop>                Starting hop"
//usage:     "\n       -g <gap>                Gap limit"
//usage:     "\n       -i <interface>          Use this interface"
//usage:     "\n       -m <hop>                Max hops"
//usage:     "\n       -p <port>               Destination port"
//usage:     "\n       -t <tos>                TOS field"
//usage:     "\n       -w <timeout>            No reply timeout (ms)"
//usage:     "\n       -z <timeout>            Dup timeout (ms)"
//usage:     "\n       -A <string>             Atlas measurement ID"
//usage:     "\n       -B <string>             Atlas bundle ID"
//usage:     "\n       -O <file>               Name of output file"
//usage:     "\n       -S <size>               Size of packet"
//usage:     "\n       -H <size>               Add IPv6 Hop-by-hop Option this size"
//usage:     "\n       -D <size>               Add IPv6 Destination Option this size"
//usage:     "\n       -R <file>               Response in file"
//usage:     "\n       -W <file>               Response out file"

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

int evtraceroute_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int evtraceroute_main(int argc UNUSED_PARAM, char **argv)
{
	int r;
	void *state;

	/* Create libevent event base */
	EventBase= event_base_new();
	if (!EventBase)
	{
		fprintf(stderr, "evtraceroute: event_base_new failed\n");
		exit(1);
	}
	DnsBase= evdns_base_new(EventBase, 1 /*initialize*/);
	if (!DnsBase)
	{
		fprintf(stderr, "evdns_base_new failed\n");
		exit(1);
	}

	state= traceroute_ops.init(argc, argv, done);
	if (!state)
	{
		fprintf(stderr, "evtraceroute: traceroute_ops.init failed\n");
		exit(1);
	}
	traceroute_ops.start(state);

	r= event_base_loop(EventBase, 0);
	if (r != 0)
	{
		fprintf(stderr, "evtraceroute: event_base_loop failed\n");
		exit(1);
	}
	return 0; /* not reached */
}

