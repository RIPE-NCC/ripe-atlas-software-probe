/*
 * Copyright (c) 2013 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * Standalone version of the event-based ping. 
 */
//config:config EVPING
//config:       bool "evping"
//config:       default n
//config:       help
//config:               standalone version of event-driven ping

//applet:IF_EVPING(APPLET(evping, BB_DIR_ROOT, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_EVPING) += evping.o

//usage:#define evping_trivial_usage
//usage:	"-[46ep] [-c <count>] [-s <size>] [-A <Atlas ID>] "
//usage:	"[-B <bundle ID>\n\t[-O <output file>] [-i <interval>] "
//usage:	"[-I <interface>] [-R <response in>]\n\t[-W <response out>] "
//usage:	"<target>"
//usage:#define evping_full_usage "\n\n"
//usage:       "\nOptions:"
//usage:       "\n     -4              IPv4"
//usage:       "\n     -6              IPv6"
//usage:       "\n     -e              use the libc stub resolver"
//usage:       "\n     -r              use the libevent resolver (default)"
//usage:       "\n     -c <count>      Number of packets"
//usage:       "\n     -s <size>       Size"
//usage:       "\n     -A <id>         Atlas measurement ID"
//usage:       "\n     -B <id>         bundle ID"
//usage:       "\n     -O <out file>   Output file name"
//usage:       "\n     -i <interval>   Inter packet interval"
//usage:       "\n     -I <interface>  Outgoing interface"
//usage:       "\n     -R <response in> Read response from a file"
//usage:       "\n     -W <response out> Write responses to a file"
//usage:       "\n"

#include "libbb.h"
#include <syslog.h>
#include <event2/dns.h>
#include <event2/event.h>
#include <event2/event_struct.h>

#include "eperd.h"

static void done(void *state UNUSED_PARAM, int error)
{
	exit(error);
}

int evping_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int evping_main(int argc UNUSED_PARAM, char **argv)
{
	int r;
	void *state;

	INIT_G();

	/* Create libevent event base */
	EventBase= event_base_new();
	if (!EventBase)
	{
		fprintf(stderr, "evping_base_new failed\n");
		exit(1);
	}
	DnsBase= evdns_base_new(EventBase, 1 /*initialize*/);
	if (!DnsBase)
	{
		fprintf(stderr, "evdns_base_new failed\n");
		exit(1);
	}

	state= ping_ops.init(argc, argv, done);
	if (!state)
	{
		fprintf(stderr, "evping_ops.init failed\n");
		exit(1);
	}
	ping_ops.start(state);

	r= event_base_loop(EventBase, 0);
	if (r != 0)
	{
		fprintf(stderr, "evping_base_loop failed\n");
		exit(1);
	}
	return 0; /* not reached */
}

