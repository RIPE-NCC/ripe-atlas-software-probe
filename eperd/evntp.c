/*
 * Copyright (c) 2013-2014 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * Standalone version of the event-based ntp. 
 */
//config:config EVNTP
//config:       bool "evntp"
//config:       default n
//config:       help
//config:               standalone version of event-driven ntp

//applet:IF_EVNTP(APPLET(evntp, BB_DIR_BIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_EVNTP) += evntp.o

//usage:#define evntp_trivial_usage
//usage:	"-[46] [-c <count>] [-i <interface>] [-w <timeout>]"
//usage:	"\n\t[-A <Atlas ID>] [-B <bundle ID>] [-O <output file>]"
//usage:	"\n\t[-R <response in>] [-W <response out>] [-s <size>] "
//usage:	"<target>\n"
//usage:#define evntp_full_usage
//usage:       "\nOptions:"
//usage:       "\n     -4              IPv4"
//usage:       "\n     -6              IPv6"
//usage:       "\n     -c <count>      Number of packets"
//usage:       "\n     -i <interface>  Outgoing interface"
//usage:       "\n     -w <timeout>    Time to wait for reply"
//usage:       "\n     -A <id>         Atlas measurement ID"
//usage:       "\n     -B <id>         bundle ID"
//usage:       "\n     -O <out file>   Output file name"
//usage:       "\n     -R <response in> Read response from a file"
//usage:       "\n     -W <response out> Write responses to a file"
//usage:       "\n     -s <size>       Additional size added to request"
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

int evntp_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int evntp_main(int argc UNUSED_PARAM, char **argv)
{
	int r;
	void *state;

	/* Create libevent event base */
	EventBase= event_base_new();
	if (!EventBase)
	{
		fprintf(stderr, "evntp: event_base_new failed\n");
		exit(1);
	}
	DnsBase= evdns_base_new(EventBase, 1 /*initialize*/);
	if (!DnsBase)
	{
		fprintf(stderr, "evdns_base_new failed\n");
		exit(1);
	}

	state= ntp_ops.init(argc, argv, done);
	if (!state)
	{
		fprintf(stderr, "evntp: ntp_ops.init failed\n");
		exit(1);
	}
	ntp_ops.start(state);

	r= event_base_loop(EventBase, 0);
	if (r != 0)
	{
		fprintf(stderr, "evntp: event_base_loop failed\n");
		exit(1);
	}
	return 0; /* not reached */
}

