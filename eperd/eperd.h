/*
 * Copyright (c) 2013-2014 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * eperd.h
 */

typedef struct CronLine CronLine;

struct globals {
	unsigned LogLevel; /* = 8; */
	const char *LogFile;
	const char *CDir; /* = CRONTABS; */
	CronLine *LineBase;
	CronLine *oldLine;
	unsigned instance_id;
	struct event_base *EventBase;
	struct evdns_base *DnsBase;
};
extern struct globals G;
#define LogLevel           (G.LogLevel               )
#define LogFile            (G.LogFile                )
#define CDir               (G.CDir                   )
#define LineBase           (G.LineBase               )
#define FileBase           (G.FileBase               )
#define oldLine            (G.oldLine                )
#define instance_id        (G.instance_id                )
#define EventBase          (G.EventBase              )
#define DnsBase            (G.DnsBase                )

#define TRT_ICMP4_INSTANCE_ID_SHIFT	    12
#define TRT_ICMP4_INSTANCE_ID_MASK	0xf000

#define LVL5  "\x05"
#define LVL7  "\x07"
#define LVL8  "\x08"
#define LVL9  "\x09"
#define WARN9 "\x49"
#define DIE9  "\xc9"
/* level >= 20 is "error" */
#define ERR20 "\x14"

struct testops
{
	void *(*init)(int argc, char *argv[], void (*done)(void *teststate));
	void (*start)(void *teststate);
	int (*delete)(void *teststate);
};

extern struct testops condmv_ops;
extern struct testops httpget_ops;
extern struct testops ntp_ops;
extern struct testops ping_ops;
extern struct testops sslgetcert_ops;
extern struct testops tdig_ops;
extern struct testops traceroute_ops;

void crondlog(const char *ctl, ...);
int get_atlas_fw_version(void);

#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW 4
#endif
