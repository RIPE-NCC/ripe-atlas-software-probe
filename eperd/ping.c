/*
ping.c
*/

#include "libbb.h"
#include <event2/event.h>

#include "eperd.h"
#include "eping.h"

#define PING_OPT_STRING ("46c:s:A:O:")

enum 
{
	opt_4 = (1 << 0),
	opt_6 = (1 << 1),
};

struct pingstate
{
	char *atlas;
	char *hostname;
	int pingcount;
	char *out_filename;

	struct evping_host *pingevent;

	unsigned long min;
	unsigned long max;
	unsigned long sum;
	int sentpkts;
	int rcvdpkts;
	int duppkts;
};

static void ping_cb(int result, int bytes,
	struct sockaddr *sa, socklen_t socklen,
	struct sockaddr *loc_sa, socklen_t loc_socklen,
	int seq, int ttl UNUSED_PARAM,
	struct timeval * elapsed, void * arg)
{
	struct pingstate *pingstate;
	unsigned long usecs;
	FILE *fh;
	char namebuf[NI_MAXHOST];
	char loc_namebuf[NI_MAXHOST];

	pingstate= arg;

#if 0
	crondlog(LVL7 "in ping_cb: result %d, bytes %d, seq %d, ttl %d",
		result, bytes, seq, ttl);
#endif

	if (result == PING_ERR_NONE)
	{
		/* Got a ping reply */
		usecs= (elapsed->tv_sec * 1000000 + elapsed->tv_usec);
		if (usecs < pingstate->min)
			pingstate->min= usecs;
		if (usecs > pingstate->max)
			pingstate->max= usecs;
		pingstate->sum += usecs;
		pingstate->sentpkts++;
		pingstate->rcvdpkts++;
	}
	if (result == PING_ERR_TIMEOUT)
	{
		/* No ping reply */
		pingstate->sentpkts++;
	}
	if (result == PING_ERR_DUP)
	{
		/* Got a duplicate ping reply */
		pingstate->duppkts++;
	}
	if (result == PING_ERR_DONE || result == PING_ERR_SENDTO)
	{
		if (pingstate->out_filename)
		{
			fh= fopen(pingstate->out_filename, "a");
			if (!fh)
				crondlog(DIE9 "unable to append to '%s'",
					pingstate->out_filename);
		}
		else
			fh= stdout;

		getnameinfo(sa, socklen, namebuf, sizeof(namebuf),
			NULL, 0, NI_NUMERICHOST);
		loc_namebuf[0]= '\0';
		getnameinfo(loc_sa, loc_socklen, loc_namebuf,
			sizeof(loc_namebuf),
			NULL, 0, NI_NUMERICHOST);

#define DBQ(str) "\"" #str "\""

		fprintf(fh, "RESULT { ");
		if (pingstate->atlas)
		{
			fprintf(fh, DBQ(id) ":" DBQ(%s),
				pingstate->atlas);
		}

		fprintf(fh, "%s" DBQ(time) ":%d, " DBQ(name) ":" DBQ(%s)
			", " DBQ(addr) ":" DBQ(%s)
			", " DBQ(srcaddr) ":" DBQ(%s)
			", " DBQ(mode) ":" DBQ(ICMP%c)
			", " DBQ(size) ":%d"
			", " DBQ(sent) ":%d"
			", " DBQ(rcvd) ":%d"
			", " DBQ(dup) ":%d",
			pingstate->atlas ? ", " : "", (int)time(NULL),
			pingstate->hostname, namebuf, loc_namebuf,
			sa->sa_family == AF_INET6 ? '6' : '4',
			bytes, pingstate->sentpkts, 
			pingstate->rcvdpkts, pingstate->duppkts);
		if (pingstate->rcvdpkts)
		{
			fprintf(fh, ", " DBQ(min) ":%.3f"
				", " DBQ(avg) ":%.3f"
				", " DBQ(max) ":%.3f"
				", " DBQ(ttl) ":%d",
				pingstate->min/1e3,
				pingstate->sum/1e3/pingstate->rcvdpkts, 
				pingstate->max/1e3, 
				ttl);
		}
		if (result == PING_ERR_SENDTO)
		{
			fprintf(fh, ", " DBQ(error) ": " DBQ(sendto failed: %s),
				strerror(seq));
		}
		fprintf(fh, " }\n");
		if (pingstate->out_filename)
			fclose(fh);
	}
}

static void *ping_init(int __attribute((unused)) argc, char *argv[],
	void (*done)(void *state))
{
	static struct evping_base *ping_base;

	int opt;
	unsigned pingcount; /* must be int-sized */
	unsigned size;
	sa_family_t af;
	const char *hostname;
	char *str_Atlas;
	char *out_filename;
	struct pingstate *state;
	struct evping_host *pingevent;

	if (!ping_base)
	{
		ping_base= evping_base_new(EventBase);
		if (!ping_base)
			crondlog(DIE9 "evping_base_new failed");
	}

	/* Parse arguments */
	pingcount= 3;
	size= 0;
	str_Atlas= NULL;
	out_filename= NULL;
	/* exactly one argument needed; -c NUM */
	opt_complementary = "=1:c+:s+";
	opt = getopt32(argv, PING_OPT_STRING, &pingcount, &size,
		&str_Atlas, &out_filename);
	hostname = argv[optind];

	af= AF_UNSPEC;
	if (opt & opt_4)
		af= AF_INET;
	if (opt & opt_6)
		af= AF_INET6;
	pingevent= evping_base_host_add(ping_base, af, hostname);
	if (!pingevent)
	{
		crondlog(LVL9 "evping_base_host_add failed");
		return NULL;
	}
	state= xzalloc(sizeof(*state));
	state->pingevent= pingevent;
	state->pingcount= pingcount;
	state->atlas= str_Atlas ? strdup(str_Atlas) : NULL;
	state->hostname= strdup(hostname);
	state->out_filename= out_filename ? strdup(out_filename) : NULL;

	evping_ping(pingevent, size, ping_cb, state, done);

	return state;
}

static void ping_start(void *state)
{
	struct pingstate *pingstate;

	pingstate= state;

	pingstate->min= ULONG_MAX;
	pingstate->max= 0;
	pingstate->sum= 0;
	pingstate->sentpkts= 0;
	pingstate->rcvdpkts= 0;
	pingstate->duppkts= 0;
	evping_start(pingstate->pingevent, pingstate->pingcount);
}

static int ping_delete(void *state)
{
	struct pingstate *pingstate;

	pingstate= state;

	evping_delete(pingstate->pingevent);
	pingstate->pingevent= NULL;
	free(pingstate->atlas);
	pingstate->atlas= NULL;
	free(pingstate->hostname);
	pingstate->hostname= NULL;
	free(pingstate->out_filename);
	pingstate->out_filename= NULL;

	free(pingstate);

	return 1;
}

struct testops ping_ops = { ping_init, ping_start, ping_delete };

