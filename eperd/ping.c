/*
ping.c
*/

#include "libbb.h"
#include <event2/event.h>

#include "eperd.h"
#include "evping.h"

#define PING_OPT_STRING ("qvc:s:w:W:I:A:O:4D6")

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
	int seq, int ttl, struct timeval * elapsed, void * arg)
{
	struct pingstate *pingstate;
	unsigned long usecs;
	FILE *fh;
	char namebuf[NI_MAXHOST];

	pingstate= arg;

	crondlog(LVL7 "in ping_cb: result %d, bytes %d, seq %d, ttl %d",
		result, bytes, seq, ttl);

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
	if (result == PING_ERR_DONE)
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

		fprintf(fh, "%s %d %s %s %d %d %d %d",
			pingstate->atlas, (int)time(NULL),
			pingstate->hostname, namebuf, bytes,
			pingstate->sentpkts, 
			pingstate->rcvdpkts, pingstate->duppkts);
		if (pingstate->rcvdpkts)
		{
			fprintf(fh, " %.3f %.3f %.3f", pingstate->min/1e3,
				pingstate->sum/1e3/pingstate->sentpkts, 
				pingstate->max/1e3);
		}
		fprintf(fh, "\n");
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
	unsigned deadline;
	unsigned timeout;
	char *str_I;
	char *str_Atlas;
	const char *hostname;
	char *str_s;
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
	out_filename= NULL;
	/* exactly one argument needed; -v and -q don't mix; -c NUM, -w NUM, -W NUM */
	opt_complementary = "=1:q--v:v--q:c+:w+:W+";
	opt = getopt32(argv, PING_OPT_STRING, &pingcount, &str_s, &deadline,
		&timeout, &str_I, &str_Atlas, &out_filename);
	hostname = argv[optind];

	pingevent= evping_base_host_add(ping_base, hostname);
	if (!pingevent)
	{
		crondlog(LVL9 "evping_base_host_add failed");
		return NULL;
	}
	state= xzalloc(sizeof(*state));
	state->pingevent= pingevent;
	state->pingcount= pingcount;
	state->atlas= strdup(str_Atlas);
	state->hostname= strdup(hostname);
	state->out_filename= out_filename ? strdup(out_filename) : NULL;

	evping_ping(pingevent, ping_cb, state);

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

