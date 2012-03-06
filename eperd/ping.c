/*
ping.c
*/

#include "libbb.h"
#include <event2/event.h>

#include "eperd.h"
#include "eping.h"

#define DBQ(str) "\"" #str "\""

#define PING_OPT_STRING ("46c:s:A:O:")

enum 
{
	opt_4 = (1 << 0),
	opt_6 = (1 << 1),
};

struct pingstate
{
	/* Parameters */
	char *atlas;
	char *hostname;
	int pingcount;
	char *out_filename;

	/* State */
	struct sockaddr_in6 sin6;
	socklen_t socklen;
	struct sockaddr_in6 loc_sin6;
	socklen_t loc_socklen;
	int busy;
	char got_reply;
	char first;
	unsigned char ttl;
	unsigned size;

	struct evping_host *pingevent;

	char *result;
	size_t reslen;
	size_t resmax;
};

static void add_str(struct pingstate *state, const char *str)
{
	size_t len;

	len= strlen(str);
	if (state->reslen + len+1 > state->resmax)
	{
		state->resmax= state->reslen + len+1 + 80;
		state->result= xrealloc(state->result, state->resmax);
	}
	memcpy(state->result+state->reslen, str, len+1);
	state->reslen += len;
	//printf("add_str: result = '%s'\n", state->result);
}

static void report(struct pingstate *state)
{
	FILE *fh;
	char namebuf[NI_MAXHOST];

	if (state->out_filename)
	{
		fh= fopen(state->out_filename, "a");
		if (!fh)
			crondlog(DIE9 "unable to append to '%s'",
				state->out_filename);
	}
	else
		fh= stdout;

	fprintf(fh, "RESULT { ");
	if (state->atlas)
	{
		fprintf(fh, DBQ(id) ":" DBQ(%s)
			", " DBQ(fw) ":%d"
			", " DBQ(time) ":%ld, ",
			state->atlas, get_atlas_fw_version(),
			(long)time(NULL));
	}

	getnameinfo((struct sockaddr *)&state->sin6, state->socklen,
		namebuf, sizeof(namebuf), NULL, 0, NI_NUMERICHOST);

	fprintf(fh, "\"name\":\"%s\", \"addr\":\"%s\"",
		state->hostname, namebuf);

	if (state->got_reply)
	{
		namebuf[0]= '\0';
		getnameinfo((struct sockaddr *)&state->loc_sin6,
			state->loc_socklen, namebuf, sizeof(namebuf),
			NULL, 0, NI_NUMERICHOST);

		fprintf(fh, ", \"srcaddr\":\"%s\"", namebuf);
	}

	fprintf(fh, ", \"mode\":\"ICMP%c\"",
		state->sin6.sin6_family == AF_INET6 ? '6' : '4');

	if (state->got_reply)
		fprintf(fh, ", " DBQ(ttl) ":%d", state->ttl);

	fprintf(fh, ", " DBQ(size) ":%d", state->size);

	fprintf(fh, ", \"result\": [ %s ] }\n", state->result);
	free(state->result);
	state->result= NULL;
	state->busy= 0;

	if (state->out_filename)
		fclose(fh);

#if 0
	if (state->base->done)
		state->base->done(state);
#endif
}

static void ping_cb(int result, int bytes,
	struct sockaddr *sa, socklen_t socklen,
	struct sockaddr *loc_sa, socklen_t loc_socklen,
	int seq, int ttl,
	struct timeval * elapsed, void * arg)
{
	struct pingstate *pingstate;
	unsigned long usecs;
	char namebuf[NI_MAXHOST];
	char line[256];

	pingstate= arg;

#if 0
	crondlog(LVL7 "in ping_cb: result %d, bytes %d, seq %d, ttl %d",
		result, bytes, seq, ttl);
#endif

	if (pingstate->first)
	{
		memcpy(&pingstate->sin6, sa, socklen);
		pingstate->socklen= socklen;

		pingstate->size= bytes;
		pingstate->ttl= ttl;
	}

	if (result == PING_ERR_NONE || result == PING_ERR_DUP)
	{
		/* Got a ping reply */
		usecs= (elapsed->tv_sec * 1000000 + elapsed->tv_usec);

		snprintf(line, sizeof(line),
			"%s{ ", pingstate->first ? "" : ", ");
		add_str(pingstate, line);
		pingstate->first= 0;
		if (result == PING_ERR_DUP)
		{
			add_str(pingstate, DBQ(dup) ":1, ");
		}

		snprintf(line, sizeof(line),
			DBQ(rtt) ":%f",
			usecs/1000.);
		add_str(pingstate, line);

		if (!pingstate->got_reply)
		{
			memcpy(&pingstate->loc_sin6, loc_sa, loc_socklen);
			pingstate->loc_socklen= loc_socklen;
				
			pingstate->got_reply= 1;
		}

		if (pingstate->size != bytes)
		{
			snprintf(line, sizeof(line),
				", " DBQ(size) ":%d", bytes);
			add_str(pingstate, line);
			pingstate->size= bytes;
		}
		if (pingstate->ttl != ttl)
		{
			snprintf(line, sizeof(line),
				", " DBQ(ttl) ":%d", ttl);
			add_str(pingstate, line);
			pingstate->ttl= ttl;
		}
		if (memcmp(&pingstate->loc_sin6, loc_sa, loc_socklen) != 0)
		{
			namebuf[0]= '\0';
			getnameinfo(loc_sa, loc_socklen, namebuf,
				sizeof(namebuf), NULL, 0, NI_NUMERICHOST);

			snprintf(line, sizeof(line),
				", " DBQ(srcaddr) ":" DBQ(%s), namebuf);
			add_str(pingstate, line);
		}

		add_str(pingstate, " }");
	}
	if (result == PING_ERR_TIMEOUT)
	{
		/* No ping reply */

		snprintf(line, sizeof(line),
			"%s{ " DBQ(x) ":" DBQ(*) " }",
			pingstate->first ? "" : ", ");
		add_str(pingstate, line);
		pingstate->first= 0;
	}
	if (result == PING_ERR_SENDTO)
	{
		snprintf(line, sizeof(line),
			"%s{ " DBQ(error) ":" DBQ(sendto failed: %s) " }",
			pingstate->first ? "" : ", ", strerror(seq));
		add_str(pingstate, line);
		pingstate->first= 0;
	}
	if (result == PING_ERR_DONE)
	{
		report(pingstate);
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

	state->result= NULL;
	state->reslen= 0;
	state->resmax= 0;

	evping_ping(pingevent, size, ping_cb, state, done);

	return state;
}

static void ping_start(void *state)
{
	struct pingstate *pingstate;

	pingstate= state;

	if (pingstate->result) free(pingstate->result);
	pingstate->resmax= 80;
	pingstate->result= xmalloc(pingstate->resmax);
	pingstate->reslen= 0;

	pingstate->first= 1;
	pingstate->got_reply= 0;

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

