/*
 * Copyright (c) 2013 RIPE NCC <atlas@ripe.net>
 * Copyright (c) 2009 Rocco Carbone
 * This includes code  Copyright (c) 2009 Rocco Carbone
 * taken from the libevent-based ping.
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * ping.c
 */

#include "libbb.h"
#include <event2/dns.h>
#include <event2/event.h>
#include <event2/event_struct.h>

#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include "eperd.h"

#define SAFE_PREFIX ATLAS_DATA_NEW

/* Don't report psize yet. */
#define DO_PSIZE	0

#define DBQ(str) "\"" #str "\""

#define PING_OPT_STRING ("!46rc:s:A:O:")

enum 
{
	opt_4 = (1 << 0),
	opt_6 = (1 << 1),
	opt_r = (1 << 2),
};

/* Intervals and timeouts (all are in milliseconds unless otherwise specified)
 */
#define DEFAULT_PING_INTERVAL   1000           /* 1 sec - 0 means flood mode */

/* Max IP packet size is 65536 while fixed IP header size is 20;
 * the traditional ping program transmits 56 bytes of data, so the
 * default data size is calculated as to be like the original
 */
#define IPHDR              20
#define MAX_DATA_SIZE      (4096 - IPHDR)

#define ICMP6_HDRSIZE (offsetof(struct icmp6_hdr, icmp6_data16[2]))

/* Error codes */
#define PING_ERR_NONE      0
#define PING_ERR_TIMEOUT   1       /* Communication with the host timed out */
#define PING_ERR_DUP       2	   /* Duplicate packet */
#define PING_ERR_DONE      3	   /* Max number of packets to send has been
				    * reached.
				    */
#define PING_ERR_SENDTO    4       /* Sendto system call failed */
#define PING_ERR_DNS	   5       /* DNS error */
#define PING_ERR_DNS_NO_ADDR 6     /* DNS no suitable addresses */
#define PING_ERR_SHUTDOWN 10       /* The request was canceled because the PING subsystem was shut down */
#define PING_ERR_CANCEL   12       /* The request was canceled via a call to evping_cancel_request */
#define PING_ERR_UNKNOWN  16       /* An unknown error occurred */


/* Definition for various types of counters */
typedef uint64_t counter_t;

/* How to keep track of a PING session */
struct pingbase
{
	struct event_base *event_base;

	evutil_socket_t rawfd4;	       /* Raw socket used to ping hosts (IPv4)
					*/
	evutil_socket_t rawfd6;	       /* Raw socket used to ping hosts (IPv6)
					*/

	pid_t pid;                     /* Identifier to send with each ICMP
					* Request */

	struct timeval tv_interval;    /* Ping interval between two subsequent
					* pings */

	/* A list of hosts to ping. */
	struct pingstate **table;
	int tabsiz;

	struct event event4;            /* Used to detect read events on raw
					 * socket */
	struct event event6;            /* Used to detect read events on raw
					 * socket */
	void (*done)(void *state);	/* Called when a ping is done */

	u_char packet [MAX_DATA_SIZE];
};

struct pingstate
{
	/* Parameters */
	char *atlas;
	char *hostname;
	int pingcount;
	char *out_filename;
	char delay_name_res;

	/* State */
	struct sockaddr_in6 sin6;
	socklen_t socklen;
	struct sockaddr_in6 loc_sin6;
	socklen_t loc_socklen;
	int busy;
	char got_reply;
	char first;
	char no_dst;
	unsigned char ttl;
	unsigned size;
	unsigned psize;

	char *result;
	size_t reslen;
	size_t resmax;

	struct pingbase *base;

	sa_family_t af;			/* Desired address family */
	struct evutil_addrinfo *dns_res;
	struct evutil_addrinfo *dns_curr;

	size_t maxsize;

	int maxpkts;			/* Number of packets to send */

	int index;                     /* Index into the array of hosts */
	u_int8_t seq;                  /* ICMP sequence (modulo 256) for next
					* run
					*/
	u_int8_t rcvd_ttl;		/* TTL in (last) reply packet */
	char dnsip;
	char send_error;

	struct event ping_timer;       /* Timer to ping host at given
					* intervals
					*/

	/* Packets Counters */
	size_t cursize;
	counter_t sentpkts;            /* Total # of ICMP Echo Requests sent */
};

/* User Data added to the ICMP header
 *
 * The 'ts' is the time the request is sent on the wire
 * and it is used to compute the network round-trip value.
 *
 * The 'index' parameter is an index value in the array of hosts to ping
 * and it is used to relate each response with the corresponding request
 */
struct evdata {
	struct timeval ts;
	uint32_t index;
};



/* Initialize a struct timeval by converting milliseconds */
static void
msecstotv(time_t msecs, struct timeval *tv)
{
	tv->tv_sec  = msecs / 1000;
	tv->tv_usec = msecs % 1000 * 1000;
}

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

static int get_timesync(void)
{
	FILE *fh;
	int lastsync;

	fh= fopen(ATLAS_TIMESYNC_FILE, "r");
	if (!fh)
		return -1;
	fscanf(fh, "%d", &lastsync);
	fclose(fh);
	return time(NULL)-lastsync;
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
			", " DBQ(lts) ":%d"
			", " DBQ(time) ":%ld, ",
			state->atlas, get_atlas_fw_version(), get_timesync(),
			(long)time(NULL));
	}

	fprintf(fh, DBQ(dst_name) ":" DBQ(%s),
		state->hostname);

	if (!state->no_dst)
	{
		getnameinfo((struct sockaddr *)&state->sin6, state->socklen,
			namebuf, sizeof(namebuf), NULL, 0, NI_NUMERICHOST);

		fprintf(fh, ", " DBQ(dst_addr) ":" DBQ(%s) ", " DBQ(af) ":%d",
			namebuf, state->sin6.sin6_family == AF_INET6 ? 6 : 4);
	}

	if (state->got_reply)
	{
		namebuf[0]= '\0';
		getnameinfo((struct sockaddr *)&state->loc_sin6,
			state->loc_socklen, namebuf, sizeof(namebuf),
			NULL, 0, NI_NUMERICHOST);

		fprintf(fh, ", \"src_addr\":\"%s\"", namebuf);
	}

	fprintf(fh, ", " DBQ(proto) ":" DBQ(ICMP));

	if (state->got_reply)
		fprintf(fh, ", " DBQ(ttl) ":%d", state->ttl);

	fprintf(fh, ", " DBQ(size) ":%d", state->size);
#if DO_PSIZE
	if (state->psize != -1)
		fprintf(fh, ", " DBQ(psize) ":%d", state->psize);
#endif /* DO_PSIZE */

	fprintf(fh, ", \"result\": [ %s ] }\n", state->result);
	free(state->result);
	state->result= NULL;

	state->busy= 0;

	if (state->out_filename)
		fclose(fh);
}

static void ping_cb(int result, int bytes, int psize,
	struct sockaddr *sa, socklen_t socklen,
	struct sockaddr *loc_sa, socklen_t loc_socklen,
	int seq, int ttl,
	struct timeval * elapsed, void * arg)
{
	struct pingstate *pingstate;
	unsigned long usecs;
	char namebuf1[NI_MAXHOST], namebuf2[NI_MAXHOST];
	char line[256];

	(void)socklen;	/* Suppress GCC unused parameter warning */

	pingstate= arg;

#if 0
	crondlog(LVL7 "in ping_cb: result %d, bytes %d, seq %d, ttl %d",
		result, bytes, seq, ttl);
#endif
	
	if (!pingstate->busy)
	{
		crondlog(LVL8 "ping_cb: not busy for state %p, '%s'",
			pingstate, pingstate->hostname);
		return;
	}

	if (pingstate->first)
	{
		pingstate->size= bytes;
		pingstate->psize= psize;
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
		pingstate->no_dst= 0;
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
		if (pingstate->psize != psize && psize != -1)
		{
#if DO_PSIZE
			snprintf(line, sizeof(line),
				", " DBQ(psize) ":%d", psize);
			add_str(pingstate, line);
#endif /* DO_PSIZE */
			pingstate->psize= psize;
		}
		if (pingstate->ttl != ttl)
		{
			snprintf(line, sizeof(line),
				", " DBQ(ttl) ":%d", ttl);
			add_str(pingstate, line);
			pingstate->ttl= ttl;
		}
		namebuf1[0]= '\0';
		getnameinfo(&pingstate->loc_sin6, loc_socklen, namebuf1,
			sizeof(namebuf1), NULL, 0, NI_NUMERICHOST);
		namebuf2[0]= '\0';
		getnameinfo(loc_sa, loc_socklen, namebuf2,
			sizeof(namebuf2), NULL, 0, NI_NUMERICHOST);

		if (strcmp(namebuf1, namebuf2) != 0)
		{
			printf("loc_sin6: %s\n", namebuf1);

			printf("loc_sa: %s\n", namebuf2);

			snprintf(line, sizeof(line),
				", " DBQ(srcaddr) ":" DBQ(%s), namebuf2);
			add_str(pingstate, line);
		}

		add_str(pingstate, " }");
	}
	if (result == PING_ERR_TIMEOUT)
	{
		/* No ping reply */

		snprintf(line, sizeof(line),
			"%s{ " DBQ(x) ":" DBQ(*),
			pingstate->first ? "" : ", ");
		add_str(pingstate, line);
		pingstate->no_dst= 0;
	}
	if (result == PING_ERR_SENDTO)
	{
		snprintf(line, sizeof(line),
			"%s{ " DBQ(error) ":" DBQ(sendto failed: %s),
			pingstate->first ? "" : ", ", strerror(seq));
		add_str(pingstate, line);
		pingstate->no_dst= 0;
	}
	if (result == PING_ERR_TIMEOUT || result == PING_ERR_SENDTO)
	{
		if (pingstate->first && pingstate->loc_socklen != 0)
		{
			namebuf1[0]= '\0';
			getnameinfo((struct sockaddr *)&pingstate->loc_sin6,
				pingstate->loc_socklen,
				namebuf1, sizeof(namebuf1),
				NULL, 0, NI_NUMERICHOST);

			snprintf(line, sizeof(line),
				", " DBQ(srcaddr) ":" DBQ(%s), namebuf1);
			add_str(pingstate, line);
		}
		add_str(pingstate, " }");
		pingstate->first= 0;
	}
	if (result == PING_ERR_DNS)
	{
		pingstate->size= bytes;
		pingstate->psize= psize;
		snprintf(line, sizeof(line),
			"%s{ " DBQ(error) ":" DBQ(dns resolution failed: %s) " }",
			pingstate->first ? "" : ", ", (char *)sa);
		add_str(pingstate, line);
		report(pingstate);
	}
	if (result == PING_ERR_DONE)
	{
		report(pingstate);
	}
}

/*
 * Checksum routine for Internet Protocol family headers (C Version).
 * From ping examples in W. Richard Stevens "Unix Network Programming" book.
 */
static int mkcksum(u_short *p, int n)
{
	u_short answer;
	long sum = 0;
	u_short odd_byte = 0;

	while (n > 1)
	  {
	    sum += *p++;
	    n -= 2;
	  }

	/* mop up an odd byte, if necessary */
	if (n == 1)
	  {
	    * (u_char *) &odd_byte = * (u_char *) p;
	    sum += odd_byte;
	  }

	sum = (sum >> 16) + (sum & 0xffff);	/* add high 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;			/* ones-complement, truncate */

	return answer;
}


/*
 * Format an ICMP Echo Request packet to be sent over the wire.
 *
 *  o the IP packet will be added on by the kernel
 *  o the ID field is the Unix process ID
 *  o the sequence number is an ascending integer
 *
 * The first 8 bytes of the data portion are used
 * to hold a Unix "timeval" struct in VAX byte-order,
 * to compute the network round-trip value.
 *
 * The second 8 bytes of the data portion are used
 * to keep an unique integer used as index in the array
 * ho hosts being monitored
 */
static void fmticmp4(u_char *buffer, size_t *sizep, u_int8_t seq,
	uint32_t idx, pid_t pid)
{
	size_t minlen;
	struct icmp *icmp = (struct icmp *) buffer;
	struct evdata *data = (struct evdata *) (buffer + ICMP_MINLEN);

	struct timeval now;

	minlen= sizeof(*data);
	if (*sizep < minlen)
		*sizep= minlen;
	if (*sizep > MAX_DATA_SIZE - ICMP_MINLEN)
		*sizep= MAX_DATA_SIZE - ICMP_MINLEN;

	if (*sizep > minlen)
		memset(buffer+minlen, '\0', *sizep-minlen);

	/* The ICMP header (no checksum here until user data has been filled in) */
	icmp->icmp_type = ICMP_ECHO;             /* type of message */
	icmp->icmp_code = 0;                     /* type sub code */
	icmp->icmp_id   = 0xffff & pid;          /* unique process identifier */
	icmp->icmp_seq  = htons(seq);            /* message identifier */

	/* User data */
	gettimeofday(&now, NULL);
	data->ts    = now;                       /* current time */
	data->index = idx;                     /* index into an array */

	/* Last, compute ICMP checksum */
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = mkcksum((u_short *) icmp, ICMP_MINLEN + *sizep);  /* ones complement checksum of struct */
}


/*
 * Format an ICMPv6 Echo Request packet to be sent over the wire.
 *
 *  o the IP packet will be added on by the kernel
 *  o the ID field is the Unix process ID
 *  o the sequence number is an ascending integer
 *
 * The first 8 bytes of the data portion are used
 * to hold a Unix "timeval" struct in VAX byte-order,
 * to compute the network round-trip value.
 *
 * The second 8 bytes of the data portion are used
 * to keep an unique integer used as index in the array
 * ho hosts being monitored
 */
static void fmticmp6(u_char *buffer, size_t *sizep,
	u_int8_t seq, uint32_t idx, pid_t pid)
{
	size_t minlen;
	struct icmp6_hdr *icmp = (struct icmp6_hdr *) buffer;
	struct evdata *data = (struct evdata *) (buffer + ICMP6_HDRSIZE);

	struct timeval now;

	minlen= sizeof(*data);
	if (*sizep < minlen)
		*sizep= minlen;
	if (*sizep > MAX_DATA_SIZE - ICMP6_HDRSIZE)
		*sizep= MAX_DATA_SIZE - ICMP6_HDRSIZE;

	if (*sizep > minlen)
		memset(buffer+minlen, '\0', *sizep-minlen);

	/* The ICMP header (no checksum here until user data has been filled in) */
	icmp->icmp6_type = ICMP6_ECHO_REQUEST;   /* type of message */
	icmp->icmp6_code = 0;                    /* type sub code */
	icmp->icmp6_id   = 0xffff & pid;         /* unique process identifier */
	icmp->icmp6_seq  = htons(seq);           /* message identifier */

	/* User data */
	gettimeofday(&now, NULL);
	data->ts    = now;                       /* current time */
	data->index = idx;                     /* index into an array */

	icmp->icmp6_cksum = 0;
}


/* Attempt to transmit an ICMP Echo Request to a given host */
static void ping_xmit(struct pingstate *host)
{
	struct pingbase *base = host->base;

	int nsent, fd4, fd6, t_errno, r;

	host->send_error= 0;
	host->got_reply= 0;
	if (host->sentpkts >= host->maxpkts)
	{
		/* Done. */
		ping_cb(PING_ERR_DONE, host->cursize, host->psize,
			(struct sockaddr *)&host->sin6, host->socklen,
			(struct sockaddr *)&host->loc_sin6, host->loc_socklen,
			0, host->rcvd_ttl, NULL,
			host);
		if (host->dns_res)
		{
			evutil_freeaddrinfo(host->dns_res);
			host->dns_res= NULL;
		}
		if (host->base->done)
			host->base->done(host);

		return;
	}

	/* Transmit the request over the network */
	if (host->sin6.sin6_family == AF_INET6)
	{
		/* Format the ICMP Echo Reply packet to send */
		fmticmp6(base->packet, &host->cursize, host->seq, host->index,
			base->pid);

		fd6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
		if (fd6 != -1)
		{
			r= connect(fd6, (struct sockaddr *)&host->sin6,
	                        host->socklen);
			if (r == 0)
			{
				host->loc_socklen= 
					sizeof(host->loc_sin6);
				getsockname(fd6, &host->loc_sin6,
					&host->loc_socklen);
			}
		}

		nsent = sendto(fd6, base->packet, host->cursize+ICMP6_HDRSIZE,
			MSG_DONTWAIT, (struct sockaddr *)&host->sin6,
			host->socklen);

		t_errno= errno;
		close(fd6);
		errno= t_errno;
	}
	else
	{
		/* Format the ICMP Echo Reply packet to send */
		fmticmp4(base->packet, &host->cursize, host->seq, host->index,
			base->pid);

		fd4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		if (fd4 != -1)
		{
			r= connect(fd4, (struct sockaddr *)&host->sin6,
	                        host->socklen);
			if (r == 0)
			{
				host->loc_socklen= 
					sizeof(host->loc_sin6);
				getsockname(fd4, &host->loc_sin6,
					&host->loc_socklen);
			}
		}


		nsent = sendto(fd4, base->packet, host->cursize+ICMP_MINLEN,
			MSG_DONTWAIT, (struct sockaddr *)&host->sin6,
			host->socklen);

		t_errno= errno;
		close(fd4);
		errno= t_errno;
	}

	if (nsent > 0)
	  {
	    /* Update timestamps and counters */
	    host->sentpkts++;

	  }
	else
	{
	  host->sentpkts++;
	  host->send_error= 1;

	  /* Report the failure and stop */
	  ping_cb(PING_ERR_SENDTO, host->cursize, -1,
			(struct sockaddr *)&host->sin6, host->socklen,
			(struct sockaddr *)&host->loc_sin6, host->loc_socklen,
			errno, 0, NULL,
			host);
	}


	/* Add the timer to handle no reply condition in the given timeout */
	evtimer_add(&host->ping_timer, &host->base->tv_interval);
}


/* The callback to handle timeouts due to destination host unreachable condition */
static void noreply_callback(int __attribute((unused)) unused, const short __attribute((unused)) event, void *h)
{
	struct pingstate *host = h;

	if (!host->got_reply && !host->send_error)
	{
		ping_cb(PING_ERR_TIMEOUT, host->cursize, -1,
			(struct sockaddr *)&host->sin6, host->socklen,
			NULL, 0,
			host->seq, -1, &host->base->tv_interval,
			host);

		/* Update the sequence number for the next run */
		host->seq = (host->seq + 1) % 256;
	}

	ping_xmit(host);
}

/*
 * Called by libevent when the kernel says that the raw socket is ready for reading.
 *
 * It reads a packet from the wire and attempt to decode and relate ICMP Echo Request/Reply.
 *
 * To be legal the packet received must be:
 *  o of enough size (> IPHDR + ICMP_MINLEN)
 *  o of ICMP Protocol
 *  o of type ICMP_ECHOREPLY
 *  o the one we are looking for (matching the same identifier of all the packets the program is able to send)
 */
static void ready_callback4 (int __attribute((unused)) unused,
	const short __attribute((unused)) event, void * arg)
{
	struct pingbase *base = arg;

	int nrecv, isDup;
	struct sockaddr_in remote;                  /* responding internet address */
	socklen_t slen = sizeof(struct sockaddr);
	struct sockaddr_in *sin4p;
	struct sockaddr_in loc_sin4;

	/* Pointer to relevant portions of the packet (IP, ICMP and user data) */
	struct ip * ip = (struct ip *) base->packet;
	struct icmphdr * icmp;
	struct evdata * data = (struct evdata *) (base->packet + IPHDR + ICMP_MINLEN);
	int hlen = 0;

	struct timeval now;
	struct pingstate * host;

	/* Time the packet has been received */
	gettimeofday(&now, NULL);

// printf("ready_callback4: before recvfrom\n");
	/* Receive data from the network */
	nrecv = recvfrom(base->rawfd4, base->packet, sizeof(base->packet), MSG_DONTWAIT, (struct sockaddr *) &remote, &slen);
	if (nrecv < 0)
	  {
	    goto done;
	  }

#if 0
		{ int i;
			printf("received:");
			for (i= 0; i<nrecv; i++)
				printf(" %02x", base->packet[i]);
			printf("\n");
		}
#endif

	/* Calculate the IP header length */
	hlen = ip->ip_hl * 4;

	/* Check the IP header */
	if (nrecv < hlen + ICMP_MINLEN || ip->ip_hl < 5)
	  {
	    /* One more too short packet */
printf("ready_callback4: too short\n");
	    goto done;
	  }

	/* The ICMP portion */
	icmp = (struct icmphdr *) (base->packet + hlen);

	/* Check the ICMP header to drop unexpected packets due to unrecognized id */
	if (icmp->un.echo.id != base->pid)
	  {
#if 0
		printf("ready_callback4: bad pid: got %d, expect %d\n",
			icmp->un.echo.id, base->pid);
#endif
	    goto done;
	  }

	/* Check the ICMP payload for legal values of the 'index' portion */
	if (data->index >= base->tabsiz || base->table[data->index] == NULL)
	  {
	    goto done;
	  }

	/* Get the pointer to the host descriptor in our internal table */
	host= base->table[data->index];

	/* Check for Destination Host Unreachable */
	if (icmp->type == ICMP_ECHO)
	{
		/* Completely ignore ECHO requests */
	}
	else if (icmp->type == ICMP_ECHOREPLY)
	  {
	    /* Use the User Data to relate Echo Request/Reply and evaluate the Round Trip Time */
	    struct timeval elapsed;             /* response time */

	    /* Compute time difference to calculate the round trip */
	    evutil_timersub (&now, &data->ts, &elapsed);

	    /* Set destination address of packet as local address */
	    sin4p= &loc_sin4;
	    memset(sin4p, '\0', sizeof(*sin4p));
	    sin4p->sin_family= AF_INET;
	    sin4p->sin_addr= ip->ip_dst;
	    host->rcvd_ttl= ip->ip_ttl;

	    /* Report everything with the wrong sequence number as a dup. 
	     * This is not quite right, it could be a late packet. Do we
	     * care?
	     */
	    isDup= (ntohs(icmp->un.echo.sequence) != host->seq);
	    ping_cb(isDup ? PING_ERR_DUP : PING_ERR_NONE,
		    nrecv - IPHDR - ICMP_MINLEN, nrecv,
		    (struct sockaddr *)&host->sin6, host->socklen,
		    (struct sockaddr *)&loc_sin4, sizeof(loc_sin4),
		    ntohs(icmp->un.echo.sequence), ip->ip_ttl, &elapsed,
		    host);

	    /* Update the sequence number for the next run */
	    host->seq = (host->seq + 1) % 256;

            if (!isDup)
		host->got_reply= 1;
	  }
	else
	{
printf("ready_callback4: not an echo reply\n");
	  /* Handle this condition exactly as the request has expired */
	  noreply_callback (-1, -1, host);
	}

done:
	;
}

/*
 * Called by libevent when the kernel says that the raw socket is ready for reading.
 *
 * It reads a packet from the wire and attempt to decode and relate ICMP Echo Request/Reply.
 *
 * To be legal the packet received must be:
 *  o of enough size (> IPHDR + ICMP_MINLEN)
 *  o of ICMP Protocol
 *  o of type ICMP_ECHOREPLY
 *  o the one we are looking for (matching the same identifier of all the packets the program is able to send)
 */
static void ready_callback6 (int __attribute((unused)) unused,
	const short __attribute((unused)) event, void * arg)
{
	struct pingbase *base = arg;

	int nrecv, isDup;
	struct sockaddr_in remote;                  /* responding internet address */

	/* Pointer to relevant portions of the packet (IP, ICMP and user data) */
	struct icmp6_hdr * icmp = (struct icmp6_hdr *) base->packet;
	struct evdata * data = (struct evdata *) (base->packet +
		offsetof(struct icmp6_hdr, icmp6_data16[2]));

	struct timeval now;
	struct pingstate * host;
	struct cmsghdr *cmsgptr;
	struct sockaddr_in6 *sin6p;
	struct msghdr msg;
	struct sockaddr_in6 loc_sin6;
	struct iovec iov[1];
	char cmsgbuf[256];

	/* Time the packet has been received */
	gettimeofday(&now, NULL);

	iov[0].iov_base= base->packet;
	iov[0].iov_len= sizeof(base->packet);
	msg.msg_name= &remote;
	msg.msg_namelen= sizeof(remote);
	msg.msg_iov= iov;
	msg.msg_iovlen= 1;
	msg.msg_control= cmsgbuf;
	msg.msg_controllen= sizeof(cmsgbuf);
	msg.msg_flags= 0;			/* Not really needed */

	/* Receive data from the network */
	nrecv= recvmsg(base->rawfd6, &msg, MSG_DONTWAIT);
	if (nrecv < 0)
	  {
	    goto done;
	  }

	/* Check the ICMP header to drop unexpected packets due to
	 * unrecognized id
	 */
	if (icmp->icmp6_id != base->pid)
	  {
	    goto done;
	  }

	/* Check the ICMP payload for legal values of the 'index' portion */
	if (data->index >= base->tabsiz || base->table[data->index] == NULL)
	  {
	    goto done;
	  }

	/* Get the pointer to the host descriptor in our internal table */
	host= base->table[data->index];

	/* Check for Destination Host Unreachable */
	if (icmp->icmp6_type == ICMP6_ECHO_REPLY)
	  {
	    /* Use the User Data to relate Echo Request/Reply and evaluate the Round Trip Time */
	    struct timeval elapsed;             /* response time */

	    /* Compute time difference to calculate the round trip */
	    evutil_timersub (&now, &data->ts, &elapsed);

	    /* Set destination address of packet as local address */
	    memset(&loc_sin6, '\0', sizeof(loc_sin6));
	    for (cmsgptr= CMSG_FIRSTHDR(&msg); cmsgptr; 
		    cmsgptr= CMSG_NXTHDR(&msg, cmsgptr))
	    {
		    if (cmsgptr->cmsg_len == 0)
			    break;	/* Can this happen? */
		    if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
			    cmsgptr->cmsg_type == IPV6_PKTINFO)
		    {
			    sin6p= &loc_sin6;
			    sin6p->sin6_family= AF_INET6;
			    sin6p->sin6_addr= ((struct in6_pktinfo *)
				    CMSG_DATA(cmsgptr))->ipi6_addr;
		    }
		    if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
			    cmsgptr->cmsg_type == IPV6_HOPLIMIT)
		    {
			    host->rcvd_ttl= *(int *)CMSG_DATA(cmsgptr);
		    }
	    }

	    /* Report everything with the wrong sequence number as a dup. 
	     * This is not quite right, it could be a late packet. Do we
	     * care?
	     */
	    isDup= (ntohs(icmp->icmp6_seq) != host->seq);
	    ping_cb(isDup ? PING_ERR_DUP : PING_ERR_NONE,
		    nrecv - ICMP6_HDRSIZE, nrecv + sizeof(struct ip6_hdr),
		    (struct sockaddr *)&host->sin6, host->socklen,
		    (struct sockaddr *)&loc_sin6, sizeof(loc_sin6),
		    ntohs(icmp->icmp6_seq), host->rcvd_ttl, &elapsed,
		    host);

	    /* Update the sequence number for the next run */
	    host->seq = (host->seq + 1) % 256;

	    if (!isDup)
		host->got_reply= 1;
	  }
	else
	  /* Handle this condition exactly as the request has expired */
	  noreply_callback (-1, -1, host);

done:
	;
}


static void *ping_init(int __attribute((unused)) argc, char *argv[],
	void (*done)(void *state))
{
	static struct pingbase *ping_base;

	int i, newsiz, delay_name_res;
	uint32_t opt;
	unsigned pingcount; /* must be int-sized */
	unsigned size;
	sa_family_t af;
	const char *hostname;
	char *str_Atlas;
	char *out_filename;
	struct pingstate *state;
	len_and_sockaddr *lsa;
	FILE *fh;

	if (!ping_base)
	{
		int p_proto, on;
		struct protoent *protop;
		evutil_socket_t fd4, fd6;

		/* Check if the ICMP protocol is available on this system */
		protop = getprotobyname("icmp");
		if (protop)
			p_proto= protop->p_proto;
		else
			p_proto= IPPROTO_ICMP;

		/* Create an endpoint for communication using raw socket for ICMP calls */
		if ((fd4 = socket(AF_INET, SOCK_RAW, p_proto)) == -1) {
		  return NULL;
		}

		/* Check if the ICMP6 protocol is available on this system */
		protop = getprotobyname("icmp6");
		if (protop)
			p_proto= protop->p_proto;
		else
			p_proto= IPPROTO_ICMPV6;

		if ((fd6 = socket(AF_INET6, SOCK_RAW, p_proto)) == -1) {
		  close(fd4);
		  return NULL;
		}

		on = 1;
		setsockopt(fd6, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on,
			sizeof(on));

		on = 1;
		setsockopt(fd6, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on,
			sizeof(on));

		ping_base = malloc(sizeof(*ping_base));
		if (ping_base == NULL)
			return (NULL);
		memset(ping_base, 0, sizeof(*ping_base));

		ping_base->event_base = EventBase;

		ping_base->tabsiz= 10;
		ping_base->table= xzalloc(ping_base->tabsiz *
			sizeof(*ping_base->table));

		ping_base->rawfd4 = fd4;
		ping_base->rawfd6 = fd6;
		evutil_make_socket_nonblocking(ping_base->rawfd4);
		evutil_make_socket_nonblocking(ping_base->rawfd6);

		/* Set default values */
		ping_base->pid = getpid();

		msecstotv(DEFAULT_PING_INTERVAL, &ping_base->tv_interval);

		/* Define the callback to handle ICMP Echo Reply and add the
		 * raw file descriptor to those monitored for read events */
		event_assign(&ping_base->event4, ping_base->event_base,
			ping_base->rawfd4, EV_READ | EV_PERSIST,
			ready_callback4, ping_base);
		event_assign(&ping_base->event6, ping_base->event_base,
			ping_base->rawfd6, EV_READ | EV_PERSIST,
			ready_callback6, ping_base);
		event_add(&ping_base->event4, NULL);
		event_add(&ping_base->event6, NULL);

		ping_base->done= 0;
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

	if (opt == 0xffffffff)
	{
		crondlog(LVL8 "bad options");
		return NULL;
	}

	if (out_filename)
	{
		if (!validate_filename(out_filename, SAFE_PREFIX))
		{
			crondlog(LVL8 "insecure file '%s'", out_filename);
			return NULL;
		}
		fh= fopen(out_filename, "a");
		if (!fh)
		{
			crondlog(LVL8 "unable to append to '%s'",
				out_filename);
			return NULL;
		}
		fclose(fh);
	}

	if (str_Atlas)
	{
		if (!validate_atlas_id(str_Atlas))
		{
			crondlog(LVL8 "bad atlas ID '%s'", str_Atlas);
			return NULL;
		}
	}

	af= AF_UNSPEC;
	if (opt & opt_4)
		af= AF_INET;
	if (opt & opt_6)
		af= AF_INET6;
	delay_name_res= !!(opt & opt_r);

	if (!delay_name_res)
	{
		/* Attempt to resolv 'name' */
		lsa= host_and_af2sockaddr(hostname, 0, af);
		if (!lsa)
			return NULL;

		if (lsa->len > sizeof(state->sin6))
		{
			free(lsa);
			return NULL;
		}
	}

	state= xzalloc(sizeof(*state));

	memset(&state->loc_sin6, '\0', sizeof(state->loc_sin6));
	state->loc_socklen= 0;
	if (!delay_name_res)
	{
		state->socklen= lsa->len;
		memcpy(&state->sin6, &lsa->u.sa, state->socklen);
		free(lsa); lsa= NULL;
	}

	state->base = ping_base;
	state->af= af;
	state->delay_name_res= delay_name_res;

	state->seq = 1;

	/* Define here the callbacks to ping the host and to handle no reply
	 * timeouts
	 */
	evtimer_assign(&state->ping_timer, state->base->event_base,
		noreply_callback, state);

	for (i= 0; i<ping_base->tabsiz; i++)
	{
		if (ping_base->table[i] == NULL)
			break;
	}
	if (i >= ping_base->tabsiz)
	{
		newsiz= 2*ping_base->tabsiz;
		ping_base->table= xrealloc(ping_base->table,
			newsiz*sizeof(*ping_base->table));
		for (i= ping_base->tabsiz; i<newsiz; i++)
			ping_base->table[i]= NULL;
		i= ping_base->tabsiz;
		ping_base->tabsiz= newsiz;
	}
	state->index= i;
	ping_base->table[i]= state;

	state->pingcount= pingcount;
	state->atlas= str_Atlas ? strdup(str_Atlas) : NULL;
	state->hostname= strdup(hostname);
	state->out_filename= out_filename ? strdup(out_filename) : NULL;

	state->result= NULL;
	state->reslen= 0;
	state->resmax= 0;

	state->maxsize = size;
	state->base->done= done;

	return state;
}

static void ping_start2(void *state)
{
	struct pingstate *pingstate;

	pingstate= state;

	pingstate->sentpkts= 0;
	pingstate->cursize= pingstate->maxsize;

	ping_xmit(pingstate);
}

static void dns_cb(int result, struct evutil_addrinfo *res, void *ctx)
{
	int count;
	struct pingstate *env;
	struct evutil_addrinfo *cur;

	env= ctx;

	if (!env->dnsip)
	{
		crondlog(LVL7
			"dns_cb: in dns_cb but not doing dns at this time");
		if (res)
			evutil_freeaddrinfo(res);
		return;
	}

	env->dnsip= 0;

	if (result != 0)
	{
		ping_cb(PING_ERR_DNS, env->maxsize, -1,
			(struct sockaddr *)evutil_gai_strerror(result), 0,
			(struct sockaddr *)NULL, 0,
			0, 0, NULL,
			env);
		ping_cb(PING_ERR_DONE, env->maxsize, -1,
			(struct sockaddr *)NULL, 0,
			(struct sockaddr *)NULL, 0,
			0, 0, NULL,
			env);
		if (env->base->done)
			env->base->done(env);
		return;
	}

	env->dns_res= res;
	env->dns_curr= res;

	count= 0;
	for (cur= res; cur; cur= cur->ai_next)
		count++;

	// env->reportcount(env, count);

	while (env->dns_curr)
	{
		env->socklen= env->dns_curr->ai_addrlen;
		if (env->socklen > sizeof(env->sin6))
			continue;	/* Weird */
		memcpy(&env->sin6, env->dns_curr->ai_addr,
			env->socklen);

		ping_start2(env);

		return;
	}

	/* Something went wrong */
	evutil_freeaddrinfo(env->dns_res);
	env->dns_res= NULL;
	env->dns_curr= NULL;
	ping_cb(PING_ERR_DNS_NO_ADDR, env->cursize, -1,
		(struct sockaddr *)NULL, 0,
		(struct sockaddr *)NULL, 0,
		0, 0, NULL,
		env);
	if (env->base->done)
		env->base->done(env);
}

static void ping_start(void *state)
{
	struct pingstate *pingstate;
	struct evutil_addrinfo hints;

	pingstate= state;

	if (pingstate->busy)
		return;

	if (pingstate->result) free(pingstate->result);
	pingstate->resmax= 80;
	pingstate->result= xmalloc(pingstate->resmax);
	pingstate->reslen= 0;

	pingstate->first= 1;
	pingstate->got_reply= 0;
	pingstate->no_dst= 1;
	pingstate->busy= 1;

	pingstate->maxpkts= pingstate->pingcount;

	if (!pingstate->delay_name_res)
	{
		ping_start2(state);
		return;
	}

	pingstate->dnsip= 1;

	memset(&hints, '\0', sizeof(hints));
	hints.ai_socktype= SOCK_DGRAM;
	hints.ai_family= pingstate->af;
	(void) evdns_getaddrinfo(DnsBase, pingstate->hostname, NULL,
		&hints, dns_cb, pingstate);
}

static int ping_delete(void *state)
{
	struct pingstate *pingstate;
	struct pingbase *base;

	pingstate= state;

	if (pingstate->busy)
	{
		crondlog(LVL8
			"ping_delete: not deleting, busy for state %p, '%s'",
			pingstate, pingstate->hostname);
		return 0;
	}

	base= pingstate->base;

	evtimer_del(&pingstate->ping_timer);

	base->table[pingstate->index]= NULL;

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

