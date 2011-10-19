/*
 * Copyright (c) 2009 Rocco Carbone <ro...@tecsiel.it>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include "event-config.h"
#endif

#include "libbb.h"

#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <values.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <math.h>

#include <event2/event.h>
#include <event2/event_struct.h>
#include "evping.h"
#include <event2/thread.h>

//#include "mm-internal.h"
//#include "evthread-internal.h"


#undef MIN	/* just in case */
#undef MAX	/* also, just in case */

#define MIN(a, b) (a < b ? a : b)
#define MAX(a, b) (a > b ? a : b)


/* Packets definitions */

/* Max IP packet size is 65536 while fixed IP header size is 20;
 * the traditional ping program transmits 56 bytes of data, so the
 * default data size is calculated as to be like the original
 */
#define IPHDR              20
#define MIN_DATA_SIZE      sizeof(struct evdata)
#define DEFAULT_DATA_SIZE  (MIN_DATA_SIZE + 44)                   /* calculated as so to be like traditional ping */
#define MAX_DATA_SIZE      (IP_MAXPACKET - IPHDR - ICMP_MINLEN)
#define DEFAULT_PKT_SIZE   ICMP_MINLEN + DEFAULT_DATA_SIZE

/* Intervals and timeouts (all are in milliseconds unless otherwise specified) */
#define DEFAULT_NOREPLY_TIMEOUT 100            /* 100 msec - 0 is illegal      */
#define DEFAULT_PING_INTERVAL   1000           /* 1 sec - 0 means flood mode   */


/* Definition for various types of counters */
typedef uint64_t counter_t;


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


/* How to keep track of each host to ping */
struct evping_host {
	struct evping_base *base;

	char *name;                    /* Host identifier as given by the user    */
	len_and_sockaddr *lsa;		/* IPv[46] address */
	int maxpkts;			/* Number of packets to send */
	char * ipname;                 /* Remote address in dot notation          */

	int index;                     /* Index into the array of hosts           */
	u_int8_t seq;                  /* ICMP sequence (modulo 256) for next run */

	struct event noreply_timer;    /* Timer to handle ICMP timeout            */
	struct event ping_timer;       /* Timer to ping host at given intervals   */

	/* Packets Counters */
	counter_t sentpkts;            /* Total # of ICMP Echo Requests sent      */
	counter_t recvpkts;            /* Total # of ICMP Echo Replies received   */
	counter_t dropped;             /* # of ICMP packets dropped               */

	/* Bytes counters */
	counter_t sentbytes;           /* Total # of bytes sent                   */
	counter_t recvbytes;           /* Total # of bytes received               */

	/* Timestamps */
	struct timeval firstsent;      /* Time first ICMP request was sent        */
	struct timeval firstrecv;      /* Time first ICMP reply was received      */
	struct timeval lastsent;       /* Time last ICMP request was sent         */
	struct timeval lastrecv;       /* Time last ICMP reply was received       */

	/* Counters for statistics */
	double shortest;               /* Shortest reply time                     */
	double longest;                /* Longest reply time                      */
	double sum;                    /* Sum of reply times                      */
	double square;                 /* Sum of qquare of reply times            */


	evping_callback_type user_callback;
	void *user_pointer;            /* the pointer given to us for this host   */

	/* these objects are kept in a circular list */
	struct evping_host *next, *prev;
};


/* How to keep track of a PING session */
struct evping_base {
	struct event_base *event_base;

	evutil_socket_t rawfd4;	       /* Raw socket used to ping hosts (IPv4)              */
	evutil_socket_t rawfd6;	       /* Raw socket used to ping hosts (IPv6)              */

	uint32_t pktsize;              /* Packet size in bytes (ICMP plus User Data) */
	pid_t pid;                     /* Identifier to send with each ICMP Request  */

	struct timeval tv_noreply;     /* ICMP Echo Reply timeout                    */
	struct timeval tv_interval;    /* Ping interval between two subsequent pings */

	/* A circular list of hosts to ping. */
	struct evping_host *host_head;
	unsigned argc;                 /* # of hosts to be pinged                    */

	struct event event4;            /* Used to detect read events on raw socket   */
	struct event event6;            /* Used to detect read events on raw socket   */

	counter_t sendfail;            /* # of failed sendto()                       */
	counter_t sentok;              /* # of successful sendto()                   */
	counter_t recvfail;            /* # of failed recvfrom()                     */
	counter_t recvok;              /* # of successful recvfrom()                 */
	counter_t tooshort;            /* # of ICMP packets too short (illegal ICMP) */
	counter_t foreign;             /* # of ICMP packets we are not looking for   */
	counter_t illegal;             /* # of ICMP packets with an illegal payload  */

	u_char quiet;

#ifndef _EVENT_DISABLE_THREAD_SUPPORT
	void *lock;
	int lock_count;
#endif

};


#define _EVENT_DISABLE_THREAD_SUPPORT
#define _EVUTIL_NIL_STMT do {} while(0)

#ifdef _EVENT_DISABLE_THREAD_SUPPORT
#define EVPING_LOCK(base)  _EVUTIL_NIL_STMT
#define EVPING_UNLOCK(base) _EVUTIL_NIL_STMT
#define ASSERT_LOCKED(base) _EVUTIL_NIL_STMT
#define EVTHREAD_ALLOC_LOCK(lock, flags) _EVUTIL_NIL_STMT
#else
#define EVPING_LOCK(base)						\
	do {								\
		if ((base)->lock) {					\
			EVLOCK_LOCK((base)->lock, EVTHREAD_WRITE);	\
		}							\
		++(base)->lock_count;					\
	} while (0)
#define EVPING_UNLOCK(base)						\
	do {								\
		assert((base)->lock_count > 0);				\
		--(base)->lock_count;					\
		if ((base)->lock) {					\
			EVLOCK_UNLOCK((base)->lock, EVTHREAD_WRITE);	\
		}							\
	} while (0)
#define ASSERT_LOCKED(base) assert((base)->lock_count > 0)
#endif


/* Initialize a struct timeval by converting milliseconds */
static void
msecstotv(time_t msecs, struct timeval *tv)
{
	tv->tv_sec  = msecs / 1000;
	tv->tv_usec = msecs % 1000 * 1000;
}


/* Lookup for a host by its index */
static struct evping_host *
evping_lookup_host(struct evping_base *base, int idx)
{
	struct evping_host *host;

	host = base->host_head;
	if (!host)
		goto done;
	do {
		if (host->index == idx)
		  return host;
		host = host->next;
	} while (host != base->host_head);
done:
	return NULL;
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
static void fmticmp4(u_char *buffer, unsigned size, u_int8_t seq,
	uint32_t idx, pid_t pid)
{
	struct icmp *icmp = (struct icmp *) buffer;
	struct evdata *data = (struct evdata *) (buffer + ICMP_MINLEN);

	struct timeval now;

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
	icmp->icmp_cksum = mkcksum((u_short *) icmp, size);  /* ones complement checksum of struct */
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
static void fmticmp6(u_char *buffer, unsigned size,
	u_int8_t seq, uint32_t idx, pid_t pid)
{
	struct icmp6_hdr *icmp = (struct icmp6_hdr *) buffer;
	struct evdata *data = (struct evdata *) (buffer + offsetof(struct icmp6_hdr, icmp6_data16[2]));

	struct timeval now;

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
static void ping_callback(int __attribute((unused)) unused,
	const short __attribute((unused)) event, void *h)
{
	struct evping_host *host = h;
	struct evping_base *base = host->base;

	u_char packet [MAX_DATA_SIZE] = "";
	int nsent;

	/* Clean the no reply timer (if any was previously set) */
	evtimer_del(&host->noreply_timer);

	if (host->sentpkts >= host->maxpkts)
	{
		/* Done. */
		if (host->user_callback)
		{
		    host->user_callback(PING_ERR_DONE, base->pktsize,
			host->ipname, 0, 0, NULL,
			host->user_pointer);
		}
		return;
	}

	/* Transmit the request over the network */
	if (host->lsa->u.sa.sa_family == AF_INET6)
	{
		/* Format the ICMP Echo Reply packet to send */
		fmticmp6(packet, base->pktsize, host->seq, host->index,
			base->pid);

		nsent = sendto(base->rawfd6, packet, base->pktsize,
			MSG_DONTWAIT, &host->lsa->u.sa, host->lsa->len);
	}
	else
	{
		/* Format the ICMP Echo Reply packet to send */
		fmticmp4(packet, base->pktsize, host->seq, host->index,
			base->pid);

		nsent = sendto(base->rawfd4, packet, base->pktsize,
			MSG_DONTWAIT, &host->lsa->u.sa, host->lsa->len);
	}

	if (nsent == base->pktsize)
	  {
	    /* One more ICMP Echo Request sent */
	    base->sentok++;

	    if (!host->sentpkts && !base->quiet)
	      printf("PING (%s) %d(%d) bytes of data.\n", host->ipname,
		     base->pktsize - ICMP_MINLEN, nsent + IPHDR);

	    /* Update timestamps and counters */
	    if (!host->sentpkts)
	      gettimeofday(&host->firstsent, NULL);
	    gettimeofday (&host->lastsent, NULL);
	    host->sentpkts++;
	    host->sentbytes += nsent;

	    /* Add the timer to handle no reply condition in the given timeout */
	    evtimer_add(&host->noreply_timer, &base->tv_noreply);
	  }
	else
	  base->sendfail++;
}


/* The callback to handle timeouts due to destination host unreachable condition */
static void noreply_callback(int __attribute((unused)) unused, const short __attribute((unused)) event, void *h)
{
	struct evping_host *host = h;

	host->dropped++;

	/* Add the timer to ping again the host at the given time interval */
	evtimer_add(&host->ping_timer, &host->base->tv_interval);

	if (host->user_callback)
	  host->user_callback(PING_ERR_TIMEOUT, -1, host->ipname,
			      host->seq, -1, &host->base->tv_noreply, host->user_pointer);

	/* Update the sequence number for the next run */
	host->seq = (host->seq + 1) % 256;
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
	struct evping_base *base = arg;

	int nrecv, isDup;
	u_char packet[MAX_DATA_SIZE];
	struct sockaddr_in remote;                  /* responding internet address */
	socklen_t slen = sizeof(struct sockaddr);

	/* Pointer to relevant portions of the packet (IP, ICMP and user data) */
	struct ip * ip = (struct ip *) packet;
	struct icmphdr * icmp;
	struct evdata * data = (struct evdata *) (packet + IPHDR + ICMP_MINLEN);
	int hlen = 0;

	struct timeval now;
	struct evping_host * host;

	/* Time the packet has been received */
	gettimeofday(&now, NULL);

	EVPING_LOCK(base);

	/* Receive data from the network */
	nrecv = recvfrom(base->rawfd4, packet, sizeof(packet), MSG_DONTWAIT, (struct sockaddr *) &remote, &slen);
	if (nrecv < 0)
	  {
	    /* One more failure */
	    base->recvfail++;

	    goto done;
	  }

	/* One more ICMP packect received */
	base->recvok++;

	/* Calculate the IP header length */
	hlen = ip->ip_hl * 4;

	/* Check the IP header */
	if (nrecv < hlen + ICMP_MINLEN || ip->ip_hl < 5)
	  {
	    /* One more too short packet */
	    base->tooshort++;

	    goto done;
	  }

	/* The ICMP portion */
	icmp = (struct icmphdr *) (packet + hlen);

	/* Check the ICMP header to drop unexpected packets due to unrecognized id */
	if (icmp->un.echo.id != base->pid)
	  {
	    /* One more foreign packet */
	    base->foreign++;

	    goto done;
	  }

	/* Check the ICMP payload for legal values of the 'index' portion */
	if (base->argc < data->index)
	  {
	    /* One more illegal packet */
	    base->illegal++;

	    goto done;
	  }

	/* Get the pointer to the host descriptor in our internal table */
	host = evping_lookup_host(base, data->index);

	/* Check for Destination Host Unreachable */
	if (icmp->type == ICMP_ECHOREPLY)
	  {
	    /* Use the User Data to relate Echo Request/Reply and evaluate the Round Trip Time */
	    struct timeval elapsed;             /* response time */
	    time_t usecs;

	    /* Compute time difference to calculate the round trip */
	    evutil_timersub (&now, &data->ts, &elapsed);

	    /* Update timestamps */
	    if (!host->recvpkts)
	      gettimeofday (&host->firstrecv, NULL);
	    gettimeofday (&host->lastrecv, NULL);
	    host->recvpkts++;
	    host->recvbytes += nrecv;

	    /* Update counters */
	    usecs = tvtousecs(&elapsed);
	    host->shortest = MIN(host->shortest, usecs);
	    host->longest = MAX(host->longest, usecs);
	    host->sum += usecs;
	    host->square += (usecs * usecs);

	    /* Report everything with the wrong sequence number as a dup. 
	     * This is not quite right, it could be a late packet. Do we
	     * care?
	     */
	    isDup= (ntohs(icmp->un.echo.sequence) != host->seq);
	    if (host->user_callback)
	    {
	    	host->user_callback(isDup ? PING_ERR_DUP : PING_ERR_NONE,
		    nrecv - IPHDR, host->ipname,
		    ntohs(icmp->un.echo.sequence), ip->ip_ttl, &elapsed,
		    host->user_pointer);
	    }

	    /* Update the sequence number for the next run */
	    host->seq = (host->seq + 1) % 256;

	    /* Clean the noreply timer */
	    evtimer_del(&host->noreply_timer);

	    /* Add the timer to ping again the host at the given time interval */
	    evtimer_add(&host->ping_timer, &host->base->tv_interval);
	  }
	else
	  /* Handle this condition exactly as the request has expired */
	  noreply_callback (-1, -1, host);

done:
	EVPING_UNLOCK(base);
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
	struct evping_base *base = arg;

	int nrecv, isDup;
	u_char packet[MAX_DATA_SIZE];
	struct sockaddr_in remote;                  /* responding internet address */
	socklen_t slen = sizeof(struct sockaddr);

	/* Pointer to relevant portions of the packet (IP, ICMP and user data) */
	struct icmp6_hdr * icmp = (struct icmp6_hdr *) packet;
	struct evdata * data = (struct evdata *) (packet +
		offsetof(struct icmp6_hdr, icmp6_data16[2]));

	struct timeval now;
	struct evping_host * host;

	/* Time the packet has been received */
	gettimeofday(&now, NULL);

	EVPING_LOCK(base);

	/* Receive data from the network */
	nrecv = recvfrom(base->rawfd6, packet, sizeof(packet), MSG_DONTWAIT, (struct sockaddr *) &remote, &slen);
	if (nrecv < 0)
	  {
	    /* One more failure */
	    base->recvfail++;

	    goto done;
	  }

	/* One more ICMP packect received */
	base->recvok++;

	/* Check the ICMP header to drop unexpected packets due to
	 * unrecognized id
	 */
	if (icmp->icmp6_id != base->pid)
	  {
	    /* One more foreign packet */
	    base->foreign++;

	    goto done;
	  }

	/* Check the ICMP payload for legal values of the 'index' portion */
	if (base->argc < data->index)
	  {
	    /* One more illegal packet */
	    base->illegal++;

	    goto done;
	  }

	/* Get the pointer to the host descriptor in our internal table */
	host = evping_lookup_host(base, data->index);

	/* Check for Destination Host Unreachable */
	if (icmp->icmp6_type == ICMP6_ECHO_REPLY)
	  {
	    /* Use the User Data to relate Echo Request/Reply and evaluate the Round Trip Time */
	    struct timeval elapsed;             /* response time */
	    time_t usecs;

	    /* Compute time difference to calculate the round trip */
	    evutil_timersub (&now, &data->ts, &elapsed);

	    /* Update timestamps */
	    if (!host->recvpkts)
	      gettimeofday (&host->firstrecv, NULL);
	    gettimeofday (&host->lastrecv, NULL);
	    host->recvpkts++;
	    host->recvbytes += nrecv;

	    /* Update counters */
	    usecs = tvtousecs(&elapsed);
	    host->shortest = MIN(host->shortest, usecs);
	    host->longest = MAX(host->longest, usecs);
	    host->sum += usecs;
	    host->square += (usecs * usecs);

	    /* Report everything with the wrong sequence number as a dup. 
	     * This is not quite right, it could be a late packet. Do we
	     * care?
	     */
	    isDup= (ntohs(icmp->icmp6_seq) != host->seq);
	    if (host->user_callback)
	    {
	    	host->user_callback(isDup ? PING_ERR_DUP : PING_ERR_NONE,
		    nrecv - IPHDR, host->ipname,
		    ntohs(icmp->icmp6_seq), -1, &elapsed,
		    host->user_pointer);
	    }

	    /* Update the sequence number for the next run */
	    host->seq = (host->seq + 1) % 256;

	    /* Clean the noreply timer */
	    evtimer_del(&host->noreply_timer);

	    /* Add the timer to ping again the host at the given time interval */
	    evtimer_add(&host->ping_timer, &host->base->tv_interval);
	  }
	else
	  /* Handle this condition exactly as the request has expired */
	  noreply_callback (-1, -1, host);

done:
	EVPING_UNLOCK(base);
}


/* exported function */
struct evping_base *
evping_base_new(struct event_base *event_base)
{
	struct protoent *proto;
	evutil_socket_t fd4, fd6;
	struct evping_base *base;

	static struct protoent icmp_default;


	/* Check if the ICMP protocol is available on this system */
	if (!(proto = getprotobyname("icmp"))) {
	  icmp_default.p_name= "icmp";
	  icmp_default.p_aliases= NULL;
	  icmp_default.p_proto= IPPROTO_ICMP;
	  proto= &icmp_default;
	  //return NULL;
	}

	/* Create an endpoint for communication using raw socket for ICMP calls */
	if ((fd4 = socket(AF_INET, SOCK_RAW, proto->p_proto)) == -1) {
	  return NULL;
	}

	/* Check if the ICMP6 protocol is available on this system */
	if (!(proto = getprotobyname("icmp6"))) {
	  icmp_default.p_name= "icmp6";
	  icmp_default.p_aliases= NULL;
	  icmp_default.p_proto= IPPROTO_ICMPV6;
	  proto= &icmp_default;
	  //return NULL;
	}

	if ((fd6 = socket(AF_INET6, SOCK_RAW, proto->p_proto)) == -1) {
	  close(fd4);
	  return NULL;
	}

	base = malloc(sizeof(struct evping_base));
	if (base == NULL)
		return (NULL);
	memset(base, 0, sizeof(struct evping_base));

	EVTHREAD_ALLOC_LOCK(base->lock, EVTHREAD_LOCKTYPE_RECURSIVE);
	EVPING_LOCK(base);

	base->event_base = event_base;

	base->rawfd4 = fd4;
	base->rawfd6 = fd6;
	evutil_make_socket_nonblocking(base->rawfd4);
	evutil_make_socket_nonblocking(base->rawfd6);

	/* Set default values */
	base->pktsize = DEFAULT_PKT_SIZE;
	base->pid = getpid();

	base->quiet= 1;

	msecstotv(DEFAULT_NOREPLY_TIMEOUT, &base->tv_noreply);
	msecstotv(DEFAULT_PING_INTERVAL, &base->tv_interval);

	/* Define the callback to handle ICMP Echo Reply and add the raw file descriptor to those monitored for read events */
	event_assign(&base->event4, base->event_base, base->rawfd4,
		EV_READ | EV_PERSIST, ready_callback4, base);
	event_assign(&base->event6, base->event_base, base->rawfd6,
		EV_READ | EV_PERSIST, ready_callback6, base);
	event_add(&base->event4, NULL);
	event_add(&base->event6, NULL);

	EVPING_UNLOCK(base);
	return base;
}


/* exported function */
void
evping_base_free(struct evping_base *base,
	int __attribute((unused)) fail_requests)
{
	EVPING_LOCK(base);

	EVPING_UNLOCK(base);
	EVTHREAD_FREE_LOCK(base->lock, EVTHREAD_LOCKTYPE_RECURSIVE);

	mm_free(base);
}


/* exported function */
struct evping_host *
evping_base_host_add(struct evping_base *base, const char * name)
{
	struct evping_host *host;
	len_and_sockaddr *lsa;
	sa_family_t af;
	char namebuf[NI_MAXHOST];

	/* Attempt to resolv 'name' */
	af= AF_UNSPEC;
	lsa= host_and_af2sockaddr(name, 0, af);
	if (!lsa)
		return NULL;

	host = malloc(sizeof(*host));
	if (!host) return NULL;

	memset(host, 0, sizeof(*host));

	EVPING_LOCK(base);

	host->lsa= lsa;
	host->base = base;
	host->name = strdup(name);

	getnameinfo(&host->lsa->u.sa, host->lsa->len,
		namebuf, sizeof(namebuf), NULL, 0, NI_NUMERICHOST);
	host->ipname = strdup(namebuf);

	host->index = base->argc;
	host->seq = 1;
	host->shortest = MAXINT;

	/* Define here the callbacks to ping the host and to handle no reply timeouts */
	evtimer_assign(&host->ping_timer, base->event_base, ping_callback, host);
	evtimer_assign(&host->noreply_timer, base->event_base, noreply_callback, host);

	/* insert this nameserver into the list of them */
	if (!base->host_head) {
	  host->next = host->prev = host;
	  base->host_head = host;
	} else {
	  host->next = base->host_head->next;
	  host->next->prev= host;
	  host->prev = base->host_head;
	  base->host_head->next = host;
	  
	  { struct evping_host *h;
		printf("evping_base_host_add: after insert, forward:");
		for (h= base->host_head; h; h= h->next)
		{
			printf(" %p", h);
			if (h->next == base->host_head)
				break;
		}
		printf("\n");

		printf("evping_base_host_add: after insert, reverse:");
		for (h= base->host_head; h; h= h->prev)
		{
			printf(" %p", h);
			if (h->prev == base->host_head)
				break;
		}
		printf("\n");
	}
	}

	base->argc++;

	EVPING_UNLOCK(base);
	return host;
}


/* exported function */
void
evping_ping(struct evping_host *host, evping_callback_type callback, void *ptr)
{
	host->user_callback = callback;
	host->user_pointer = ptr;
}

void
evping_delete(struct evping_host *host)
{
	struct evping_host *h;
	struct evping_base *base= host->base;

	printf("evping_delete: before delete, forward:");
	for (h= base->host_head; h; h= h->next)
	{
		printf(" %p", h);
		if (h->next == base->host_head)
			break;
	}
	printf("\n");

	printf("evping_delete: before delete, reverse:");
	for (h= base->host_head; h; h= h->prev)
	{
		printf(" %p", h);
		if (h->prev == base->host_head)
			break;
	}
	printf("\n");

	evtimer_del(&host->noreply_timer);
	evtimer_del(&host->ping_timer);
	free(host->name);
	host->name= NULL;
	free(host->ipname);
	host->ipname= NULL;
	free(host->lsa);
	host->lsa= NULL;
	if (host->next == host)
	{
		/* Only element in list */
		host->base->host_head= NULL;
	}
	else
	{
		host->next->prev= host->prev;
		host->prev->next= host->next;
		if (host->base->host_head == host)
			host->base->host_head= host->next;
	}
	free(host);

	printf("evping_delete: after delete, forward:");
	for (h= base->host_head; h; h= h->next)
	{
		printf(" %p", h);
		if (h->next == base->host_head)
			break;
	}
	printf("\n");

	printf("evping_delete: after delete, reverse:");
	for (h= base->host_head; h; h= h->prev)
	{
		printf(" %p", h);
		if (h->prev == base->host_head)
			break;
	}
	printf("\n");

}

/* exported function */
void
evping_start(struct evping_host *host, int count)
{
	struct timeval asap = { 0, 0 };

	host->maxpkts= count;
	host->sentpkts= 0;

	/* Schedule to immediately ping this host */
	evtimer_add(&host->ping_timer, &asap);
}


/* exported function */
int
evping_base_count_hosts(struct evping_base *base)
{
	const struct evping_host *host;
	int n = 0;

	EVPING_LOCK(base);
	host = base->host_head;
	if (!host)
		goto done;
	do {
		++n;
		host = host->next;
	} while (host != base->host_head);
done:
	EVPING_UNLOCK(base);
	return n;
}


/* exported function */
void
evping_stats(struct evping_base *base)
{
	struct evping_host *host;

	EVPING_LOCK(base);
	host = base->host_head;
	if (!host)
		goto done;
	do {
	  	printf("--- %s ping statistics ---\n"
		       "%lld packets transmitted, %lld received, %.2f%% packet loss, time %.1fms\n",
		       host->ipname, (long long)host->sentpkts,
		       (long long)host->recvpkts,
		       100.0 * (host->sentpkts - host->recvpkts) / ((double) host->sentpkts),
		       host->sum / 1000.0);

		if (host->recvpkts)
		  {
		    double average = host->sum / host->recvpkts;
		    double deviation = sqrt(((host->recvpkts * host->square) -
					     (host->sum * host->sum)) / (host->recvpkts * (host->recvpkts - 1.0)));

		    printf ("rtt min/avg/max/sdev = %.3f/%.3f/%.3f/%.3f ms\n\n",
			    host->shortest / 1000.0,
			    average / 1000.0,
			    host->longest / 1000.0,
			    deviation / 1000.0);
		  }
		else
		  printf ("\n");

		host = host->next;
	} while (host != base->host_head);
done:
	EVPING_UNLOCK(base);
}


/* exported function */
const char *
evping_err_to_string(int err)
{
    switch (err) {
	case PING_ERR_NONE: return "no error";
	case PING_ERR_TIMEOUT: return "request timed out";
	case PING_ERR_SHUTDOWN: return "ping subsystem shut down";
	case PING_ERR_CANCEL: return "ping request canceled";
	case PING_ERR_UNKNOWN: return "unknown";
	default: return "[Unknown error code]";
    }
}


/* exported function */
/* The time since 'tv' in microseconds */
time_t
tvtousecs (struct timeval *tv)
{
	return tv->tv_sec * 1000000.0 + tv->tv_usec;
}
