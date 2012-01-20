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
#include "eping.h"
#include <event2/thread.h>

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
#define MAX_DATA_SIZE      (4096 - IPHDR - ICMP_MINLEN)
#define DEFAULT_PKT_SIZE   ICMP_MINLEN + DEFAULT_DATA_SIZE

/* Intervals and timeouts (all are in milliseconds unless otherwise specified) */
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

	struct sockaddr_in6 sin6;	/* IPv[46] address */
	socklen_t socklen;		/* Lenght of socket address */
	struct sockaddr_in6 loc_sin6;	/* Local IPv[46] address */
	socklen_t loc_socklen;		/* Lenght of socket address */
	size_t maxsize;

	int maxpkts;			/* Number of packets to send */

	int index;                     /* Index into the array of hosts           */
	u_int8_t seq;                  /* ICMP sequence (modulo 256) for next run */
	int got_reply;

	//struct event noreply_timer;    /* Timer to handle ICMP timeout            */
	struct event ping_timer;       /* Timer to ping host at given intervals   */

	/* Packets Counters */
	size_t cursize;
	counter_t sentpkts;            /* Total # of ICMP Echo Requests sent      */

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

	pid_t pid;                     /* Identifier to send with each ICMP Request  */

	struct timeval tv_interval;    /* Ping interval between two subsequent pings */

	/* A list of hosts to ping. */
	struct evping_host **table;
	int tabsiz;

	struct event event4;            /* Used to detect read events on raw socket   */
	struct event event6;            /* Used to detect read events on raw socket   */

	counter_t sendfail;            /* # of failed sendto()                       */
	counter_t sentok;              /* # of successful sendto()                   */
	counter_t recvfail;            /* # of failed recvfrom()                     */
	counter_t recvok;              /* # of successful recvfrom()                 */
	counter_t tooshort;            /* # of ICMP packets too short (illegal ICMP) */
	counter_t foreign;             /* # of ICMP packets we are not looking for   */
	counter_t illegal;             /* # of ICMP packets with an illegal payload  */

	void (*done)(void *state);	/* Called when a ping is done */

	u_char packet [MAX_DATA_SIZE];

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
#define	EVTHREAD_FREE_LOCK(lock, flags) _EVUTIL_NIL_STMT
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

	minlen= ICMP_MINLEN + sizeof(*data);
	if (*sizep < minlen)
		*sizep= minlen;
	if (*sizep > MAX_DATA_SIZE)
		*sizep= MAX_DATA_SIZE;

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
	icmp->icmp_cksum = mkcksum((u_short *) icmp, *sizep);  /* ones complement checksum of struct */
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
	struct evdata *data = (struct evdata *) (buffer + offsetof(struct icmp6_hdr, icmp6_data16[2]));

	struct timeval now;

	minlen= offsetof(struct icmp6_hdr, icmp6_data16[2]) + sizeof(*data);
	if (*sizep < minlen)
		*sizep= minlen;
	if (*sizep > MAX_DATA_SIZE)
		*sizep= MAX_DATA_SIZE;

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
static void ping_xmit(struct evping_host *host)
{
	struct evping_base *base = host->base;

	int nsent;

	host->got_reply= 0;
	if (host->sentpkts >= host->maxpkts)
	{
		/* Done. */
		if (host->user_callback)
		{
		    host->user_callback(PING_ERR_DONE, host->cursize,
			(struct sockaddr *)&host->sin6, host->socklen,
			(struct sockaddr *)&host->loc_sin6, host->loc_socklen,
			0, 0, NULL,
			host->user_pointer);
		    if (host->base->done)
			host->base->done(host);
		}

		/* Fake packet sent to kill timer */
	    	host->sentpkts++;

		return;
	}

	/* Transmit the request over the network */
	if (host->sin6.sin6_family == AF_INET6)
	{
		/* Format the ICMP Echo Reply packet to send */
		fmticmp6(base->packet, &host->cursize, host->seq, host->index,
			base->pid);

		nsent = sendto(base->rawfd6, base->packet, host->cursize,
			MSG_DONTWAIT, (struct sockaddr *)&host->sin6,
			host->socklen);
	}
	else
	{
		/* Format the ICMP Echo Reply packet to send */
		fmticmp4(base->packet, &host->cursize, host->seq, host->index,
			base->pid);

#if 0
		{ int i;
			printf("sending:");
			for (i= 0; i<base->pktsize; i++)
				printf(" %02x", base->packet[i]);
			printf("\n");
		}
#endif
		nsent = sendto(base->rawfd4, base->packet, host->cursize,
			MSG_DONTWAIT, (struct sockaddr *)&host->sin6,
			host->socklen);
	}

	if (nsent > 0)
	  {
	    /* One more ICMP Echo Request sent */
	    base->sentok++;

	    /* Update timestamps and counters */
	    host->sentpkts++;

	  }
	else
	{
	  base->sendfail++;
	  host->sentpkts++;

	  /* Report the failure and stop */
	  if (host->user_callback)
	  {
		host->user_callback(PING_ERR_SENDTO, host->cursize,
			(struct sockaddr *)&host->sin6, host->socklen,
			(struct sockaddr *)&host->loc_sin6, host->loc_socklen,
			errno, 0, NULL,
			host->user_pointer);
		if (host->base->done)
			host->base->done(host);
	  }
	}
}


/* The callback to handle timeouts due to destination host unreachable condition */
static void noreply_callback(int __attribute((unused)) unused, const short __attribute((unused)) event, void *h)
{
	struct evping_host *host = h;

	if (!host->got_reply && host->user_callback)
	{
		host->user_callback(PING_ERR_TIMEOUT, -1,
			(struct sockaddr *)&host->sin6, host->socklen,
			NULL, 0,
			host->seq, -1, &host->base->tv_interval,
			host->user_pointer);

		/* Update the sequence number for the next run */
		host->seq = (host->seq + 1) % 256;
	}

	ping_xmit(host);

	if (host->sentpkts <= host->maxpkts)
	{
		evtimer_add(&host->ping_timer, &host->base->tv_interval);
	}
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
	struct sockaddr_in remote;                  /* responding internet address */
	socklen_t slen = sizeof(struct sockaddr);
	struct sockaddr_in *sin4p;

	/* Pointer to relevant portions of the packet (IP, ICMP and user data) */
	struct ip * ip = (struct ip *) base->packet;
	struct icmphdr * icmp;
	struct evdata * data = (struct evdata *) (base->packet + IPHDR + ICMP_MINLEN);
	int hlen = 0;

	struct timeval now;
	struct evping_host * host;

	/* Time the packet has been received */
	gettimeofday(&now, NULL);

	EVPING_LOCK(base);

// printf("ready_callback4: before recvfrom\n");
	/* Receive data from the network */
	nrecv = recvfrom(base->rawfd4, base->packet, sizeof(base->packet), MSG_DONTWAIT, (struct sockaddr *) &remote, &slen);
	if (nrecv < 0)
	  {
	    /* One more failure */
	    base->recvfail++;

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

	/* One more ICMP packect received */
	base->recvok++;

	/* Calculate the IP header length */
	hlen = ip->ip_hl * 4;

	/* Check the IP header */
	if (nrecv < hlen + ICMP_MINLEN || ip->ip_hl < 5)
	  {
	    /* One more too short packet */
printf("ready_callback4: too short\n");
	    base->tooshort++;

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

	    /* One more foreign packet */
	    base->foreign++;

	    goto done;
	  }

	/* Check the ICMP payload for legal values of the 'index' portion */
	if (data->index >= base->tabsiz || base->table[data->index] == NULL)
	  {
	    /* One more illegal packet */
	    base->illegal++;

	    goto done;
	  }

	/* Get the pointer to the host descriptor in our internal table */
	host= base->table[data->index];

	/* Check for Destination Host Unreachable */
	if (icmp->type == ICMP_ECHOREPLY)
	  {
	    /* Use the User Data to relate Echo Request/Reply and evaluate the Round Trip Time */
	    struct timeval elapsed;             /* response time */
	    time_t usecs;

	    /* Compute time difference to calculate the round trip */
	    evutil_timersub (&now, &data->ts, &elapsed);

	    /* Update counters */
	    usecs = tvtousecs(&elapsed);

	    /* Set destination address of packet as local address */
	    memset(&host->loc_sin6, '\0', sizeof(host->loc_sin6));
	    sin4p= (struct sockaddr_in *)&host->loc_sin6;
	    sin4p->sin_family= AF_INET;
	    sin4p->sin_addr= ip->ip_dst;
	    host->loc_socklen= sizeof(*sin4p);

	    /* Report everything with the wrong sequence number as a dup. 
	     * This is not quite right, it could be a late packet. Do we
	     * care?
	     */
	    isDup= (ntohs(icmp->un.echo.sequence) != host->seq);
	    if (host->user_callback)
	    {
	    	host->user_callback(isDup ? PING_ERR_DUP : PING_ERR_NONE,
		    nrecv - IPHDR,
		    (struct sockaddr *)&host->sin6, host->socklen,
		    NULL, 0,
		    ntohs(icmp->un.echo.sequence), ip->ip_ttl, &elapsed,
		    host->user_pointer);
	    }

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
	struct sockaddr_in remote;                  /* responding internet address */

	/* Pointer to relevant portions of the packet (IP, ICMP and user data) */
	struct icmp6_hdr * icmp = (struct icmp6_hdr *) base->packet;
	struct evdata * data = (struct evdata *) (base->packet +
		offsetof(struct icmp6_hdr, icmp6_data16[2]));

	struct timeval now;
	struct evping_host * host;
	struct cmsghdr *cmsgptr;
	struct sockaddr_in6 *sin6p;
	struct msghdr msg;
	struct iovec iov[1];
	char cmsgbuf[256];

	/* Time the packet has been received */
	gettimeofday(&now, NULL);

	EVPING_LOCK(base);

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
	if (data->index >= base->tabsiz || base->table[data->index] == NULL)
	  {
	    /* One more illegal packet */
	    base->illegal++;

	    goto done;
	  }

	/* Get the pointer to the host descriptor in our internal table */
	host= base->table[data->index];

	/* Check for Destination Host Unreachable */
	if (icmp->icmp6_type == ICMP6_ECHO_REPLY)
	  {
	    /* Use the User Data to relate Echo Request/Reply and evaluate the Round Trip Time */
	    struct timeval elapsed;             /* response time */
	    time_t usecs;

	    /* Compute time difference to calculate the round trip */
	    evutil_timersub (&now, &data->ts, &elapsed);

	    /* Update counters */
	    usecs = tvtousecs(&elapsed);

	    /* Set destination address of packet as local address */
	    memset(&host->loc_sin6, '\0', sizeof(host->loc_sin6));
	    host->loc_socklen= sizeof(*sin6p);
	    for (cmsgptr= CMSG_FIRSTHDR(&msg); cmsgptr; 
		    cmsgptr= CMSG_NXTHDR(&msg, cmsgptr))
	    {
		    if (cmsgptr->cmsg_len == 0)
			    break;	/* Can this happen? */
		    if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
			    cmsgptr->cmsg_type == IPV6_PKTINFO)
		    {
			    sin6p= &host->loc_sin6;
			    sin6p->sin6_family= AF_INET6;
			    sin6p->sin6_addr= ((struct in6_pktinfo *)
				    CMSG_DATA(cmsgptr))->ipi6_addr;
		    }
	    }

	    /* Report everything with the wrong sequence number as a dup. 
	     * This is not quite right, it could be a late packet. Do we
	     * care?
	     */
	    isDup= (ntohs(icmp->icmp6_seq) != host->seq);
	    if (host->user_callback)
	    {
	    	host->user_callback(isDup ? PING_ERR_DUP : PING_ERR_NONE,
		    nrecv - IPHDR,\
		    (struct sockaddr *)&host->sin6, host->socklen,
		    NULL, 0,
		    ntohs(icmp->icmp6_seq), -1, &elapsed,
		    host->user_pointer);
	    }

	    /* Update the sequence number for the next run */
	    host->seq = (host->seq + 1) % 256;

	    if (!isDup)
		host->got_reply= 1;
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
	int p_proto, on;
	struct protoent *protop;
	evutil_socket_t fd4, fd6;
	struct evping_base *base;

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
	setsockopt(fd6, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));

	base = malloc(sizeof(struct evping_base));
	if (base == NULL)
		return (NULL);
	memset(base, 0, sizeof(struct evping_base));

	EVTHREAD_ALLOC_LOCK(base->lock, EVTHREAD_LOCKTYPE_RECURSIVE);
	EVPING_LOCK(base);

	base->event_base = event_base;

	base->tabsiz= 10;
	base->table= xzalloc(base->tabsiz * sizeof(*base->table));

	base->rawfd4 = fd4;
	base->rawfd6 = fd6;
	evutil_make_socket_nonblocking(base->rawfd4);
	evutil_make_socket_nonblocking(base->rawfd6);

	/* Set default values */
	base->pid = getpid();

	msecstotv(DEFAULT_PING_INTERVAL, &base->tv_interval);

	/* Define the callback to handle ICMP Echo Reply and add the raw file descriptor to those monitored for read events */
	event_assign(&base->event4, base->event_base, base->rawfd4,
		EV_READ | EV_PERSIST, ready_callback4, base);
	event_assign(&base->event6, base->event_base, base->rawfd6,
		EV_READ | EV_PERSIST, ready_callback6, base);
	event_add(&base->event4, NULL);
	event_add(&base->event6, NULL);

	base->done= 0;

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

	free(base);
}


/* exported function */
struct evping_host *
evping_base_host_add(struct evping_base *base, sa_family_t af, const char * name)
{
	int i, newsiz;
	struct evping_host *host;
	len_and_sockaddr *lsa;

	/* Attempt to resolv 'name' */
	lsa= host_and_af2sockaddr(name, 0, af);
	if (!lsa)
		return NULL;

	if (lsa->len > sizeof(host->sin6))
	{
		free(lsa);
		return NULL;
	}

	host = malloc(sizeof(*host));
	if (!host) return NULL;

	memset(host, 0, sizeof(*host));

	EVPING_LOCK(base);

	memcpy(&host->sin6, &lsa->u.sa, lsa->len);
	host->socklen= lsa->len;
	free(lsa); lsa= NULL;
	memset(&host->loc_sin6, '\0', sizeof(host->loc_sin6));
	host->loc_socklen= 0;

	host->base = base;

	host->seq = 1;

	/* Define here the callbacks to ping the host and to handle no reply timeouts */
	evtimer_assign(&host->ping_timer, base->event_base,
		noreply_callback, host);

	for (i= 0; i<base->tabsiz; i++)
	{
		if (base->table[i] == NULL)
			break;
	}
	if (i >= base->tabsiz)
	{
		newsiz= 2*base->tabsiz;
		base->table= xrealloc(base->table,
			newsiz*sizeof(*base->table));
		for (i= base->tabsiz; i<newsiz; i++)
			base->table[i]= NULL;
		i= base->tabsiz;
		base->tabsiz= newsiz;
	}
	host->index= i;
	base->table[i]= host;

	EVPING_UNLOCK(base);
	return host;
}


/* exported function */
void
evping_ping(struct evping_host *host, size_t size,
	evping_callback_type callback, void *ptr,
	void (*done)(void *state))
{
	host->maxsize = size;
	host->user_callback = callback;
	host->user_pointer = ptr;
	host->base->done= done;
}

void
evping_delete(struct evping_host *host)
{
	struct evping_base *base= host->base;

	evtimer_del(&host->ping_timer);

	assert(base->table[host->index] == host);
	base->table[host->index]= NULL;

	free(host);
}

/* exported function */
void
evping_start(struct evping_host *host, int count)
{
	host->maxpkts= count;
	host->sentpkts= 0;
	host->cursize= host->maxsize;

	ping_xmit(host);

	/* Add the timer to handle no reply condition in the given timeout */
	evtimer_add(&host->ping_timer, &host->base->tv_interval);
}


/* exported function */
int
evping_base_count_hosts(struct evping_base *base)
{
	int i, n = 0;

	EVPING_LOCK(base);
	for (i= 0; i<base->tabsiz; i++)
	{
		if (base->table[i])
			n++;
	}

	EVPING_UNLOCK(base);
	return n;
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
