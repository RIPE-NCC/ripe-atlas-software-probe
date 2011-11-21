/*
 * Copyright (c) 2011 RIPE NCC, Antony Antony
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
#include <netdb.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <math.h>
#include <assert.h>
#include "eperd.h" 
#include "evping.h"

#include <event2/event.h>
#include <event2/event_struct.h>

#include "mm-internal.h"
#include "evthread-internal.h"


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
#define DEFAULT_DATA_SIZE  (MIN_DATA_SIZE + 44)          
#define DEFAULT_PKT_SIZE   ICMP_MINLEN + DEFAULT_DATA_SIZE
#define MAX_DNS_BUF_SIZE   2048

/* Intervals and timeouts (all are in milliseconds unless otherwise specified) */
#define DEFAULT_NOREPLY_TIMEOUT 100            /* 100 msec - 0 is illegal      */
#define DEFAULT_PING_INTERVAL   1000           /* 1 sec - 0 means flood mode   */

#ifndef ns_t_dnskey
#define ns_t_dnskey   48
#endif

#ifndef T_DNSKEY
#define T_DNSKEY ns_t_dnskey
#endif

static void ChangetoDnsNameFormat(u_char * dns,unsigned char* qry) ;
struct tdig_base *tdig_base_new(struct event_base *event_base); 

/* Definition for various types of counters */
typedef uint64_t counter_t;


struct evdata {
	struct timeval ts;
	uint32_t index;
};

/* How to keep track of a DNS query session */
struct tdig_base {
	struct event_base *event_base;

	evutil_socket_t rawfd;	       /* Raw socket used to nsm hosts              */

	uint32_t pktsize;              /* Packet size in bytes */

	struct timeval tv_noreply;     /* DNS query Reply timeout                    */
	struct timeval tv_interval;    /* between two subsequent queries */

	/* A circular list of user queries */
	struct query_state *qry_head;

	struct event event;            /* Used to detect read events on raw socket   */

	counter_t sendfail;            /* # of failed sendto()                       */
	counter_t sentok;              /* # of successful sendto()                   */
	counter_t recvfail;            /* # of failed recvfrom()                     */
	counter_t recvok;              /* # of successful recvfrom()                 */
	counter_t tooshort;            /* # of ICMP packets too short (illegal ICMP) */
	counter_t foreign;             /* # of ICMP packets we are not looking for   */
	counter_t illegal;             /* # of ICMP packets with an illegal payload  */

	u_char quiet;

	u_int16_t qtype; 
	u_int16_t qclass;  
	
        struct DNS_HEADER *dns;
	struct EDNS0_HEADER *edns0;

#ifndef _EVENT_DISABLE_THREAD_SUPPORT
	void *lock;
	int lock_count;
#endif

};


static struct tdig_base *base;

/* How to keep track of each user query to send dns query */
static struct query_state {

	struct tdig_base *base;
	char * name;                 /* Host identifier as given by the user */
	char * fqname;              /* Full qualified hostname          */ 
	char * ipname;              /* Remote address in dot notation   */
	int index;                  /* Index into the array of queries  */
	u_int8_t seq;               /* query id 16 bit */

	int opt_v4_only ;
	int opt_v6_only ;
	int opt_tcp;
	int opt_edns0;
	int opt_dnssec;
	
	char * atlas_Str; 
	u_int16_t qtype;
	u_int16_t qclass;

	
	unsigned char *lookupname;
	char * server_ip_str;

	struct addrinfo *res, *ressave;

	struct event noreply_timer;    /* Timer to handle ICMP timeout            */
	struct event nsm_timer;        /* Timer to next query intervals   */

	/* Packets Counters */
	counter_t sentpkts;            /* Total # of ICMP Echo Requests sent      */
	counter_t recvpkts;            /* Total # of ICMP Echo Replies received   */
	counter_t dropped;             /* # of unanswered queries 		  */

	/* Bytes counters */
	counter_t sentbytes;           /* Total # of bytes sent                   */
	counter_t recvbytes;           /* Total # of bytes received               */

	/* Timestamps */
	struct timeval firstsent;      /* Time first ICMP request was sent        */
	struct timeval firstrecv;      /* Time first ICMP reply was received      */
	struct timeval lastsent;       /* Time last ICMP request was sent         */
	struct timeval lastrecv;       /* Time last ICMP reply was received       */

	//tdig_callback_type user_callback;
	void *user_callback;
	void *user_pointer;            /* the pointer given to us for this qry   */

	/* these objects are kept in a circular list */
	struct query_state *next, *prev;
};
//DNS header structure
struct DNS_HEADER
{
	u_int16_t id;        // identification number
	u_int16_t rd :1,     // recursion desired
		  tc :1,     // truncated message
		  aa :1,     // authoritive answer
		  opcode :4, // purpose of message
		  qr :1,     // query/response flag
		  rcode :4,  // response code
		  cd :1,     // checking disabled
		  ad :1,     // authenticated data
		  z :1,      // its z! reserved
		  ra :1;     // recursion available
	u_int16_t q_count; // number of question entries
	u_int16_t ans_count; // number of answer entries
	u_int16_t auth_count; // number of authority entries
	u_int16_t add_count; // number of resource entries
};

// EDNS0

struct EDNS0_HEADER
{
        /** EDNS0 available buffer size, see RFC2671 */
        u_int16_t qtype;
        uint16_t _edns_udp_size;
        u_int8_t _edns_x; // combined rcode and edns version both zeros.
        u_int8_t _edns_y; // combined rcode and edns version both zeros.
        //u_int16_t _edns_z;
        u_int16_t DO ;
        u_int16_t len ;
        u_int8_t _edns_d;
};

//Constant sized fields of query structure
struct QUESTION
{
        u_int16_t qtype;
        u_int16_t qclass;
};

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
        u_int16_t type;
        u_int16_t _class;
        u_int32_t ttl;
        u_int16_t data_len;
};
#pragma pack(pop)

//Pointers to resource record contents
struct RES_RECORD
{
        unsigned char *name;
        struct R_DATA *resource;
        unsigned char *rdata;
};

#ifdef _EVENT_DISABLE_THREAD_SUPPORT
#define EVPING_LOCK(base)  _EVUTIL_NIL_STMT
#define EVPING_UNLOCK(base) _EVUTIL_NIL_STMT
#define ASSERT_LOCKED(base) _EVUTIL_NIL_STMT
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


static struct option longopts[]=
{
        { "hostname-bind", no_argument, NULL, 'h' },
        { "id-server", no_argument, NULL, 'i' },
        { "version-bind", no_argument, NULL, 'b' },
        { "version.server", no_argument, NULL, 'r' },
        { "soa", required_argument, NULL, 's' },
        { "edns0", required_argument, NULL, 'e' },
        { "dnssec", no_argument, NULL, 'd' },
        { "dnskey", required_argument, NULL, 'D' },
        { NULL, }
};



/* Initialize a struct timeval by converting milliseconds */
static void
msecstotv(time_t msecs, struct timeval *tv)
{
	tv->tv_sec  = msecs / 1000;
	tv->tv_usec = msecs % 1000 * 1000;
}


/* Lookup for a query by its index */
static struct query*
tdig_lookup_query( int index)
{
	struct query_state *qry;

	qry = base->qry_head;
	if (!qry)
		goto done;
	do {
		if (qry->index == index)
		  return qry;
		qry = qry->next;
	} while (qry != base->qry_head);
done:
	return NULL;
}


static void fmt_dns_query(u_char *buf, unsigned size, uint32_t index)
{
	u_char *qname;
        struct QUESTION *qinfo = NULL;
        struct EDNS0_HEADER *e;
        int r;
	unsigned char lookupname[32];
	u_int16_t qtype;
 	u_int16_t qclass;


	/* Temp AA  */
	strcpy(lookupname , "hostname.bind.");
	qtype = T_TXT; /* TEXT */
        qclass = C_CHAOS;
	int opt_edns0 = 0;
	
	//point to the query portion
        qname =(u_char *)&buf[sizeof(struct DNS_HEADER)];
	ChangetoDnsNameFormat(qname, lookupname); // fill the query portion.

	

        qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; 
        size = (strlen((const char*)qname) + 1);

        qinfo->qtype = htons(qtype);
        qinfo->qclass = htons(qclass);
	
	e=(struct EDNS0_HEADER*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + sizeof(struct QUESTION) + 2 ) ]; //fill it

        e->qtype = htons(ns_t_opt);
        e->_edns_udp_size = htons(opt_edns0);
        //e->_edns_z = htons(128);
        //if(opt_dnssec  == 1)
        {
                e->DO = 0x80;
        }
        e->len = htons(0);
        return ;
}

/* Attempt to transmit an ICMP Echo Request to a given qry */
static void tdig_send_query_callback(int unused, const short event, void *h)
{
	struct query_state *qry = h;
	struct tdig_base *base = qry->base;

	u_char packet [MAX_DNS_BUF_SIZE] ;
	int nsent;

	/* Clean the no reply timer (if any was previously set) */
	evtimer_del(&qry->noreply_timer);

	bzero(packet, MAX_DNS_BUF_SIZE);
	/* Format the DNS Qeury packet to send */

	
	struct DNS_HEADER *dns = NULL;
	dns = (struct DNS_HEADER *)&packet;
	
	int r;
        r =  rand();
        r %= 65535;
	dns->id = (unsigned short) r;
        dns->qr = 0; //This is a query
        dns->opcode = 0; //This is a standard query
        dns->aa = 0; //Not Authoritative
        dns->tc = 0; //This message is not truncated
        dns->rd = 0; //Recursion  not Desired
        dns->ra = 0; //Recursion not available! hey we dont have it (lol)
        dns->z = 0;
        dns->ad = 0;
        dns->cd = 0;
        dns->rcode = 0;
        dns->q_count = htons(1); //we have only 1 question
        dns->ans_count = 0;
        dns->auth_count = 0;
        dns->add_count = htons(0);

	fmt_dns_query(packet, base->pktsize, qry->index);
	base->pktsize += sizeof(struct DNS_HEADER) + sizeof(struct QUESTION) + sizeof(struct EDNS0_HEADER) ;
	/* Transmit the request over the network */

	nsent = sendto(base->rawfd, packet,base->pktsize, MSG_DONTWAIT, qry->res->ai_addr, qry->res->ai_addrlen);

	if (nsent == base->pktsize)
	  {
	    /* One more DNS Query is sent */
	    base->sentok++;

	    if (!qry->sentpkts && !base->quiet)
	      printf("PING %s (%s) %d(%d) bytes of data.\n", qry->fqname, qry->ipname,
		     base->pktsize - ICMP_MINLEN, nsent + IPHDR);

	    /* Update timestamps and counters */
	    if (!qry->sentpkts)
	      gettimeofday(&qry->firstsent, NULL);
	    gettimeofday (&qry->lastsent, NULL);
	    qry->sentpkts++;
	    qry->sentbytes += nsent;

	    /* Add the timer to handle no reply condition in the given timeout */
	    evtimer_add(&qry->noreply_timer, &base->tv_noreply);
	  }
	else 
	  {
	  	base->sendfail++;
		 //perror("send");

	  }
}


/* The callback to handle timeouts due to destination host unreachable condition */
static void noreply_callback(int unused, const short event, void *h)
{
	struct query_state *qry = h;

	qry->dropped++;

	/* Add the timer to ping again the host at the given time interval */
	evtimer_add(&qry->nsm_timer, &qry->base->tv_interval);

	/*
	if (qry->user_callback)
	  qry->user_callback(PING_ERR_TIMEOUT, -1, qry->fqname, qry->ipname,
			      qry->seq, -1, &qry->base->tv_noreply, qry->user_pointer);
	*/

	/* Update the sequence number for the next run */
	qry->seq = (qry->seq + 1) % 256;
}


/*
 * Called by libevent when the kernel says that the raw socket is ready for reading.
 *
 * It reads a packet from the wire and attempt to decode and relate DNS Request/Reply.
 *
 * To be legal the packet received must be:
 *  o of enough size (> IPHDR + ICMP_MINLEN)
 *  o of ICMP Protocol
 *  o of type ICMP_ECHOREPLY
 *  o the one we are looking for (matching the same identifier of all the packets the program is able to send)
 */
static void ready_callback (int unused, const short event, void * arg)
{
	struct tdig_base *base = arg;

	int nrecv;
	u_char packet[MAX_DNS_BUF_SIZE];
	struct sockaddr_in remote;                  /* responding internet address */
	socklen_t slen = sizeof(struct sockaddr);

	/* Pointer to relevant portions of the packet (IP, ICMP and user data) */
	struct ip * ip = (struct ip *) packet;
	struct icmphdr * icmp;
	struct evdata * data = (struct evdata *) (packet + IPHDR + ICMP_MINLEN);
	int hlen = 0;

	struct timeval now;
	struct query_state * qry;

	/* Time the packet has been received */
	gettimeofday(&now, NULL);

	EVPING_LOCK(base);

	/* Receive data from the network */
	nrecv = recvfrom(base->rawfd, packet, sizeof(packet), MSG_DONTWAIT, (struct sockaddr *) &remote, &slen);
	if (nrecv < 0)
	{
		/* One more failure */
		base->recvfail++;
		goto done;
	}

	/* One more ICMP packect received */
	base->recvok++; 

	/* Get the pointer to the qry descriptor in our internal table */
	qry = tdig_lookup_query( data->index);
	if ( ! qry) 
		goto done;

	/* Use the User Data to relate Echo Request/Reply and evaluate the Round Trip Time */
	struct timeval elapsed;             /* response time */
	time_t usecs;

	/* Compute time difference to calculate the round trip */
	evutil_timersub (&now, &data->ts, &elapsed);

	/* Update timestamps */
	if (!qry->recvpkts)
		gettimeofday (&qry->firstrecv, NULL);
	gettimeofday (&qry->lastrecv, NULL);
	qry->recvpkts++;
	qry->recvbytes += nrecv;

	/* Update counters */
	usecs = tvtousecs(&elapsed);

	/*
	   if (qry->user_callback)
	   qry->user_callback(PING_ERR_NONE, nrecv - IPHDR, qry->fqname, qry->ipname,
	   ntohs(icmp->un.echo.sequence), ip->ip_ttl, &elapsed, qry->user_pointer);
	 */

	/* Clean the noreply timer */
	evtimer_del(&qry->noreply_timer);

	/* Add the timer to nsm again the qry at the given time interval */
	evtimer_add(&qry->nsm_timer, &qry->base->tv_interval);


	/* Handle this condition exactly as the request has expired */
	// noreply_callback (-1, -1, qry);

done:
	EVPING_UNLOCK(base);
}

static void *tdig_init(int __attribute((unused)) argc, char *argv[])
{
	char *str_Atlas;
        const char *hostname;
	char *check;
        char *out_filename;
        struct query_state *qry;
	int c;
	if(!base)
		base = tdig_base_new(EventBase);
	if(!base)
		crondlog(DIE9 "tdig_base_new failed");

	 qry=xzalloc(sizeof(*qry));

	int opt_v4_only, opt_v6_only;
	opt_v4_only =  opt_v6_only = 0;

        while (c= getopt_long(argc, argv, "46dD:e:tbhirs:A:?", longopts, NULL), c != -1)
        {
                switch(c)
                {
                        case '4':
                                qry->opt_v4_only = 1;
                                break;
                        case '6':
                                qry->opt_v6_only = 1;
                                break;
                        case 'A':
                                qry->atlas_Str = strdup(optarg);
                                break;
                        case 'b':
				qry->lookupname  = strdup ("version.bind.");
                                break;
                        case 'D':
                                qry->qtype = T_DNSKEY;
                                qry->qclass = C_IN;
                                if(qry->opt_edns0 == 0)
                                        qry->opt_edns0 = 512;
                                qry->opt_dnssec = 1;
                                qry->lookupname  = strdup(optarg);
                                break;

                        case 'd':
                                qry->opt_dnssec = 1;
                                if(qry->opt_edns0 == 0)
                                        qry->opt_edns0 = 512;
                                break;
                        case 'e':
                                qry->opt_edns0= strtoul(optarg, &check, 10);
                                break;
                        case 'h':
				qry->lookupname = strdup("hostname.bind.");
                                break;
                        case 'i':
				qry->lookupname = strdup("id.server.");
                                break;
                        case 'r':
				qry->lookupname = strdup("version.server.");
                                break;
			case 's':
                                qry->qtype = T_SOA;
                                qry->qclass = C_IN;
                                qry->lookupname =  strdup(optarg);
                                break;
                        case 't':
                                qry->opt_tcp = 1;
                        break;

                        default:
                                fprintf(stderr, "ERROR unknown option %d \n");
                                return (0);
                }
        }
	 if (optind != argc-1)
		crondlog(DIE9 "exactly one server IP address expected");
        qry->server_ip_str = strdup(argv[optind]);

      return qry;
}


/* exported function */
struct tdig_base *
tdig_base_new(struct event_base *event_base)
{
	struct protoent *proto;
	evutil_socket_t fd;
	struct tdig_base *base;

	 base= xzalloc(sizeof(*base));
	 base->event_base= event_base;

	struct addrinfo hints;

	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_flags = 0;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = 0;


	/* Create an endpoint for communication using raw socket for ICMP calls */
	if ((fd = socket(hints.ai_family, hints.ai_socktype, hints.ai_protocol) ) < 0 )
	{
	  return NULL;
	} 

	base = mm_malloc(sizeof(struct tdig_base));
	if (base == NULL)
		return (NULL);
	memset(base, 0, sizeof(struct tdig_base));

	EVTHREAD_ALLOC_LOCK(base->lock, EVTHREAD_LOCKTYPE_RECURSIVE);
	EVPING_LOCK(base);

	base->event_base = event_base;

	base->rawfd = fd;
	evutil_make_socket_nonblocking(base->rawfd);

	/* Set default values */
	base->pktsize = DEFAULT_PKT_SIZE;
	//base->pid = getpid();

	msecstotv(DEFAULT_NOREPLY_TIMEOUT, &base->tv_noreply);
	msecstotv(DEFAULT_PING_INTERVAL, &base->tv_interval);

	/* Define the callback to handle ICMP Echo Reply and add the raw file descriptor to those monitored for read events */
	event_add(&base->event, NULL);

	EVPING_UNLOCK(base);
	return base;
}

void tdig_base_free(struct tdig_base *base, int fail_requests)
{
	EVPING_LOCK(base);

	EVPING_UNLOCK(base);
	EVTHREAD_FREE_LOCK(base->lock, EVTHREAD_LOCKTYPE_RECURSIVE);

	mm_free(base);
}

void tdig_start (struct query_state *qry)
{
	struct querystent *h;

	int err_num;
	struct addrinfo hints, *res;

	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_family = AF_INET;	
	hints.ai_flags = 0;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = 0;
	char port[] = "domain";

	if ( ( err_num  = getaddrinfo(qry->server_ip_str, port , &hints, &res)))
	{
		printf("%s ERROR port %s %s\n", qry->server_ip_str, port, gai_strerror(err_num));
		return -1;
	}

	qry = (struct query_state *) mm_malloc(sizeof(struct query_state));
	if (!qry) return -1;

	memset(qry, 0, sizeof(struct query_state));

	EVPING_LOCK(base);

	qry->res = res;
	qry->ressave = res;

	//AA  qry->index = base->argc;  //aa index needs replacing
	qry->seq = 1;

	/* Define here the callbacks to nsm  the query and to handle no reply timeouts */
	evtimer_assign(&qry->nsm_timer, base->event_base, tdig_send_query_callback, qry);
	evtimer_assign(&qry->noreply_timer, base->event_base, noreply_callback, qry);

	/* insert this nameserver into the list of them */
	if (!base->qry_head) {
	  qry->next = qry->prev = qry;
	  base->qry_head = qry;
	} else {
	  qry->next = base->qry_head->next;
	  qry->prev = base->qry_head;
	  base->qry_head->next = qry;
	  if (base->qry_head->prev == base->qry_head) {
	    base->qry_head->prev = qry;
	  }
	}
	EVPING_UNLOCK(base);
	return 0;
}

/*


int tdig_base_count_queries(struct tdig_base *base)
{
	const struct query_state *qry;
	int n = 0;

	EVPING_LOCK(base);
	qry = base->qry_head;
	if (!qry)
		goto done;
	do {
		++n;
		qry = qry->next;
	} while (qry != base->qry_head);
done:
	EVPING_UNLOCK(base);
	return n;
}


/* exported function */
void
tdig_stats(struct tdig_base *base)
{
}


/* exported function */
const char *
tdig_err_to_string(int err)
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
/*
time_t
tvtousecs (struct timeval *tv)
{
	return tv->tv_sec * 1000000.0 + tv->tv_usec;
} 
*/


static void ChangetoDnsNameFormat(u_char *  dns,unsigned char* qry)
{
	char *s;
	s = dns;
	int lock = 0 , i;
	for(i = 0 ; i < (int)strlen((char*)qry) ; i++)
	{
		//printf ("%c", qry[i] );
		if(qry[i]=='.')
		{
			*dns++=i-lock;
			for(;lock<i;lock++) {
				*dns++=qry[lock];
			}
			lock++; //or lock=i+1;
		}
	}
	*dns++=0;
}


static int tdig_delete(void *state)
{
        struct query_state *qry;

        qry= state;

/*
        free(trtstate->atlas);
        trtstate->atlas= NULL;
        free(trtstate->hostname);
        trtstate->hostname= NULL;
        free(trtstate->out_filename);
        trtstate->out_filename= NULL;

*/
        free(qry);

        return qry;
}

struct testops tdig_ops = { tdig_init, tdig_start, tdig_delete };
