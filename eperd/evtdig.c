/*
 * Copyright (c) 2011 RIPE NCC, Antony Antony <antony@ripe.net>, <atlas@ripe.net>
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
#include "eping.h"

#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/dns.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>
#define DQ(str) "\"" #str "\""
#define DQC(str) "\"" #str "\" : "
#define JS(key, val) fprintf(fh, "\"" #key"\" : \"%s\" , ",  val); 
#define JD(key, val) fprintf(fh, "\"" #key"\" : \"%d\" , ",  val); 
#define JLD(key, val) fprintf(fh, "\"" #key"\" :  %ld , ",  val); 

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
#define MAX_DNS_BUF_SIZE   2048

/* Intervals and timeouts (all are in milliseconds unless otherwise specified) */
#define DEFAULT_NOREPLY_TIMEOUT 100            /* 100 msec - 0 is illegal      */
#define DEFAULT_PING_INTERVAL   1000           /* 1 sec - 0 means flood mode   */

// seems T_DNSKEY is not defined header files of lenny and sdk
#ifndef ns_t_dnskey
#define ns_t_dnskey   48
#endif

#ifndef T_DNSKEY
#define T_DNSKEY ns_t_dnskey
#endif

//static uint32_t fmt_dns_query(u_char *buf, struct query_state *qry);
static void ChangetoDnsNameFormat(u_char * dns,unsigned char* qry) ;
struct tdig_base *tdig_base_new(struct event_base *event_base); 
void readcb_tcp(struct bufferevent *bev, void *ptr);
void eventcb_tcp(struct bufferevent *bev, short events, void *ptr);

/* Definition for various types of counters */
typedef uint64_t counter_t;

/* How to keep track of a DNS query session */
struct tdig_base {
	struct event_base *event_base;

	evutil_socket_t rawfd_v4;       /* Raw socket used to nsm hosts              */

	struct timeval tv_noreply;     /* DNS query Reply timeout                    */
	struct timeval tv_interval;    /* between two subsequent queries */

	/* A circular list of user queries */
	struct query_state *qry_head;

	struct event event;            /* Used to detect read events on raw socket   */

	counter_t sendfail;            /* # of failed sendto()                       */
	counter_t sentok;              /* # of successful sendto()                   */
	counter_t recvfail;            /* # of failed recvfrom()                     */
	counter_t recvok;              /* # of successful recvfrom()                 */
	counter_t foreign;             /* # of DNS replies we are not looking for   */
	counter_t illegal;             /* # of DNS packets with an illegal payload  */
	counter_t sentbytes; 
	counter_t recvtbytes; 
	
	/* used only for the stand alone version */
	void (*done)(void *state);
};

static struct tdig_base *tdig_base;

/* How to keep track of each user query to send dns query */
static struct query_state {

	struct tdig_base *base;
	char * name;                /* Host identifier as given by the user */
	char * fqname;              /* Full qualified hostname          */ 
	char * ipname;              /* Remote address in dot notation   */
	u_int16_t qryid;             /* query id 16 bit */
	int tcp_fd;
	FILE *tcp_file;

	struct bufferevent *bev_tcp;

	int opt_v4_only ;
	int opt_v6_only ;
	int opt_proto;
	int opt_edns0;
	int opt_dnssec;
	
	char * str_Atlas; 
	u_int16_t qtype;
	u_int16_t qclass;
	
	unsigned char *lookupname;
	char * server_name;
	char *out_filename ;

	uint32_t pktsize;              /* Packet size in bytes */
	struct addrinfo *res, *ressave, *ressent;
	
	struct sockaddr_in remote;     /* store the reply packet src address      */


	struct event noreply_timer;    /* Timer to handle timeout            */
	struct event nsm_timer;        /* Timer to next query intervals   */
	struct timeval xmit_time;	
	double triptime;

	/* Packets Counters */
	counter_t sentpkts;            /* Total # of DNS queries sent      */
	counter_t recvpkts;            /* Total # of DNS replies received   */
	counter_t dropped;             /* # of unanswered queries 		  */

	/* Bytes counters */
	counter_t sentbytes;           /* Total # of bytes sent                   */
	counter_t recvbytes;           /* Total # of bytes received               */


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

static struct option longopts[]=
{
        { "hostname-bind", no_argument, NULL, 'h' },
        { "id-server", no_argument, NULL, 'i' },
        { "version-bind", no_argument, NULL, 'b' },
        { "version.server", no_argument, NULL, 'r' },
        { "soa", required_argument, NULL, 's' },
        { "out-file", required_argument, NULL, 'O' },
        { "edns0", required_argument, NULL, 'e' },
        { "dnssec", no_argument, NULL, 'd' },
        { "dnskey", required_argument, NULL, 'D' },
        { NULL, }
};

static void done(void *state UNUSED_PARAM)
{
        //fprintf(stderr, "And we are done\n");
        exit(0);
}

static int tdig_delete(void *state);
static void *tdig_init(int argc, char *argv[], void (*done)(void *state));
int evtdig_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int evtdig_main(int argc, char **argv) 
{ 
	int r;
	EventBase=event_base_new();
	if (!EventBase)
	{
		crondlog(DIE9 "event_base_new failed"); /* exits */
	}

	//DnsBase = evdns_base_new(EventBase, 1);
	struct query_state *qry;
	qry = tdig_init(argc, argv, done);
	if (!qry)
	{
		crondlog(DIE9 "new query state failed"); /* exits */
	}

	tdig_start(qry);  
	printf ("starting query\n");

   event_base_dispatch (EventBase);
   event_base_loopbreak (EventBase);
}

/* Initialize a struct timeval by converting milliseconds */
static void
msecstotv(time_t msecs, struct timeval *tv)
{
	tv->tv_sec  = msecs / 1000;
	tv->tv_usec = msecs % 1000 * 1000;
}


/* Lookup for a query by its index */
static struct query* tdig_lookup_query( int index)
{ 
	struct query_state *qry;

	qry = tdig_base->qry_head;
	if (!qry)
		goto done;
	do {
		if (qry->qryid == index)
		{
			//AA chnage to LVL5
			crondlog(LVL9 "found matching query id %d", index);
			
			return qry;
		}
		qry = qry->next;
	} while (qry != tdig_base->qry_head);
done:
	return NULL;

}


static uint32_t fmt_dns_query(u_char *buf, struct query_state *qry)
{
	u_char *qname;
        struct QUESTION *qinfo = NULL;
        struct EDNS0_HEADER *e;
        int r;
	uint32_t  size = 0;


	//point to the query portion
        qname =(u_char *)&buf[sizeof(struct DNS_HEADER)];
	ChangetoDnsNameFormat(qname, qry->lookupname); // fill the query portion.

        qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; 
        size = (strlen((const char*)qname) + 1);

        qinfo->qtype = htons(qry->qtype);
        qinfo->qclass = htons(qry->qclass);
	
	e=(struct EDNS0_HEADER*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + sizeof(struct QUESTION) + 2 ) ]; //fill it

        e->qtype = htons(qry->qtype);
        e->_edns_udp_size = htons(qry->opt_edns0);
        //e->_edns_z = htons(128);
        //if(opt_dnssec  == 1)
        {
                e->DO = 0x80;
        }
        e->len = htons(0);
        return size ;
}

/* Attempt to transmit an DNS Request a given qry to a server*/
static void tdig_send_query_callback(int unused, const short event, void *h)
{
	struct query_state *qry = h;
	struct tdig_base *base = qry->base;

	u_char packet [MAX_DNS_BUF_SIZE] ;
	uint32_t nsent;

	/* Clean the no reply timer (if any was previously set) */
	evtimer_del(&qry->noreply_timer);

	bzero(packet, MAX_DNS_BUF_SIZE);
	/* Format the DNS Qeury packet to send */


	struct DNS_HEADER *dns = NULL;
	dns = (struct DNS_HEADER *)&packet;

	int r;
	srand ( time(NULL) );
	r =  rand();
	r %= 65535;
	qry->qryid = (uint16_t) r; // host is storing int host byte order
	dns->id = (uint16_t) htons(r); 
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
	qry->pktsize = fmt_dns_query(packet, qry);
	qry->pktsize += sizeof(struct DNS_HEADER) + sizeof(struct QUESTION) + sizeof(struct EDNS0_HEADER) ;

	/* Transmit the request over the network */

	if(qry->opt_proto == 17)  //UDP 
	{
		do
		{
			gettimeofday(&qry->xmit_time, NULL);
			nsent = sendto(base->rawfd_v4, packet,qry->pktsize, MSG_DONTWAIT, qry->res->ai_addr, qry->res->ai_addrlen);

			if (nsent == qry->pktsize)
			{
				/* One more DNS Query is sent */
				base->sentok++;
				base->sentbytes+=nsent;

				qry->sentpkts++;
				qry->sentbytes += nsent;
				qry->ressent = qry->res;

				/* Add the timer to handle no reply condition in the given timeout */
				evtimer_add(&qry->noreply_timer, &base->tv_noreply);
			}
			else 
			{
				base->sendfail++;
				//perror("send");
			}
		} while ((qry->res = qry->res->ai_next) != NULL);
	}
	else{ //TCP yet to be complted.
		uint8_t wire[1300];
		int wire_wrote = 0;
		/*
		   qry->tcp_fd= connect_to_tcp(qry);
		   if (qry->tcp_fd == -1)
		   {
		   crondlog(DIE9 "%s UNABLE-TO-CONNECT-TCP-ERROR\n", qry->server_name);
		// goto err;
		}

		// Stdio makes life easy
		qry->tcp_file= fdopen(qry->tcp_fd, "r+");
		if (qry->tcp_file == NULL)
		{
		printf ("fdopen failed");
		// sprintf (errstr, "fdopen failed");
		crondlog(DIE9 "fdopen failed %s", qry->server_name);
		// goto err;
		}

		 */
		qry->bev_tcp =  bufferevent_socket_new(qry->base, -1, BEV_OPT_CLOSE_ON_FREE);
		bufferevent_setcb(qry->bev_tcp, readcb_tcp, NULL, eventcb_tcp, qry);
		int rc;
		bufferevent_socket_connect_hostname(qry->bev_tcp, NULL, AF_UNSPEC, qry->server_name, 53);
		if(rc < 0) {
			crondlog(LVL9 "error in hostname %s", qry->server_name);
		}

		crondlog(LVL9 "dispatched tcp callback %s", qry->server_name);

		/*
		   qry->tcp_fd= -1;
		   ldns_write_uint16(wire, qry->pktsize );
		   memcpy(wire + 2, packet, qry->pktsize);
		   wire_wrote = fwrite(wire, (qry->pktsize+2), 1, qry->tcp_file);
		   fflush( qry->tcp_file);
		   crondlog(LVL9 "send packet to %s wrote %d len %d", qry->server_name, wire_wrote, (qry->pktsize + 2));
		 */
	}
}

void readcb_tcp(struct bufferevent *bev, void *ptr)
{
    char buf[1024];
    int n;
    struct evbuffer *input = bufferevent_get_input(bev);
    while ((n = evbuffer_remove(input, buf, sizeof(buf))) > 0) {
        fwrite(buf, 1, n, stdout);
    }
}

void eventcb_tcp(struct bufferevent *bev, short events, void *ptr)
{
	struct query_state *qry = ptr;

    if (events & BEV_EVENT_CONNECTED) {
        printf("Connect okay.\n");
    } else if (events & (BEV_EVENT_ERROR|BEV_EVENT_EOF)) {
         struct event_base *base = ptr;
         if (events & BEV_EVENT_ERROR) {
                 int err = bufferevent_socket_get_dns_error(bev);
                 if (err)
                         printf("DNS error: %s\n", evutil_gai_strerror(err));
         }
         printf("Closing\n");
         bufferevent_free(bev);
         event_base_loopexit(base, NULL);
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

}

/*
 * Called by libevent when the kernel says that the raw socket is ready for reading.
 *
 * It reads a packet from the wire and attempt to decode and relate DNS Request/Reply.
 *
 * To be legal the packet received must be:
 *  o of enough size (> DNS Header size)
 *  o the one we are looking for (matching the same identifier of all the packets the program is able to send)
 */
static void ready_callback (int unused, const short event, void * arg)
{
	struct tdig_base *base = arg;

	int nrecv;
	struct DNS_HEADER *dnsR = NULL;
	u_char packet[MAX_DNS_BUF_SIZE];
	struct sockaddr_in remote;                  /* responding internet address */
	socklen_t slen = sizeof(struct sockaddr);
	bzero(packet, MAX_DNS_BUF_SIZE);

	struct timeval now;
	struct query_state * qry;

	/* Time the packet has been received */
	gettimeofday(&now, NULL);

	/* Receive data from the network */
	nrecv = recvfrom(base->rawfd_v4, packet, sizeof(packet), MSG_DONTWAIT, (struct sockaddr *) &remote, &slen);
	if (nrecv < 0)
	{
		/* One more failure */
		base->recvfail++;
		goto done;
	} 

	dnsR = (struct DNS_HEADER*) packet;
		/* One more ICMP packect received */
	base->recvok++; 

	/* Get the pointer to the qry descriptor in our internal table */
	qry = tdig_lookup_query( ntohs(dnsR->id));

	if ( ! qry) 
		goto done;

	/* Use the User Data to relate Echo Request/Reply and evaluate the Round Trip Time */

	qry->recvpkts++;
	qry->recvbytes += nrecv;
	qry->triptime = (now.tv_sec-qry->xmit_time.tv_sec)*1000 +
                                (now.tv_usec-qry->xmit_time.tv_usec)/1e3;
	printReply(packet, nrecv, qry );

	/* Clean the noreply timer */
	evtimer_del(&qry->noreply_timer);
	if(base->done)
		{
			tdig_delete(qry);
			base->done(qry);
		}

done:
  return;
} 


static void *tdig_init(int argc, char *argv[], void (*done)(void *state))
{
        const char *hostname;
	char *check;
        struct query_state *qry;
	int c;


	if(!tdig_base)
		tdig_base = tdig_base_new(EventBase);

	if(!tdig_base)
		crondlog(DIE9 "tdig_base_new failed");

	tdig_base->done = done;

	 qry=xzalloc(sizeof(*qry));
	int opt_v4_only, opt_v6_only;
	opt_v4_only =  opt_v6_only = 0;
	

	bzero(qry, sizeof(*qry));
	// initialize per query state variables;
	qry->qtype = T_TXT; /* TEXT */
        qry->qclass = C_CHAOS;
	qry->opt_v4_only = 1; 
	qry->opt_v6_only = 1; 
	qry->str_Atlas = NULL;
	qry->out_filename = NULL;
	qry->opt_proto = 17; 
	qry->tcp_file = NULL;
	qry->tcp_fd = -1;
	qry->server_name = NULL;
	qry->str_Atlas = NULL;

	optind = 0;
        while (c= getopt_long(argc, argv, "46dD:e:tbhiO:rs:A:?", longopts, NULL), c != -1)
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
                                qry->str_Atlas = strdup(optarg);
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

			case 'O':
				qry->out_filename = strdup(optarg);
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
                                qry->opt_proto = 6;
                        break;

                        default:
                                fprintf(stderr, "ERROR unknown option 0%o ??\n", c); 
				break;
                                return (0);
                }
        }
	 if (optind != argc-1)
		crondlog(DIE9 "exactly one server IP address expected");
        qry->server_name = strdup(argv[optind]);
	qry->base = tdig_base;

      return qry;
}

/* exported function */
struct tdig_base *
tdig_base_new(struct event_base *event_base)
{
	struct protoent *proto;
	evutil_socket_t fd;
	struct tdig_base *tdig_base;
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

	tdig_base= xzalloc(sizeof( struct tdig_base));
	if (tdig_base == NULL)
		return (NULL);

	memset(tdig_base, 0, sizeof(struct tdig_base));
	tdig_base->event_base = event_base;

	tdig_base->rawfd_v4 = fd;
	evutil_make_socket_nonblocking(tdig_base->rawfd_v4); 

	msecstotv(DEFAULT_NOREPLY_TIMEOUT, &tdig_base->tv_noreply);
	msecstotv(DEFAULT_PING_INTERVAL, &tdig_base->tv_interval);

	// Define the callback to handle UDP Reply 
	// add the raw file descriptor to those monitored for read events 

	event_assign(&tdig_base->event, tdig_base->event_base, tdig_base->rawfd_v4, EV_READ | EV_PERSIST, ready_callback, tdig_base);
	event_add(&tdig_base->event, NULL);

	return tdig_base;
}

void tdig_base_free(struct tdig_base *base, int fail_requests)
{

	free(base);
}

void tdig_start (struct query_state *qry)
{
	struct querystent *h;
	struct timeval asap = { 0, 0 };

	int err_num;
	struct addrinfo hints, *res;

	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_family = AF_INET;	
	hints.ai_flags = 0;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = 0;
	char port[] = "domain";

	if ( ( err_num  = getaddrinfo(qry->server_name, port , &hints, &res)))
	{
		printf("%s ERROR port %s %s\n", qry->server_name, port, gai_strerror(err_num));
		return -1;
	}

	qry->res = res;
	qry->ressave = res;

	/* insert this nameserver into the list of them */
	if (!tdig_base->qry_head) {
	  qry->next = qry->prev = qry;
	  tdig_base->qry_head = qry;
	} else {
	  qry->next = tdig_base->qry_head->next;
	  qry->prev = tdig_base->qry_head;
	  tdig_base->qry_head->next = qry;
	  if (tdig_base->qry_head->prev == tdig_base->qry_head) {
	    tdig_base->qry_head->prev = qry;
	  }
	}
	/* initialize callbacks: no reply timeout and sendpacket */
	evtimer_assign(&qry->nsm_timer, tdig_base->event_base, tdig_send_query_callback, qry);
	evtimer_assign(&qry->noreply_timer, tdig_base->event_base, noreply_callback, qry); 

 	evtimer_add(&qry->nsm_timer, &asap);
	return 0;
}

int tdig_base_count_queries(struct tdig_base *base)
{
	const struct query_state *qry;
	int n = 0;

	qry = base->qry_head;
	if (!qry)
		goto done;
	do {
		++n;
		qry = qry->next;
	} while (qry != base->qry_head);
done:
	return n;
}


/* exported function */
void
tdig_stats(struct tdig_base *base)
{
}

const char * tdig_err_to_string(int err)
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

	qry = state;

	if(qry->out_filename)
	{ 
			free(qry->out_filename);
			qry->out_filename = NULL ;
	}
	if(qry->lookupname) 
	{
		free(qry->lookupname);
		qry->lookupname = NULL;
	}
	if( qry->str_Atlas) 
	{
		free( qry->str_Atlas);
		 qry->str_Atlas = NULL;
	}
	if(qry->server_name)
	{
		free(qry->server_name);
		qry->server_name = NULL;
	}
		

	if(qry->ressave )
	{ 
		freeaddrinfo(qry->ressave);
		qry->ressave  = NULL;
	}

	/*
	   free(trtstate->atlas);
	   trtstate->atlas= NULL;
	   free(trtstate->hostname);
	   trtstate->hostname= NULL;
	   free(trtstate->out_filename);
	   trtstate->out_filename= NULL;

	 */
	free(qry);
	return 1;
} 

void printReply(unsigned char *result, int wire_size, struct query_state *qry ) 
{
	int i, stop=0;
	unsigned char *qname, *reader;
	struct DNS_HEADER *dnsR = NULL;
	struct RES_RECORD answers[20]; //the replies from the DNS server
	void *ptr;
	char addrstr[100];
	FILE *fh; 


	if (qry->out_filename)
	{
		fh= fopen(qry->out_filename, "a");
		if (!fh)
			crondlog(DIE9 "unable to append to '%s'",
					qry->out_filename);
	}
	else
		fh = stdout;

	dnsR = (struct DNS_HEADER*) result;

	//point to the query portion
	qname =(unsigned char*)&result[sizeof(struct DNS_HEADER)];

	//move ahead of the dns header and the query field
	reader = &result[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];


	// print results 
	// non packet 
	
	fprintf(fh, "{ ");
	if(qry->str_Atlas) 
	{
		
		//fprintf(fh, DQC(id)  DQ(%s) DQC(time) DQ(%ld) "," , qry->str_Atlas, qry->xmit_time.tv_sec);
		JS(id, qry->str_Atlas);
		JLD(time, qry->xmit_time.tv_sec);

	}
	JS(name,  qry->server_name);
	JD(pf, qry->ressent->ai_family == PF_INET6 ? 6 : 4);
	JS(proto, qry->opt_proto == 6 ? "TCP" : "UDP" );
	switch (qry->ressent->ai_family)
	{
		case AF_INET:
			ptr = &((struct sockaddr_in *) qry->ressent->ai_addr)->sin_addr;
			break;
		case AF_INET6:
			ptr = &((struct sockaddr_in6 *) qry->ressent->ai_addr)->sin6_addr;
			break;
	}
	inet_ntop (qry->ressent->ai_family, ptr, addrstr, 100);
	fprintf(fh, " , \"address\" : \"%s\"", addrstr);

	fprintf (fh, " , \"result\" : { ");
	fprintf (fh, " \"rt\" : %.3f", qry->triptime);
	fprintf (fh, " , \"ID\" : %d", ntohs(dnsR->id));
	// results from reply received 
	stop=0;  
	fprintf (fh, " , \"size\" : %d", wire_size);
	fprintf (fh, " , \"TC\" : %d",  dnsR->tc);
	fprintf (fh, " , \"ANCOUNT\" : %d ", ntohs(dnsR->ans_count ));
	fprintf (fh, " , \"QDCOUNT\" : %u ",ntohs(dnsR->q_count));
	fprintf (fh, " , \"AA\" : %d" , ntohs(dnsR->auth_count));
	fprintf (fh, " , \"ARCOUNT\" : %d",ntohs(dnsR->add_count));

	if (dnsR->ans_count > 0)
	{
		for(i=0;i<ntohs(dnsR->ans_count);i++)
		{
			answers[i].name=ReadName(reader,result,&stop);
			reader = reader + stop;

			answers[i].resource = (struct R_DATA*)(reader);
			reader = reader + sizeof(struct R_DATA);
		}

		fprintf (fh, ", \"answers\" : [ ");
		//print answers
		for(i=0;i<ntohs(dnsR->ans_count);i++)
		{
			answers[i].rdata  = NULL;

			if(ntohs(answers[i].resource->type)==T_TXT) //txt
			{
				fprintf(fh, " \"TYPE\" : \"TXT\"");
				fprintf(fh, " , \"NAME\" : \"%s\" ",answers[i].name);
				answers[i].rdata = ReadName(reader,result,&stop);
				reader = reader + stop;

				answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
				fprintf(fh, " , \"RDATA\" : \"%s\"", answers[i].rdata);
			}
			else if (ntohs(answers[i].resource->type)== T_SOA)
			{
				fprintf(fh, " \"TYPE\" : \"SOA\"");
				fprintf(fh, " , \"NAME\" : \"%s\" ",answers[i].name);
				answers[i].rdata = ReadName(reader,result,&stop);
				//printf(" %s", answers[i].rdata);
				reader =  reader + stop;
				free(answers[i].rdata);
				answers[i].rdata = ReadName(reader,result,&stop);
				//printf(" %s", answers[i].rdata);
				reader =  reader + stop;
				u_int32_t serial;
				serial = get32b(reader);
				fprintf(fh, " , \"SERIAL\" : %u", serial);
				reader =  reader + 4;
			}
			else if (ntohs(answers[i].resource->type)== T_DNSKEY)
			{
				fprintf(fh, " \"TYPE\" : \"DNSKEY\"");
			}
			else  
			{

				fprintf(fh, " \"TYPE\" : %u", ntohs(answers[i].resource->type));
				fprintf(fh, " , \"error\" : \"UNKNOWN\"");
				fprintf(fh, " , \"len\" : %u", answers[i].resource->data_len );
			}
			fflush(stdout);

			// free mem 
			if(answers[i].rdata != NULL) 
				free (answers[i].rdata); 
		} 
		fprintf (fh, " ]");
	}

	for(i=0;i<ntohs(dnsR->ans_count);i++)
	{
		free(answers[i].name);
	}

	fprintf (fh , " }"); //result
	fprintf(fh, " }");
	fprintf(fh, "\n");
	if (qry->out_filename)
                fclose(fh);
}

int connect_to_tcp(struct query_state *qry)
{
	int r, s, s_errno;
	//struct addrinfo *res, *aip;
	struct addrinfo  *aip;
	struct addrinfo hints;
	char addrstr[100];
	void *ptr;
	struct addrinfo *res;
 	char port[] = "domain";	

	memset(&hints, '\0', sizeof(hints));
	hints.ai_socktype= SOCK_STREAM;
	r= getaddrinfo(qry->server_name, port, &hints, &res);
	if (r != 0)
	{
		crondlog(DIE9 "unable to resolve %s : %s", qry->server_name, 
			gai_strerror(r));
		return (-1);
	}
	qry->res = res;
        qry->ressave = res;

	s_errno= 0;
	s= -1;
	for (aip= res; aip != NULL; aip= aip->ai_next)
	{
		s= socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s == -1)
		{
			s_errno= errno;
			continue;
		}

		if (connect(s, res->ai_addr, res->ai_addrlen) == 0)
		{
			break;
		}

		s_errno= errno;
		close(s);
		s= -1;
	}

	if (s == -1)
		errno= s_errno;
	return s;
}
struct testops tdig_ops = { tdig_init, tdig_start, tdig_delete }; 

