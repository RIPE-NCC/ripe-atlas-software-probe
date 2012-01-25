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

#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/dns.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>
#define DQ(str) "\"" #str "\""
#define DQC(str) "\"" #str "\" : "
#define JS(key, val) fprintf(fh, "\"" #key"\" : \"%s\" , ",  val); 
#define JS1(key, fmt, val) fprintf(fh, "\"" #key"\" : "#fmt" , ",  val); 
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

/* Definition for various types of counters */
typedef uint64_t counter_t;

/* How to keep track of a DNS query session */
struct tdig_base {
	struct event_base *event_base;

	evutil_socket_t rawfd_v4;       /* Raw socket used to nsm hosts              */
	evutil_socket_t rawfd_v6;       /* Raw socket used to nsm hosts              */

	struct timeval tv_noreply;     /* DNS query Reply timeout                    */
	struct timeval tv_interval;    /* between two subsequent queries */

	/* A circular list of user queries */
	struct query_state *qry_head;

	struct event event4;            /* Used to detect read events on raw socket   */
	struct event event6;            /* Used to detect read events on raw socket   */

	counter_t sendfail;            /* # of failed sendto()                       */
	counter_t sentok;              /* # of successful sendto()                   */
	counter_t recvfail;            /* # of failed recvfrom()                     */
	counter_t recvok;              /* # of successful recvfrom()                 */
	counter_t foreign;             /* # of DNS replies we are not looking for   */
	counter_t illegal;             /* # of DNS packets with an illegal payload  */
	counter_t sentbytes; 
	counter_t recvtbytes; 	
	counter_t timedout;

	u_char packet [MAX_DNS_BUF_SIZE] ;

	/* used only for the stand alone version */
	void (*done)(void *state);
};

static struct tdig_base *tdig_base;

/* How to keep track of each user query to send dns query */
struct query_state {

	struct tdig_base *base;
	char * name;                /* Host identifier as given by the user */
	char * fqname;              /* Full qualified hostname          */ 
	char * ipname;              /* Remote address in dot notation   */
	struct sockaddr *remote4;  /* source address of return packet */
	struct sockaddr_in6 *remote6 ; /* source address of return packet */
	u_int16_t qryid;             /* query id 16 bit */
	int tcp_fd;
	FILE *tcp_file;

	struct bufferevent *bev_tcp;

	int opt_v4_only ;
	int opt_v6_only ;
	int opt_AF;
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

	/* Bytes counters */
	counter_t sentbytes;           /* Total # of bytes sent                   */
	counter_t recvbytes;           /* Total # of bytes received               */


	//tdig_callback_type user_callback;
	void *user_callback;
	void *user_pointer;            /* the pointer given to us for this qry   */

	/* these objects are kept in a circular list */
	struct query_state *next, *prev;

	char *result;
	size_t reslen;
	size_t resmax; 

	u_char *outbuff;
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


//static uint32_t fmt_dns_query(u_char *buf, struct query_state *qry);
static int tdig_delete(void *state);
static void ChangetoDnsNameFormat(u_char * dns,unsigned char* qry) ;
struct tdig_base *tdig_base_new(struct event_base *event_base); 
void readcb_tcp(struct bufferevent *bev, void *ptr);
void eventcb_tcp(struct bufferevent *bev, short events, void *ptr);
void tdig_start (struct query_state *qry);
void printReply(struct query_state *qry, int wire_size, unsigned char *result );
static void done(void *state);
static void *tdig_init(int argc, char *argv[], void (*done)(void *state));
static void process_reply(void * arg, int nrecv, struct sockaddr *remote4, struct sockaddr_in6 *remote6,  struct timeval now);
static void mk_dns_buff(struct query_state *qry,  u_char *packet);

/* move the next functions from tdig.c */
u_int32_t get32b (char *p);
void ldns_write_uint16(void *dst, uint16_t data);
unsigned char* ReadName(unsigned char* reader,unsigned char* buffer,int* count);
/* from tdig.c */

int evtdig_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int evtdig_main(int argc, char **argv) 
{ 
	struct query_state *qry;

	EventBase=event_base_new();
	if (!EventBase)
	{
		crondlog(DIE9 "event_base_new failed"); /* exits */
	}

	DnsBase = evdns_base_new(EventBase, 1);
	qry = tdig_init(argc, argv, done);
	if (!qry)
	{
		crondlog(DIE9 "new query state failed"); /* exits */
	}

	tdig_start(qry);  
	printf ("starting query\n");

	event_base_dispatch (EventBase);
	event_base_loopbreak (EventBase);
	return 0;
}

static void done(void *state UNUSED_PARAM)
{
	//fprintf(stderr, "And we are done\n");
	exit(0);
}


static void add_str(struct query_state *qry, const char *str)
{
	size_t len;
	len= strlen(str);
	if (qry->reslen + len+1 > qry->resmax)
	{
		qry->resmax= qry->reslen + len+1 + 80;
		qry->result= xrealloc(qry->result, qry->resmax);
	}
	memcpy(qry->result+qry->reslen, str, len+1);
	qry->reslen += len;
	//printf("add_str: result = '%s'\n", state->result);
}


/* Initialize a struct timeval by converting milliseconds */
	static void
msecstotv(time_t msecs, struct timeval *tv)
{
	tv->tv_sec  = msecs / 1000;
	tv->tv_usec = msecs % 1000 * 1000;
}


/* Lookup for a query by its index */
static struct query_state* tdig_lookup_query( struct tdig_base * base, int idx)
{ 
	struct query_state *qry;

	qry = base->qry_head;
	if (!qry)
		return NULL;
	do {
		if (qry->qryid == idx)
		{
			//AA chnage to LVL5
			crondlog(LVL9 "found matching query id %d", idx);
			return qry;
		}
		qry = qry->next;
	} while (qry != base->qry_head);

	return NULL;
}

#if 0
static uint32_t fmt_dns_query(u_char *buf, struct query_state *qry)
{
	u_char *qname;
	struct QUESTION *qinfo = NULL;
	struct EDNS0_HEADER *e;
	uint32_t  size = 0;

	return size ;
}
#endif

static void mk_dns_buff(struct query_state *qry,  u_char *packet) 
{
	struct DNS_HEADER *dns = NULL;
	u_char *qname;
	struct QUESTION *qinfo = NULL;
	struct EDNS0_HEADER *e;
	int r;

	dns = (struct DNS_HEADER *)packet;
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

	//point to the query portion
	qname =(u_char *)&packet[sizeof(struct DNS_HEADER)];
	ChangetoDnsNameFormat(qname, qry->lookupname); // fill the query portion.

	qinfo =(struct QUESTION*)&packet[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; 
	qry->pktsize  = (strlen((const char*)qname) + 1);

	qinfo->qtype = htons(qry->qtype);
	qinfo->qclass = htons(qry->qclass);

	e=(struct EDNS0_HEADER*)&packet[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + sizeof(struct QUESTION) + 2 ) ]; //fill it

	e->qtype = htons(qry->qtype);
	e->_edns_udp_size = htons(qry->opt_edns0);
	//e->_edns_z = htons(128);
	//if(opt_dnssec  == 1)
	{
		e->DO = 0x80;
	}
	e->len = htons(0);

	qry->pktsize += sizeof(struct DNS_HEADER) + sizeof(struct QUESTION) + sizeof(struct EDNS0_HEADER) ;

	/* Transmit the request over the network */
}

/* Attempt to transmit an DNS Request a given qry to a server*/
static void tdig_send_query_callback(int unused UNUSED_PARAM, const short event UNUSED_PARAM, void *h)
{
	struct query_state *qry = h;
	struct tdig_base *base = qry->base;
	int serrno;
	char line[80];
	uint32_t nsent;
	u_char *outbuff;
	int err = 0;

	/* Clean the no reply timer (if any was previously set) */
	evtimer_del(&qry->noreply_timer);

	if(qry->opt_proto == 17)  //UDP 
	{	
		outbuff = xzalloc(MAX_DNS_BUF_SIZE);
		bzero(outbuff, MAX_DNS_BUF_SIZE);
		qry->outbuff = outbuff;
		mk_dns_buff(qry, outbuff);
		do
		{
			gettimeofday(&qry->xmit_time, NULL);
			switch (qry->res->ai_family)
			{
				case AF_INET:
					nsent = sendto(base->rawfd_v4, outbuff,qry->pktsize, MSG_DONTWAIT, qry->res->ai_addr, qry->res->ai_addrlen);
					break;
				case AF_INET6:
					nsent = sendto(base->rawfd_v6, outbuff,qry->pktsize, MSG_DONTWAIT, qry->res->ai_addr, qry->res->ai_addrlen);
					break;
			}

			qry->ressent = qry->res;
			if (nsent == qry->pktsize)
			{
				/* One more DNS Query is sent */
				base->sentok++;
				base->sentbytes+=nsent;

				qry->sentbytes += nsent;

				err  = 0;
				/* Add the timer to handle no reply condition in the given timeout */
				evtimer_add(&qry->noreply_timer, &base->tv_noreply);
			}
			else 
			{
				err  = 1;
				base->sendfail++;
				serrno= errno; 
				sprintf(line, "\"senderror\" : \"%s\" ,", strerror(serrno)); 
				add_str(qry, line);
				//perror("send"); 
			}
		} while ((qry->res = qry->res->ai_next) != NULL);
		free (outbuff);
		outbuff = NULL;
		if(err) 
		{
			printReply (qry, 0, NULL);
			return;
		}
	}
	else{ //TCP yet to be complted.
		qry->bev_tcp =  bufferevent_socket_new(qry->base->event_base, -1, BEV_OPT_CLOSE_ON_FREE);
		bufferevent_setcb(qry->bev_tcp, readcb_tcp, NULL, eventcb_tcp, qry);
		bufferevent_enable(qry->bev_tcp, EV_READ|EV_WRITE);
		bufferevent_socket_connect_hostname(qry->bev_tcp, DnsBase,
				qry->opt_AF, qry->server_name, 53);
		crondlog(LVL9 "dispatched tcp callback %s", qry->server_name);
	}
}

void readcb_tcp(struct bufferevent *bev, void *ptr)
{
	struct query_state *qry = ptr;
	int n;
	u_char b2[2];
	struct timeval rectime;	
	struct evbuffer *input ;
	int wire_size;

	gettimeofday(&rectime, NULL);
	bzero(qry->base->packet, MAX_DNS_BUF_SIZE);
	printf("read was called\n");
	evbuffer_remove(input, b2, 2 );
	wire_size = ldns_read_uint16(b2);

	input = bufferevent_get_input(bev);
	n = evbuffer_remove(input, qry->base->packet, wire_size );
	printf (" got %d bytes to process\n", n);
	bufferevent_free(bev);
	process_reply(qry->base, n, NULL, NULL, rectime); 	


	// AA not sure if I want to empty the buffer in while. However if the size too big generate error message.
	/*
	   while ((n = evbuffer_remove(input, qry->base->packet, MAX_DNS_BUF_SIZE )) > 0) {
	   printf (" got %d bytes to process\n", n);
	   process_reply(qry->base, n, NULL, NULL, rectime); 	

	   } */

}

void eventcb_tcp(struct bufferevent *bev, short events, void *ptr)
{
	struct query_state *qry = ptr;
	u_char *outbuff;
	uint16_t payload_len ;
	u_char wire[1300];

	if (events & BEV_EVENT_CONNECTED) {
		printf("Connect okay.\n");
		outbuff = xzalloc(MAX_DNS_BUF_SIZE);
		bzero(outbuff, MAX_DNS_BUF_SIZE);
		qry->outbuff = outbuff;
		mk_dns_buff(qry, outbuff);
		payload_len = (uint16_t) qry->pktsize;
		ldns_write_uint16(wire, qry->pktsize);
		memcpy(wire + 2, outbuff, qry->pktsize);
		evbuffer_add(bufferevent_get_output(qry->bev_tcp), wire, (qry->pktsize +2));

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
static void noreply_callback(int unused  UNUSED_PARAM, const short event UNUSED_PARAM, void *h)
{
	char line[80];
	struct query_state *qry = h;
	qry->base->timedout++;
	sprintf(line, "\"timedout\" : 1 , ");
	add_str(qry, line);
	printReply (qry, 0, NULL);
	return;
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

static void process_reply(void * arg, int nrecv, struct sockaddr *remote4, struct sockaddr_in6 *remote6,  struct timeval now)
{
	struct tdig_base *base = arg;

	struct DNS_HEADER *dnsR = NULL;

	struct query_state * qry;

	dnsR = (struct DNS_HEADER*) base->packet;
	base->recvok++; 

	/* Get the pointer to the qry descriptor in our internal table */
	qry = tdig_lookup_query(base, ntohs(dnsR->id));

	if ( ! qry) 
		return;

	/* Use the User Data to relate Echo Request/Reply and evaluate the Round Trip Time */

	qry->base->recvok++;
	qry->recvbytes += nrecv;
	qry->triptime = (now.tv_sec-qry->xmit_time.tv_sec)*1000 +
		(now.tv_usec-qry->xmit_time.tv_usec)/1e3;
	qry->remote4 = remote4;
	qry->remote6 = remote6;

	/* Clean the noreply timer */
	evtimer_del(&qry->noreply_timer);
	printReply (qry, nrecv, base->packet);
	return;
}

static void ready_callback4 (int unused UNUSED_PARAM, const short event UNUSED_PARAM, void * arg)
{
	struct tdig_base *base = arg;
	int nrecv;
	struct sockaddr *remote4;                  /* responding internet address */
	struct sockaddr_in6 *remote6 ;
	socklen_t slen;
	struct timeval rectime;

	remote4 = xzalloc(sizeof(struct sockaddr));
	remote6 = NULL;

	slen = sizeof(struct sockaddr);
	bzero(base->packet, MAX_DNS_BUF_SIZE);
	/* Time the packet has been received */

	gettimeofday(&rectime, NULL);
	/* Receive data from the network */
	nrecv = recvfrom(base->rawfd_v4, base->packet, sizeof(base->packet), MSG_DONTWAIT, remote4, &slen);
	if (nrecv < 0)
	{
		/* One more failure */
		base->recvfail++;
		return ;
	}
	process_reply(arg, nrecv, remote4, remote6, rectime);
	return;
} 

static void ready_callback6 (int unused UNUSED_PARAM, const short event UNUSED_PARAM, void * arg)
{
	struct tdig_base *base = arg;
	int nrecv; 
	struct timeval rectime;
	struct msghdr msg;
	struct iovec iov[1];
	//char buf[INET6_ADDRSTRLEN];
	struct sockaddr *remote6;
	struct sockaddr_in *remote4;
	char cmsgbuf[256];

	/* Time the packet has been received */
	gettimeofday(&rectime, NULL);

	remote6 = xzalloc(sizeof(struct sockaddr_in6));
	remote4 = NULL;

	iov[0].iov_base= base->packet;
	iov[0].iov_len= sizeof(base->packet);

	msg.msg_name= remote6;
	msg.msg_namelen= sizeof( struct sockaddr_in6);
	msg.msg_iov= iov;
	msg.msg_iovlen= 1;
	msg.msg_control= cmsgbuf;
	msg.msg_controllen= sizeof(cmsgbuf);
	msg.msg_flags= 0;                       /* Not really needed */

	nrecv= recvmsg(base->rawfd_v6, &msg, MSG_DONTWAIT);
	if (nrecv == -1)
	{
		/* Strange, read error */
		printf("ready_callback6: read error '%s'\n", strerror(errno));
		return;
	}
	process_reply(arg, nrecv, remote4, remote6, rectime);

	return;
}

static void *tdig_init(int argc, char *argv[], void (*done)(void *state))
{
	char *check;
	struct query_state *qry;
	int c;
	int opt_v4_only, opt_v6_only;

	if(!tdig_base)
		tdig_base = tdig_base_new(EventBase);

	if(!tdig_base)
		crondlog(DIE9 "tdig_base_new failed");

	tdig_base->done = done;


	tdig_base->sendfail = 0;
	tdig_base->sentok  = 0;
	tdig_base->recvfail  = 0;
	tdig_base->recvok  = 0;
	tdig_base->foreign  = 0;
	tdig_base->illegal  = 0;
	tdig_base->sentbytes  = 0;
	tdig_base->recvtbytes = 0;
	tdig_base->timedout = 0;


	qry=xzalloc(sizeof(*qry));
	opt_v4_only =  opt_v6_only = 0;


	bzero(qry, sizeof(*qry));
	// initialize per query state variables;
	qry->qtype = T_TXT; /* TEXT */
	qry->qclass = C_CHAOS;
	qry->opt_v4_only = 0; 
	qry->opt_v6_only = 0; 
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
				qry->opt_AF = AF_INET;
				break;
			case '6':
				qry->opt_v6_only = 1;
				qry->opt_AF = AF_INET6;
				break;
			case 'A':
				qry->str_Atlas = strdup(optarg);
				break;
			case 'b':
				qry->lookupname  = (u_char *) strdup ("version.bind.");
				break;
			case 'D':
				qry->qtype = T_DNSKEY;
				qry->qclass = C_IN;
				if(qry->opt_edns0 == 0)
					qry->opt_edns0 = 512;
				qry->opt_dnssec = 1;
				qry->lookupname  = (u_char *) strdup(optarg);
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
				qry->lookupname = (u_char *) strdup("hostname.bind.");
				break;
			case 'i':
				qry->lookupname = (u_char *) strdup("id.server.");
				break;

			case 'O':
				qry->out_filename = strdup(optarg);
				break;
			case 'r':
				qry->lookupname = (u_char *) strdup("version.server.");
				break;
			case 's':
				qry->qtype = T_SOA;
				qry->qclass = C_IN;
				qry->lookupname =  (u_char *) strdup(optarg);
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
	if(qry->opt_v6_only  == 0)
	{
		qry->opt_v4_only = 1;
		qry->opt_AF = AF_INET;
	}
	qry->server_name = strdup(argv[optind]);
	qry->base = tdig_base;

	return qry;
}

/* exported function */
	struct tdig_base *
tdig_base_new(struct event_base *event_base)
{
	evutil_socket_t fd6;
	evutil_socket_t fd4;
	struct addrinfo hints;
	int on = 1;

	bzero(&hints,sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_flags = 0;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = 0;

	/* Create an endpoint for communication using raw socket for ICMP calls */
	if ((fd4 = socket(hints.ai_family, hints.ai_socktype, hints.ai_protocol) ) < 0 )
	{
		return NULL;
	} 

	hints.ai_family = AF_INET6;
	if ((fd6 = socket(hints.ai_family, hints.ai_socktype, hints.ai_protocol) ) < 0 )
	{
		close(fd4);
		return NULL;
	} 

	tdig_base= xzalloc(sizeof( struct tdig_base));
	if (tdig_base == NULL)
	{
		close(fd4);
		close(fd6);
		return (NULL);
	}

	memset(tdig_base, 0, sizeof(struct tdig_base));
	tdig_base->event_base = event_base;

	tdig_base->rawfd_v4 = fd4;
	tdig_base->rawfd_v6 = fd6;

	setsockopt(fd6, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));

	on = 1;
	setsockopt(fd6, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on));

	//memset(&tdig_base-->loc_sin6, '\0', sizeof(tdig_base-->loc_sin6));
	//tdig_base-->loc_socklen= 0;

	evutil_make_socket_nonblocking(tdig_base->rawfd_v4); 

	msecstotv(DEFAULT_NOREPLY_TIMEOUT, &tdig_base->tv_noreply);
	msecstotv(DEFAULT_PING_INTERVAL, &tdig_base->tv_interval);

	// Define the callback to handle UDP Reply 
	// add the raw file descriptor to those monitored for read events 

	event_assign(&tdig_base->event4, tdig_base->event_base, tdig_base->rawfd_v4, 
			EV_READ | EV_PERSIST, ready_callback4, tdig_base);
	event_add(&tdig_base->event4, NULL);

	event_assign(&tdig_base->event6, tdig_base->event_base, tdig_base->rawfd_v6, 
			EV_READ | EV_PERSIST, ready_callback6, tdig_base);
	event_add(&tdig_base->event6, NULL);

	return tdig_base;
}

void tdig_start (struct query_state *qry)
{
	struct timeval asap = { 0, 0 };

	int err_num;
	struct addrinfo hints, *res;
	char port[] = "domain";

	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = 0;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = 0;


	if(qry->opt_v6_only == 1) 
	{
		hints.ai_family = AF_INET6;
	}
	else if(qry->opt_v4_only == 1)
	{
		hints.ai_family = AF_INET;
	}

	if( (qry->opt_v4_only == 1 )  && (qry->opt_v6_only == 1) )
	{
		hints.ai_family = AF_UNSPEC;
	}

	if ( ( err_num  = getaddrinfo(qry->server_name, port , &hints, &res)))
	{
		printf("%s ERROR port %s %s\n", qry->server_name, port, gai_strerror(err_num));
		return ;
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
	return ;
}

#if 0
int tdig_base_count_queries(struct tdig_base *base)
{
	const struct query_state *qry;
	int n = 0;

	qry = base->qry_head;
	if (!qry)
		return 0;
	do {
		++n;
		qry = qry->next;
	} while (qry != base->qry_head);

	return n;
}


/* exported function */
	void
tdig_stats(struct tdig_base *base)
{
}

#endif

static void ChangetoDnsNameFormat(u_char *  dns,unsigned char* qry)
{
	char *s;
	int lock = 0, i;

	s = dns;
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


static void free_qry_inst(struct query_state *qry)
{

	void (*terminator)(void *state);
	struct event_base *event_base;

	if(qry->result) 
	{
		free(qry->result);
		qry->result= NULL;
		qry->resmax = 0;
	}
	if(qry->ressave )
	{
		freeaddrinfo(qry->ressave);
		qry->ressave  = NULL;
	}

	if( qry->remote6) 
	{
		free( qry->remote6);
		qry->remote6 = NULL;
	}
	if( qry->remote4) 
	{
		free( qry->remote4);
		qry->remote4 = NULL;
	}

	if(qry->base->done)
	{
		terminator = qry->base->done;
		event_base = qry->base->event_base;

		tdig_delete(qry);
		event_base_loopbreak(event_base);
		event_base_free(event_base);
		terminator(qry);
	}

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

void printReply(struct query_state *qry, int wire_size, unsigned char *result )
{
	int i, stop=0;
	unsigned char *qname, *reader;
	struct DNS_HEADER *dnsR = NULL;
	struct RES_RECORD answers[20]; //the replies from the DNS server
	void *ptr;
	char addrstr[100];
	FILE *fh; 
	//char buf[INET6_ADDRSTRLEN];
	u_int32_t serial;

	if (qry->out_filename)
	{
		fh= fopen(qry->out_filename, "a");
		if (!fh)
			crondlog(DIE9 "unable to append to '%s'",
					qry->out_filename);
	}
	else
		fh = stdout;

	fprintf(fh, "{ ");
	if(qry->str_Atlas) 
	{

		//fprintf(fh, DQC(id)  DQ(%s) DQC(time) DQ(%ld) "," , qry->str_Atlas, qry->xmit_time.tv_sec);
		//JS(id, qry->str_Atlas);
		JS1(id, %s, qry->str_Atlas);
		JS1(time, %ld,  qry->xmit_time.tv_sec);

	}
	JS(name,  qry->server_name);
	JS(proto, qry->opt_proto == 6 ? "TCP" : "UDP" );

	if( qry->ressent)
	{  // started to send query
		JD(pf, qry->ressent->ai_family == PF_INET6 ? 6 : 4);
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
		JS(address , addrstr);
	}

	if(result)
	{
		dnsR = (struct DNS_HEADER*) result;

		//point to the query portion
		qname =(unsigned char*)&result[sizeof(struct DNS_HEADER)];

		//move ahead of the dns header and the query field
		reader = &result[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];

		fprintf (fh, " \"result\" : { ");
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
	} 

	fprintf(fh, " \"end\": 0");
	fprintf(fh, " }");
	fprintf(fh, "\n");
	if (qry->out_filename)
		fclose(fh);
	free_qry_inst(qry);
}

struct testops tdig_ops = { tdig_init, tdig_start, tdig_delete }; 
