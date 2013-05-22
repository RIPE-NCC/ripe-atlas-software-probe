/*
 * Copyright (c) 2011-2013 RIPE NCC <atlas@ripe.net>
 * Copyright (c) 2009 Rocco Carbone <ro...@tecsiel.it>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include "libbb.h"
#include "atlas_bb64.h"
#include "atlas_probe.h"
#include <netdb.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <math.h>
#include <assert.h>

#include "eperd.h" 
#include "resolv.h"
#include "readresolv.h"
#include "tcputil.h"

#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/dns.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>
#define DQ(str) "\"" #str "\""
#define DQC(str) "\"" #str "\" : "
#define JS(key, val) fprintf(fh, "\"" #key"\" : \"%s\" , ",  val); 
#define JS_NC(key, val) fprintf(fh, "\"" #key"\" : \"%s\" ",  val); 
#define JSDOT(key, val) fprintf(fh, "\"" #key"\" : \"%s.\" , ",  val); 
#define JS1(key, fmt, val) fprintf(fh, "\"" #key"\" : "#fmt" , ",  val); 
#define JD(key, val) fprintf(fh, "\"" #key"\" : %d , ",  val); 
#define JD_NC(key, val) fprintf(fh, "\"" #key"\" : %d ",  val); 
#define JU(key, val) fprintf(fh, "\"" #key"\" : %u , ",  val); 
#define JU_NC(key, val) fprintf(fh, "\"" #key"\" : %u",  val); 
#define JC fprintf(fh, ","); 

#define SAFE_PREFIX ATLAS_DATA_NEW

#define BLURT crondlog (LVL5 "%s:%d %s()", __FILE__, __LINE__,  __func__);crondlog
#define IAMHERE crondlog (LVL5 "%s:%d %s()", __FILE__, __LINE__,  __func__);

#undef MIN	/* just in case */
#undef MAX	/* also, just in case */
#define Q_RESOLV_CONF -1
#define O_RESOLV_CONF  1003
#define O_PREPEND_PROBE_ID  1004
#define O_EVDNS 1005

#define DNS_FLAG_RD 0x0100

#define MIN(a, b) (a < b ? a : b)
#define MAX(a, b) (a > b ? a : b)

#define ENV2QRY(env) \
	((struct query_state *)((char *)env - offsetof(struct query_state, tu_env)))

#define MAX_DNS_BUF_SIZE   5120
#define MAX_DNS_OUT_BUF_SIZE   512

/* Intervals and timeouts (all are in milliseconds unless otherwise specified) */
#define DEFAULT_NOREPLY_TIMEOUT 5000           /* 1000 msec - 0 is illegal      */
#define DEFAULT_LINE_LENGTH 80 
#define DEFAULT_STATS_REPORT_INTERVEL 180 		/* in seconds */
#define CONN_TO            5  /* TCP connection time out in seconds */

/* state of the dns query */
#define STATUS_DNS_RESOLV 		1001
#define STATUS_TCP_CONNECTING 		1002
#define STATUS_TCP_CONNECTED 		1003
#define STATUS_TCP_WRITE 		1004
#define STATUS_NEXT_QUERY		1005
#define STATUS_FREE 			0

// seems T_DNSKEY is not defined header files of lenny and sdk
#ifndef ns_t_dnskey
#define ns_t_dnskey   48
#endif

#ifndef T_DNSKEY
#define T_DNSKEY ns_t_dnskey
#endif

#ifndef ns_t_rrsig
#define ns_t_rrsig   46
#endif

#ifndef T_RRSIG
#define T_RRSIG ns_t_rrsig
#endif

#ifndef ns_t_nsec
#define ns_t_nsec   47
#endif

#ifndef T_NSEC
#define T_NSEC ns_t_nsec
#endif  

#ifndef T_NSEC3
#define T_NSEC3 ns_t_nsec3
#endif  

#ifndef ns_t_nsec3
#define ns_t_nsec3   50
#endif


#ifndef ns_t_ds
#define ns_t_ds   43
#endif

#ifndef T_DS
#define T_DS ns_t_ds
#endif 


/* Definition for various types of counters */
typedef uint32_t counter_t;

/* How to keep track of a DNS query session */
struct tdig_base {
	struct event_base *event_base;

	evutil_socket_t rawfd_v4;       /* Raw socket used to nsm hosts              */
	evutil_socket_t rawfd_v6;       /* Raw socket used to nsm hosts              */

	struct timeval tv_noreply;     /* DNS query Reply timeout                    */

	/* A circular list of user queries */
	struct query_state *qry_head;

	struct event event4;            /* Used to detect read events on raw socket   */
	struct event event6;            /* Used to detect read events on raw socket   */
	struct event statsReportEvent;
	int resolv_max;
	char nslist[MAXNS][INET6_ADDRSTRLEN * 2];

	counter_t sendfail;            /* # of failed sendto()                       */
	counter_t sentok;              /* # of successful sendto()                   */
	counter_t recvfail;            /* # of failed recvfrom()                     */
	counter_t recvok;              /* # of successful recvfrom()                 */
	counter_t martian;             /* # of DNS replies we are not looking for   */
	counter_t shortpkt;            /* # of DNS payload with size < sizeof(struct DNS_HEADER) == 12 bytes */
	counter_t sentbytes; 
	counter_t recvbytes; 	
	counter_t timeout;
	counter_t queries; 	
	counter_t activeqry;

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
	u_int16_t qryid;             /* query id 16 bit */
	int tcp_fd;
	FILE *tcp_file;
	int wire_size;

	struct bufferevent *bev_tcp;
	struct tu_env tu_env;

	int opt_v4_only ;
	int opt_v6_only ;
	int opt_AF;
	int opt_proto;
	int opt_edns0;
	int opt_dnssec;
	int opt_nsid;
	int opt_qbuf;
	int opt_abuf;
	int opt_resolv_conf;
	int opt_rd;
	int opt_prepend_probe_id;
	int opt_evdns;

	char * str_Atlas; 
	u_int16_t qtype;
	u_int16_t qclass;

	char *lookupname;
	char * server_name;
	char *out_filename ;

	uint32_t pktsize;              /* Packet size in bytes */
	struct addrinfo *res, *ressave, *ressent;

	struct sockaddr_in remote;     /* store the reply packet src address      */


	struct event noreply_timer;    /* Timer to handle timeout */
	struct event nsm_timer;       /* Timer to send UDP */
	struct event next_qry_timer;  /* Timer event to start next query */

	struct timeval xmit_time;	
	double triptime;

	//tdig_callback_type user_callback;
	void *user_callback;
	void *user_pointer;            /* the pointer given to us for this qry   */

	/* these objects are kept in a circular list */
	struct query_state *next, *prev;

	struct buf err; 
	struct buf qbuf; 
	struct buf packet;
	int qst ; 
	char dst_addr_str[(INET6_ADDRSTRLEN+1)]; 
	char loc_addr_str[(INET6_ADDRSTRLEN+1)]; 
	unsigned short dst_ai_family ;
	unsigned short loc_ai_family ;
	struct sockaddr_in6 loc_sin6;
        socklen_t loc_socklen;
	

	u_char *outbuff;
};
//DNS header structure
struct DNS_HEADER
{
	u_int16_t id;        // identification number

	u_int16_t flags;
/* 
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

*/
	u_int16_t q_count; // number of question entries
	u_int16_t ans_count; // number of answer entries
	u_int16_t ns_count; // number of authority entries
	u_int16_t add_count; // number of resource entries
};

// EDNS OPT pseudo-RR : EDNS0
struct EDNS0_HEADER
{
	/** EDNS0 available buffer size, see RFC2671 */
	u_int16_t otype;
	uint16_t _edns_udp_size;
	u_int8_t _edns_x; // combined rcode and edns version both zeros.
	u_int8_t _edns_y; // combined rcode and edns version both zeros.
	u_int16_t Z ;     // first bit is the D0 bit.
}; 

// EDNS OPT pseudo-RR : eg NSID RFC 5001 
struct EDNS_NSID 
{
	uint16_t len;
	u_int16_t otype;
	u_int16_t odata; 
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
	// class IN
	{ "a", required_argument, NULL, (100000 + T_A) },
	{ "ns", required_argument, NULL, (100000 + T_NS) },
	{ "cname", required_argument, NULL, (100000 + T_CNAME) },
	{ "ptr", required_argument, NULL, (100000 + T_PTR ) },
	{ "mx", required_argument, NULL, (100000 + T_MX ) },
	{ "txt", required_argument, NULL, (100000 + T_TXT ) },
	{ "aaaa", required_argument, NULL, (100000 + T_AAAA) },
	{ "axfr", required_argument, NULL, (100000 + T_AXFR ) },  //yet to be tested.
	{ "any", required_argument, NULL, (100000 + T_ANY) },
	{ "dnskey", required_argument, NULL, (100000 + T_DNSKEY) },
	{ "nsec", required_argument, NULL, (100000 + T_NSEC) },
	{ "nsec3", required_argument, NULL, (100000 + T_NSEC3) },
	{ "ds", required_argument, NULL, (100000 + T_DS) },
	{ "rrsig", required_argument, NULL, (100000 + T_RRSIG) },
	{ "soa", required_argument, NULL, 's' },

	// clas CHAOS
	{ "hostname.bind", no_argument, NULL, 'h' },
	{ "id.server", no_argument, NULL, 'i' },
	{ "version.bind", no_argument, NULL, 'b' },
	{ "version.server", no_argument, NULL, 'r' },

	// flags
	{ "edns0", required_argument, NULL, 'e' },
	{ "nsid", no_argument, NULL, 'n' },
	{ "d0", no_argument, NULL, 'd' },
 	
	{ "resolv", no_argument, NULL, O_RESOLV_CONF },
	{ "qbuf", no_argument, NULL, 1001 },
	{ "noabuf", no_argument, NULL, 1002 },

	{ "evdns", no_argument, NULL, O_EVDNS },
	{ "out-file", required_argument, NULL, 'O' },
	{ "p_probe_id", no_argument, NULL, O_PREPEND_PROBE_ID },
	{ NULL, }
};
static char line[DEFAULT_LINE_LENGTH];

static void tdig_stats(int unused UNUSED_PARAM, const short event UNUSED_PARAM, void *h);
static int tdig_delete(void *state);
static void ChangetoDnsNameFormat(u_char *dns, char * qry) ;
struct tdig_base *tdig_base_new(struct event_base *event_base); 
void tdig_start (struct query_state *qry);
void printReply(struct query_state *qry, int wire_size, unsigned char *result);
void printErrorQuick (struct query_state *qry);
static void local_exit(void *state);
static void *tdig_init(int argc, char *argv[], void (*done)(void *state));
static void process_reply(void * arg, int nrecv, struct timeval now, int af, void *remote);
static void mk_dns_buff(struct query_state *qry,  u_char *packet);
int ip_addr_cmp (u_int16_t af_a, void *a, u_int16_t af_b, void *b);
static void udp_dns_cb(int err, struct evutil_addrinfo *ev_res, struct query_state *qry);

/* move the next functions from tdig.c */
u_int32_t get32b (char *p);
void ldns_write_uint16(void *dst, uint16_t data);
uint16_t ldns_read_uint16(const void *src);
unsigned char* ReadName(unsigned char *base, size_t size, size_t offset,
        int* count);
/* from tdig.c */

void print_txt_json(unsigned char *rdata, int txt_len, FILE *fh);

int evtdig_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int evtdig_main(int argc, char **argv) 
{ 
	struct query_state *qry;

	EventBase=event_base_new();
	if (!EventBase)
	{
		crondlog(LVL9 "event_base_new failed"); /* exits */
	}

	qry = tdig_init(argc, argv, NULL);
	if(!qry) {
		crondlog(DIE9 "evdns_base_new failed"); /* exits */
		event_base_free	(EventBase);
		return 1;
	}

	DnsBase = evdns_base_new(EventBase, 1);
	if (!DnsBase) {
		crondlog(DIE9 "evdns_base_new failed"); /* exits */
		event_base_free	(EventBase);
		return 1;
	}

	tdig_start(qry);  
	printf ("starting query\n");

	event_base_dispatch (EventBase);
	event_base_loopbreak (EventBase);
	if(EventBase)
	event_base_free(EventBase);
	return 0;
}

void print_txt_json(unsigned char *rdata, int txt_len, FILE *fh)
{
        int i;

        fprintf(fh, ", \"RDATA\" : \"");
        for(i = 0; i < txt_len; i++) {
                if( (*rdata == 34  ) || (*rdata == 92  ))  {
                        fprintf(fh, "\\%c", *(char *)rdata  );
                }
                // Space - DEL
                else if ((*rdata > 31  ) && (*rdata < 128)) {
                        fprintf(fh, "%c", *(char *)rdata );
                }
                else {
                        fprintf(fh, "\\u00%02X", *rdata   );
                }
                rdata++;
        }

        fprintf(fh, "\"");
}

static void local_exit(void *state UNUSED_PARAM)
{
	//fprintf(stderr, "And we are done\n");
	exit(0);
}


/* Initialize a struct timeval by converting milliseconds */
static void msecstotv(time_t msecs, struct timeval *tv)
{
	tv->tv_sec  = msecs / 1000;
	tv->tv_usec = msecs % 1000 * 1000;
}

int ip_addr_cmp (u_int16_t af_a, void *a, u_int16_t af_b, void *b) 
{
	struct sockaddr_in *a4;
	struct sockaddr_in *b4;
	struct sockaddr_in6 *a6;
	struct sockaddr_in6 *b6;
	char buf[INET6_ADDRSTRLEN];

	if(af_a != af_b) {
		crondlog(LVL5 "address family mismatch in  %d ", __LINE__);
		return -1;
	}
 
	if(af_a == AF_INET ) {
		a4 = (struct sockaddr_in *) a;
		b4 = (struct sockaddr_in *) b;
		if( memcmp ( &(a4->sin_addr),  &(b4->sin_addr), sizeof(struct in_addr)) == 0) {
			return 0;
		}
		else 
			return 1;
	}
	else if(af_a == AF_INET6 ) {
		a6 = (struct sockaddr_in6 *) a;
		b6 = (struct sockaddr_in6 *) b;
		if( memcmp ( &(a6->sin6_addr),  &(b6->sin6_addr), sizeof(struct in6_addr)) == 0) {
			inet_ntop(AF_INET6, &(a6->sin6_addr), buf, sizeof(buf));
			crondlog(LVL5 "address6 match  A %s", buf);
			inet_ntop(AF_INET6, &(b6->sin6_addr), buf, sizeof(buf));
			crondlog(LVL5 "address6 match  B %s", buf);

			return 0;
		}
		else {
			inet_ntop(AF_INET6, &(a6->sin6_addr), buf, sizeof(buf));
			crondlog(LVL5 "address6 mismatch  A %s", buf);
			inet_ntop(AF_INET6, &(b6->sin6_addr), buf, sizeof(buf));
			crondlog(LVL5 "address mismatch  B %s", buf);


			return 1;
		}
	}
	return 1;
}

/* Lookup for a query by its index */
static struct query_state* tdig_lookup_query( struct tdig_base * base, int idx, int af, void * remote)
{ 
	int i = 0;
	struct query_state *qry;

	qry = base->qry_head;
	if (!qry)
		return NULL;
	do {
		i++;
		if (qry->qryid == idx)
		{
			//AA chnage to LVL5
			crondlog(LVL7 "found matching query id %d", idx);
			if( qry->ressent && ip_addr_cmp (af, remote, qry->ressent->ai_family, qry->ressent->ai_addr) == 0) {
				crondlog(LVL7 "matching id and address id %d", idx);
				return qry;
			}
			else {
				crondlog(LVL7 "matching id and address mismatch id %d", idx);
			} 
		}
		qry = qry->next;
		if (i > (2*base->activeqry) ) {
			crondlog(LVL7 "i am looping %d AA", idx);
			return NULL;
		}
		
	} while (qry != base->qry_head);

	return NULL;
}

static void mk_dns_buff(struct query_state *qry,  u_char *packet) 
{
	struct DNS_HEADER *dns = NULL;
	u_char *qname;
	struct QUESTION *qinfo = NULL;
	struct EDNS0_HEADER *e;
	struct EDNS_NSID *n;
	int r;
	struct buf pbuf;
	char *lookup_prepend;
	int probe_id;

	dns = (struct DNS_HEADER *)packet;
	r =  random();
	r %= 65535;
	qry->qryid = (uint16_t) r; // host is storing int host byte order
	crondlog(LVL5 "%s %s() : %d base address %p",__FILE__, __func__, __LINE__, qry->base);
	BLURT(LVL5 "dns qyery id %d", qry->qryid);
	dns->id = (uint16_t) htons(r); 
 /*
	dns->qr = 0; //This is a query
	dns->opcode = 0; //This is a standard query
	dns->aa = 0; //Not Authoritative
	dns->tc = 0; //This message is not truncated
	dns->rd = 0; //Recursion  not Desired
	dns->ra = 1; //Recursion not available! hey we dont have it (lol)
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;
*/
	dns->q_count = htons(1); //we have only 1 question
	dns->ans_count = 0;
	dns->ns_count = 0;
	dns->add_count = htons(0);

	if (( qry->opt_resolv_conf > Q_RESOLV_CONF ) ||  (qry->opt_rd )){
		// if you need more falgs do a bitwise and here.
		dns->flags = htons(DNS_FLAG_RD);
	}

	//point to the query portion
	qname =(u_char *)&packet[sizeof(struct DNS_HEADER)];

	// should it be limited to clas C_IN ? 
	if(qry->opt_prepend_probe_id ) {
		probe_id = get_probe_id();
		probe_id =  MAX(probe_id, 0);


		lookup_prepend = xzalloc(DEFAULT_LINE_LENGTH +  sizeof(qry->lookupname));
		snprintf(lookup_prepend, (sizeof(qry->lookupname) + DEFAULT_LINE_LENGTH - 1),  "%d.%lu.%s", probe_id, qry->xmit_time.tv_sec, qry->lookupname);

		ChangetoDnsNameFormat(qname, lookup_prepend); // fill the query portion.

		free(lookup_prepend);
	}
	else {
		ChangetoDnsNameFormat(qname, qry->lookupname); // fill the query portion.
	}
	qinfo =(struct QUESTION*)&packet[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; 

	qinfo->qtype = htons(qry->qtype);
	qinfo->qclass = htons(qry->qclass);

	qry->pktsize  = (strlen((const char*)qname) + 1) + sizeof(struct DNS_HEADER) + sizeof(struct QUESTION) ;
	if(qry->opt_nsid || qry->opt_dnssec || (qry->opt_edns0 > 512)) { 
		e=(struct EDNS0_HEADER*)&packet[ qry->pktsize + 1 ];
		e->otype = htons(ns_t_opt);
		e->_edns_udp_size = htons(qry->opt_edns0);
		if(qry->opt_dnssec) {
			e->Z = htons(0x8000);
		}
		else  {
			e->Z = 0x0;
		}
		crondlog(LVL5 "opt header in hex | %02X  %02X %02X %02X %02X %02X %02X %02X %02X | %02X",
				packet[qry->pktsize],
				packet[qry->pktsize + 1],
				packet[qry->pktsize + 2],
				packet[qry->pktsize + 3],
				packet[qry->pktsize + 4],
				packet[qry->pktsize + 5],
				packet[qry->pktsize + 6],
				packet[qry->pktsize + 7],
				packet[qry->pktsize + 8],
				packet[qry->pktsize + 9]);

		qry->pktsize  += sizeof(struct EDNS0_HEADER) ;

		if(qry->opt_nsid ) {
			dns->add_count = htons(1);
			n=(struct EDNS_NSID*)&packet[ qry->pktsize + 1 ];
			n->len =  htons(4);
			n->otype = htons(3); 
		}
		qry->pktsize  += sizeof(struct EDNS_NSID) + 1;
		dns->add_count = htons(1);
		/* Transmit the request over the network */
	}
	buf_init(&pbuf, -1);

	if(qry->pktsize) {
		snprintf(line, DEFAULT_LINE_LENGTH, "%0d bytes ", qry->pktsize);
		buf_add(&pbuf, line, strlen(line));

		line[0]  = '"'; 
		buf_add(&pbuf, line, 1);
		for(int x = 0; x < qry->pktsize; x++) {
			snprintf(line, DEFAULT_LINE_LENGTH, "%02X ", packet[x]);
			buf_add(&pbuf, line, 3);
		}
		line[0]  = '"'; 
		line[1]  = '\0';
		buf_add(&pbuf, line, 2 );
		crondlog(LVL5 "payload : %s", pbuf.buf);
		buf_cleanup(&pbuf);
	}
} 



/* Attempt to transmit a UDP DNS Request to a serveri. TCP is else where */
static void tdig_send_query_callback(int unused UNUSED_PARAM, const short event UNUSED_PARAM, void *h)
{
	struct query_state *qry = h;
	struct tdig_base *base = qry->base;
	uint32_t nsent = 0;
	u_char *outbuff;
	int err = 0; 
	int sockfd;

		/* Clean the no reply timer (if any was previously set) */
	evtimer_del(&qry->noreply_timer);

	outbuff = xzalloc(MAX_DNS_OUT_BUF_SIZE);
	bzero(outbuff, MAX_DNS_OUT_BUF_SIZE);
	//AA delete qry->outbuff = outbuff;
	gettimeofday(&qry->xmit_time, NULL);
	mk_dns_buff(qry, outbuff);
	do {
		switch (qry->res->ai_family) {
			case AF_INET:
				nsent = sendto(base->rawfd_v4, outbuff,qry->pktsize, MSG_DONTWAIT, qry->res->ai_addr, qry->res->ai_addrlen);
				break;
			case AF_INET6:
				nsent = sendto(base->rawfd_v6, outbuff,qry->pktsize, MSG_DONTWAIT, qry->res->ai_addr, qry->res->ai_addrlen);
				break;
		}
		qry->ressent = qry->res;

		if (nsent == qry->pktsize) {
			// the packet is send. Now lets try to the source address we would have used.
			// create another sock with same dest, connect and get the source address 
    			// delete that socket and hope the the source address is the right one.
			if ((sockfd = socket(qry->res->ai_family, SOCK_DGRAM, 0 ) ) < 0 ) { 
                                        snprintf(line, DEFAULT_LINE_LENGTH, "%s \"socket\" : \"temp socket to get src address failed %s\"", qry->err.size ? ", " : "", strerror(errno));
                                        buf_add(&qry->err, line, strlen(line));
				return;
        		}
			else  {
				qry->loc_socklen = sizeof(qry->loc_sin6);
				connect(sockfd, qry->res->ai_addr, qry->res->ai_addrlen);
				if (getsockname(sockfd,(struct sockaddr *)&qry->loc_sin6, &qry->loc_socklen)  == -1) {
					snprintf(line, DEFAULT_LINE_LENGTH, "%s \"getscokname\" : \"%s\"", qry->err.size ? ", " : "", strerror(errno));
					buf_add(&qry->err, line, strlen(line));
				}
				close(sockfd);
			}

			/* One more DNS Query is sent */
			base->sentok++;
			base->sentbytes += nsent;
			err  = 0;
			/* Add the timer to handle no reply condition in the given timeout */
			evtimer_add(&qry->noreply_timer, &base->tv_noreply);
			if(qry->opt_qbuf) {
				buf_init(&qry->qbuf, -1);
				buf_add_b64(&qry->qbuf, outbuff, qry->pktsize, 0);
			}

		}
		else {
			err  = 1;
			base->sendfail++;
			snprintf(line, DEFAULT_LINE_LENGTH, "%s \"senderror\" : \"AF %s, %s\"", qry->err.size ? ", " : ""
					, strerror(errno) ,  qry->res->ai_family == AF_INET ? "AF_INET" :"NOT AF_INET"); 
			buf_add(&qry->err, line, strlen(line));
		}
	} while ((qry->res = qry->res->ai_next) != NULL);
	free (outbuff);
	outbuff = NULL;
	if(err) {
		printReply (qry, 0, NULL);
		return;
	}
}

static void next_qry_cb(int unused  UNUSED_PARAM, const short event UNUSED_PARAM, void *h) {
	struct query_state *qry = h;
	BLURT(LVL5 "next query for %s",  qry->server_name);
	tdig_start(qry);  
}

/* The callback to handle timeouts due to destination host unreachable condition */
static void noreply_callback(int unused  UNUSED_PARAM, const short event UNUSED_PARAM, void *h)
{
	struct query_state *qry = h;
	qry->base->timeout++;
	snprintf(line, DEFAULT_LINE_LENGTH, "%s \"timeout\" : %d", qry->err.size ? ", " : "", DEFAULT_NOREPLY_TIMEOUT);
	buf_add(&qry->err, line, strlen(line));

	BLURT(LVL5 "AAA timeout for %s ", qry->server_name);
	printReply (qry, 0, NULL);
	return;
} 

static void tcp_timeout_callback (int __attribute((unused)) unused, 
		const short __attribute((unused)) event, void *s)
{
	struct query_state * qry;
	qry = ENV2QRY(s);
	noreply_callback(0, 0, qry);
}

static void tcp_reporterr(struct tu_env *env, enum tu_err cause,
                const char *str)
{
	struct query_state * qry;
	qry = ENV2QRY(env);

       // if (env != &state->tu_env) abort();  // Why do i need this? AA

        switch(cause)
        {
        case TU_DNS_ERR:

		snprintf(line, DEFAULT_LINE_LENGTH, "%s \"TUDNS\" : \"%s\"", qry->err.size ? ", " : "", str );
		buf_add(&qry->err, line, strlen(line));
                break;

        case TU_READ_ERR:
		// need more than this reporting for this case AA
		snprintf(line, DEFAULT_LINE_LENGTH, "%s \"TU_READ_ERR\" : \"%s\"", qry->err.size ? ", " : "", str );
		buf_add(&qry->err, line, strlen(line));
                break;

        case TU_CONNECT_ERR:
		snprintf(line, DEFAULT_LINE_LENGTH, "%s \"TUCONNECT\" : \"%s\"", qry->err.size ? ", " : "", str );
		buf_add(&qry->err, line, strlen(line));
		//reconnect next one AA 
                break;

        case TU_OUT_OF_ADDRS:
		snprintf(line, DEFAULT_LINE_LENGTH, "%s \"TU_OUT_OF_ADDRESS\" : \"%s\"", qry->err.size ? ", " : "", str );
		buf_add(&qry->err, line, strlen(line));
                break;

        default:
		snprintf(line, DEFAULT_LINE_LENGTH, "%s \"TU_UNKNOWN\" : \"%d %s\"", qry->err.size ? ", " : "", cause, str );
                crondlog(DIE9 "reporterr: bad cause %d", cause);
		break;
        }
	printReply (qry, 0, NULL);
}

static void tcp_dnscount(struct tu_env *env, int count)
{
	struct query_state * qry;
	qry = ENV2QRY(env); 
	BLURT(LVL5 "dns count for %s : %d", qry->server_name , count);
}

static void tcp_beforeconnect(struct tu_env *env,
        struct sockaddr *addr, socklen_t addrlen)
{
	struct query_state * qry;
	qry = ENV2QRY(env); 
	gettimeofday(&qry->xmit_time, NULL); 
	qry->dst_ai_family = addr->sa_family;
	BLURT(LVL5 "time : %d",  qry->xmit_time.tv_sec);
	getnameinfo(addr, addrlen, qry->dst_addr_str, INET6_ADDRSTRLEN , NULL, 0, NI_NUMERICHOST);
}

static void tcp_connected(struct tu_env *env, struct bufferevent *bev)
{
	uint16_t payload_len ;
	u_char *outbuff;	
	u_char *wire;
	struct query_state * qry; 
	qry = ENV2QRY(env); 

	qry->loc_socklen= sizeof(qry->loc_sin6);
        getsockname(bufferevent_getfd(bev), &qry->loc_sin6, &qry->loc_socklen);

	qry->bev_tcp =  bev;
	outbuff = xzalloc(MAX_DNS_BUF_SIZE);
	bzero(outbuff, MAX_DNS_OUT_BUF_SIZE);
	mk_dns_buff(qry, outbuff);
	payload_len = (uint16_t) qry->pktsize;
	wire = xzalloc (payload_len + 4);
	ldns_write_uint16(wire, qry->pktsize);
	memcpy(wire + 2, outbuff, qry->pktsize);
	evbuffer_add(bufferevent_get_output(qry->bev_tcp), wire, (qry->pktsize +2));
	qry->base->sentok++;
	qry->base->sentbytes+= (qry->pktsize +2);
	BLURT(LVL5 "send %u bytes", payload_len );

	if(qry->opt_qbuf) {
		buf_init(&qry->qbuf, -1);
		buf_add_b64(&qry->qbuf, outbuff, qry->pktsize, 0);
	}
	free(outbuff);
	free(wire);
}

static void tcp_readcb(struct bufferevent *bev UNUSED_PARAM, void *ptr) 
{

        struct query_state *qry = ptr;
        int n;
        u_char b2[2];
        struct timeval rectime;
        struct evbuffer *input ;
        struct DNS_HEADER *dnsR = NULL;

        qry = ENV2QRY(ptr);
	BLURT(LVL5 "TCP readcb %s", qry->server_name );

	if( qry->packet.size && (qry->packet.size >= qry->wire_size)) {
		snprintf(line, DEFAULT_LINE_LENGTH, "%s \"TCPREADSIZE\" : "
				" \"red more bytes than expected %d, got %zu\""
				, qry->err.size ? ", " : ""
				, qry->wire_size, qry->packet.size);
		buf_add(&qry->err, line, strlen(line));	
		printReply (qry, 0, NULL);
		return;
	}

        gettimeofday(&rectime, NULL);
        bzero(qry->base->packet, MAX_DNS_BUF_SIZE);

        input = bufferevent_get_input(bev);
        if(qry->wire_size == 0) {
                n = evbuffer_remove(input, b2, 2 );
		if(n == 2){
			qry->wire_size = ldns_read_uint16(b2);
			buf_init(&qry->packet, -1);
		}
		else {

			snprintf(line, DEFAULT_LINE_LENGTH, "%s \"TCPREAD\" : \"expected 2 bytes and got %d\"", qry->err.size ? ", " : "", n );
			buf_add(&qry->err, line, strlen(line));	
		}
	} 
	while ((n = evbuffer_remove(input,line , DEFAULT_LINE_LENGTH )) > 0) {
		buf_add(&qry->packet, line, n);
		if(qry->wire_size == qry->packet.size) {
			crondlog(LVL5 "in readcb %s %s red %d bytes ", qry->str_Atlas, qry->server_name,  qry->wire_size);
			crondlog(LVL5 "qry pointer address readcb %p qry.id, %d", qry->qryid);
			crondlog(LVL5 "DBG: base pointer address readcb %p",  qry->base );
			dnsR = (struct DNS_HEADER*) qry->packet.buf;
			if ( ntohs(dnsR->id)  == qry->qryid ) {
				qry->triptime = (rectime.tv_sec - qry->xmit_time.tv_sec)*1000 + (rectime.tv_usec-qry->xmit_time.tv_usec)/1e3;
				printReply (qry, qry->packet.size, qry->packet.buf);
			}
			else {
				bzero(line, DEFAULT_LINE_LENGTH);
				snprintf(line, DEFAULT_LINE_LENGTH, " %s \"idmismatch\" : \"mismatch id from tcp fd %d\"", qry->err.size ? ", " : "", n);
				buf_add(&qry->err, line, strlen(line));
				printReply (qry, 0, NULL);
			}
			return;
		} 
	}
}

static void tcp_writecb(struct bufferevent *bev, void *ptr) 
{
	/*
	struct query_state * qry; 
	qry = ENV2QRY(ptr); 
	*/
	BLURT(LVL5 "TCP writecb");
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

static void process_reply(void * arg, int nrecv, struct timeval now, int af, void *remote )
{
	struct tdig_base *base = arg;

	struct DNS_HEADER *dnsR = NULL;

	struct query_state * qry;

	if (nrecv < sizeof (struct DNS_HEADER)) {
		base->shortpkt++;
		return;
	}

	dnsR = (struct DNS_HEADER*) base->packet;
	base->recvok++; 


	crondlog(LVL7 "DBG: base address process reply %p, nrec %d", base, nrecv);
	/* Get the pointer to the qry descriptor in our internal table */
	qry = tdig_lookup_query(base, ntohs(dnsR->id), af, remote);
	
	if ( ! qry) {
		base->martian++;
		crondlog(LVL7 "DBG: no match found for qry id i %d",\
ntohs(dnsR->id));
		return;
	}

	qry->base->recvbytes += nrecv;
	gettimeofday(&now, NULL);  // lave this till fix now from ready_callback6 corruption; ghoost
	qry->triptime = (now.tv_sec-qry->xmit_time.tv_sec)*1000 + (now.tv_usec-qry->xmit_time.tv_usec)/1e3;

	/* Clean the noreply timer */
	evtimer_del(&qry->noreply_timer);
	printReply (qry, nrecv, base->packet);
	return;
}

static void ready_callback4 (int unused UNUSED_PARAM, const short event UNUSED_PARAM, void * arg)
{
	struct tdig_base *base = arg;
	int nrecv;
	struct sockaddr_in remote4;                  /* responding internet address */
	socklen_t slen;
	struct timeval rectime;
	
	slen = sizeof(struct sockaddr);
	bzero(base->packet, MAX_DNS_BUF_SIZE);
	/* Time the packet has been received */

	gettimeofday(&rectime, NULL);
	/* Receive data from the network */
	nrecv = recvfrom(base->rawfd_v4, base->packet, sizeof(base->packet), MSG_DONTWAIT, &remote4, &slen);
	if (nrecv < 0) {
		/* One more failure */
		base->recvfail++;
		return ;
	}
	process_reply(arg, nrecv, rectime, remote4.sin_family, &remote4);
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
	struct sockaddr_in6 remote6;
	char cmsgbuf[256];

	/* Time the packet has been received */
	gettimeofday(&rectime, NULL);

	iov[0].iov_base= base->packet;
	iov[0].iov_len= sizeof(base->packet);

	msg.msg_name= &remote6;
	msg.msg_namelen= sizeof( struct sockaddr_in6);
	msg.msg_iov= iov;
	msg.msg_iovlen= 1;
	msg.msg_control= cmsgbuf;
	msg.msg_controllen= sizeof(cmsgbuf);
	msg.msg_flags= 0;                       /* Not really needed */

	nrecv= recvmsg(base->rawfd_v6, &msg, MSG_DONTWAIT);
	if (nrecv == -1) {
		/* Strange, read error */
		printf("ready_callback6: read error '%s'\n", strerror(errno));
		return;
	}
	process_reply(arg, nrecv, rectime, remote6.sin6_family, &remote6);

	return;
}

/* this called for each query/line in eperd */
static void *tdig_init(int argc, char *argv[], void (*done)(void *state))
{
	char *check;
	struct query_state *qry;
	int c;

	if(!tdig_base)
		tdig_base = tdig_base_new(EventBase);

	if(!tdig_base)
		crondlog(DIE9 "tdig_base_new failed");

	tdig_base->done = done;

	qry=xzalloc(sizeof(*qry));

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
	tdig_base->activeqry++;
	qry->qst = 0;
	qry->wire_size = 0;
	qry->triptime = 0;
	qry->opt_edns0 = 512; 
	qry->opt_dnssec = 0;
	qry->opt_nsid = 0; 
	qry->opt_qbuf = 0; 
	qry->opt_abuf = 1; 
	qry->opt_rd = 0;
	qry->opt_evdns = 0;
	qry->opt_prepend_probe_id = 0;
	qry->ressave = NULL;
	qry->ressent = NULL;
	buf_init(&qry->err, -1);
	buf_init(&qry->packet, -1);
	qry->opt_resolv_conf = (Q_RESOLV_CONF - 1);
	qry->lookupname = NULL;
	qry->dst_ai_family = 0;
	qry->loc_ai_family = 0;
	qry->loc_sin6.sin6_family = 0;

	/* initialize callbacks : */
	/* sendpacket  called by UDP send */
	evtimer_assign(&qry->nsm_timer, tdig_base->event_base,
		tdig_send_query_callback, qry);
	/* no reply timeout for udp  queries */
	evtimer_assign(&qry->noreply_timer, tdig_base->event_base,
		noreply_callback, qry); 

	/* callback/timer used for restarting query by --resove */
	evtimer_assign(&qry->next_qry_timer, tdig_base->event_base, next_qry_cb
			                ,qry);

	optind = 0;
	while (c= getopt_long(argc, argv, "46adD:e:tbhinqO:Rrs:A:?", longopts, NULL), c != -1) {
		switch(c) {
			case '4':
				qry->opt_v4_only = 1;
				qry->opt_AF = AF_INET;
				break;
			case '6':
				qry->opt_v6_only = 1;
				qry->opt_AF = AF_INET6;
				break;

			case 'a':
				qry->opt_v6_only = 1;
				qry->opt_v4_only = 1;
				break;

			case 'A':
				qry->str_Atlas = strdup(optarg);
				break;
			case 'b':
				qry->lookupname = strdup ("version.bind.");
				break;
		
			case 'd':
				qry->opt_dnssec = 1;
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

			case 'n':
				qry->opt_nsid = 1;
				break;

			case 'O':
				qry->out_filename = strdup(optarg);
				break;

			case 'r':
				qry->lookupname = strdup("version.server.");
				break;

			case 'R':
				qry->opt_rd = 1;
				break;

			case 's':
				qry->qtype = T_SOA;
				qry->qclass = C_IN;
				qry->lookupname = strdup(optarg);
				break;

			case 't':
				qry->opt_proto = 6;
				break;

			case 1001:
				qry->opt_qbuf = 1;
				break;

			case 1002:
				qry->opt_abuf = 0;
				break;

			case O_RESOLV_CONF :
				qry->opt_resolv_conf = Q_RESOLV_CONF ;
				qry->opt_v6_only = 1;
				qry->opt_v4_only = 1;
				break;

			case O_PREPEND_PROBE_ID:
				qry->opt_prepend_probe_id = 1;
				break;

			case O_EVDNS:
				qry->opt_evdns = 1;
				break;

			case (100000 + T_A):
				qry->qtype = T_A;
				qry->qclass = C_IN;
				qry->lookupname = strdup(optarg);
				break;

			case (100000 + T_NS):
				qry->qtype = T_NS;
				qry->qclass = C_IN;
				qry->lookupname = strdup(optarg);
				break;

			case (100000 + T_CNAME):
				qry->qtype = T_CNAME;
				qry->qclass = C_IN;
				qry->lookupname = strdup(optarg);
				break;

			case (100000 + T_PTR):
				qry->qtype = T_PTR;
				qry->qclass = C_IN;
				qry->lookupname = strdup(optarg);
				break;

			case (100000 + T_MX):
				qry->qtype = T_MX;
				qry->qclass = C_IN;
				qry->lookupname = strdup(optarg);
				break;

			case (100000 + T_TXT):
				qry->qtype = T_TXT;
				qry->qclass = C_IN;
				qry->lookupname =  strdup(optarg);
				break;

			case (100000 + T_AAAA ):
				qry->qtype = T_AAAA ;
				qry->qclass = C_IN;
				qry->lookupname = strdup(optarg);
				break;

			case (100000 + T_AXFR ):
				qry->qtype = T_AXFR ;
				qry->qclass = C_IN;
				qry->lookupname = strdup(optarg);
				break;

			case (100000 + T_ANY):
				qry->qtype = T_ANY ;
				qry->qclass = C_IN;
				qry->lookupname = strdup(optarg);
				break;

			case (100000 + T_DS):
				qry->qtype = T_DS;
				qry->qclass = C_IN;
				qry->lookupname  = strdup(optarg);
				break;

			case (100000 + T_NSEC):
				qry->qtype = T_NSEC;
				qry->qclass = C_IN;
				qry->lookupname = strdup(optarg);
				break;

			case (100000 + T_NSEC3):
				qry->qtype = T_NSEC3;
				qry->qclass = C_IN;
				qry->lookupname = strdup(optarg);
				break;

			case (100000 + T_DNSKEY):
				qry->qtype = T_DNSKEY;
				qry->qclass = C_IN;
				qry->lookupname = strdup(optarg);
				break;

			case (100000 + T_RRSIG):
				qry->qtype = T_RRSIG;
				qry->qclass = C_IN;
				qry->lookupname = strdup(optarg);
				break;break;

			default:
				fprintf(stderr, "ERROR unknown option %d ??\n", c); 
				 tdig_delete(qry);
				return (0);
				break;
		}
	}
	if( qry->opt_resolv_conf == Q_RESOLV_CONF ) {
		if(tdig_base->resolv_max ) {
			qry->opt_resolv_conf = 1;
			qry->server_name = strdup(tdig_base->nslist[0]);
		}
		else {
			// may be the /etc/resolv.conf is yet to red. 
			// try once then use it || give up
			tdig_base->resolv_max = get_local_resolvers (tdig_base->nslist);
			if(tdig_base->resolv_max ){
				qry->opt_resolv_conf = 1;
				qry->server_name = strdup(tdig_base->nslist[0]);
			}
			else {
				tdig_delete(qry);
				return NULL;
			}
		}
	}
	else if (optind != argc-1)  {
		crondlog(LVL9 "ERROR no server IP address in input");
		tdig_delete(qry);
		return NULL;
	}
	else 
		qry->server_name = strdup(argv[optind]);

	 if(qry->lookupname == NULL) {
		crondlog(LVL9 "ERROR no query in command line");
		tdig_delete(qry);
		return NULL;
	}

	if (qry->out_filename &&
		!validate_filename(qry->out_filename, SAFE_PREFIX))
	{
		crondlog(LVL8 "insecure file '%s'", qry->out_filename);
		tdig_delete(qry);
		return NULL;
	}


	if(qry->opt_v6_only  == 0)
	{
		qry->opt_v4_only = 1;
		qry->opt_AF = AF_INET;
	}
	qry->base = tdig_base;

	/* insert this qry into the list of queries */
	if (!tdig_base->qry_head) {
		qry->next = qry->prev = qry;
		tdig_base->qry_head = qry;
		tdig_stats( 0, 0, tdig_base); // call this first time to initial values.
		crondlog(LVL7 "new head qry %s qry->prev %s qry->next %s", qry->str_Atlas,  qry->prev->str_Atlas,  qry->next->str_Atlas);
	} 
	else {	
		crondlog(LVL7 "old head hea %s hea->prev %s hea->next %s", tdig_base->qry_head->str_Atlas,  tdig_base->qry_head->prev->str_Atlas,  tdig_base->qry_head->next->str_Atlas);
		if (tdig_base->qry_head->prev == tdig_base->qry_head) {
			tdig_base->qry_head->prev = qry;
			crondlog(LVL7 "head->prev == head quereis %d AA", tdig_base->activeqry);
		}
		qry->next = tdig_base->qry_head->next;
		qry->prev = tdig_base->qry_head;
		tdig_base->qry_head->next->prev = qry;
		tdig_base->qry_head->next = qry;
		crondlog(LVL7 " qry %s qry->prev %s qry->next  %s", qry->str_Atlas,  qry->prev->str_Atlas,  qry->next->str_Atlas);
		crondlog(LVL7 "new head hea %s hea->prev %s hea->next %s", tdig_base->qry_head->str_Atlas,  tdig_base->qry_head->prev->str_Atlas,  tdig_base->qry_head->next->str_Atlas);
	}
	return qry;
}

/* called only once. Initialize tdig_base variables here */
struct tdig_base * tdig_base_new(struct event_base *event_base)
{
	evutil_socket_t fd6;
	evutil_socket_t fd4;
	struct addrinfo hints;
	int on = 1;
	struct timeval tv;

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

	tdig_base->qry_head = NULL;
	tdig_base->sendfail = 0;
	tdig_base->sentok  = 0;
	tdig_base->recvfail  = 0;
	tdig_base->recvok  = 0;
	tdig_base->martian  = 0;
	tdig_base->shortpkt  = 0;
	tdig_base->sentbytes  = 0;
	tdig_base->recvbytes = 0;
	tdig_base->timeout = 0;
	tdig_base->activeqry = 0;
	tdig_base->resolv_max = 0;

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

	// Define the callback to handle UDP Reply 
	// add the raw file descriptor to those monitored for read events 

	event_assign(&tdig_base->event4, tdig_base->event_base, tdig_base->rawfd_v4, 
			EV_READ | EV_PERSIST, ready_callback4, tdig_base);
	event_add(&tdig_base->event4, NULL);

	event_assign(&tdig_base->event6, tdig_base->event_base, tdig_base->rawfd_v6, 
			EV_READ | EV_PERSIST, ready_callback6, tdig_base);
	event_add(&tdig_base->event6, NULL);
	
	evtimer_assign(&tdig_base->statsReportEvent, tdig_base->event_base, tdig_stats, tdig_base);
	tv.tv_sec =  DEFAULT_STATS_REPORT_INTERVEL;
	tv.tv_usec =  0;
	event_add(&tdig_base->statsReportEvent, &tv);

	return tdig_base;
}

static void udp_dns_cb(int err, struct evutil_addrinfo *ev_res, struct query_state *qry) {
	
	if (err)  {
		qry->qst = STATUS_FREE;
		snprintf(line, DEFAULT_LINE_LENGTH, "\"evdns_getaddrinfo\": \"%s\"", evutil_gai_strerror(err));
		buf_add(&qry->err, line, strlen(line));
		printReply (qry, 0, NULL);
		return ;

	}
	else {
		qry->res = ev_res;
		qry->ressave = ev_res;
		tdig_send_query_callback(0, 0, qry);
	}
}

void tdig_start (struct query_state *qry)
{
	struct timeval asap = { 0, 0 };
	struct timeval interval;

	int err_num;
	struct addrinfo hints, *res;
	char port[] = "domain";
	char port_as_char[] = "53";  

	switch(qry->qst)
	{
		case STATUS_NEXT_QUERY :
		case  STATUS_FREE :
			break;
		default:
			printErrorQuick(qry);
			return ;
	}

	if(qry->opt_resolv_conf > tdig_base->resolv_max) {
		qry->opt_resolv_conf = 0;
		free (qry->server_name);
		qry->server_name = strdup(tdig_base->nslist[qry->opt_resolv_conf]);
		qry->opt_resolv_conf++;
	}

	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = 0;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = 0;

	gettimeofday(&qry->xmit_time, NULL);
	qry->qst =  STATUS_DNS_RESOLV;

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

	if(qry->opt_proto == 17) {  //UDP 
		if(qry->opt_evdns ) {
			// use EVDNS asynchronous call 
			evdns_getaddrinfo(DnsBase, qry->server_name, port_as_char , &hints, udp_dns_cb, qry);
		}
		else {
			// using getaddrinfo; blocking call
			if ( ( err_num  = getaddrinfo(qry->server_name, port , &hints, &res)))
			{
				snprintf(line, DEFAULT_LINE_LENGTH, "%s \"getaddrinfo\": \"port %s, AF %d %s\"", qry->err.size ? ", " : "",  port,  hints.ai_family, gai_strerror(err_num));
				buf_add(&qry->err, line, strlen(line));

				printReply (qry, 0, NULL);
				qry->qst = STATUS_FREE;
				return ;
			}

			qry->res = res;
			qry->ressave = res;

			evtimer_add(&qry->nsm_timer, &asap);
		}
	}
	else { // TCP Query

		qry->wire_size =  0;
		crondlog(LVL5 "TCP QUERY %s", qry->server_name);
		interval.tv_sec = CONN_TO;
		interval.tv_usec= 0;
		tu_connect_to_name (&qry->tu_env,   qry->server_name, port_as_char,
				&interval, &hints, tcp_timeout_callback, tcp_reporterr,
				tcp_dnscount, tcp_beforeconnect,
				tcp_connected, tcp_readcb, tcp_writecb);

	}
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

#endif

static void tdig_stats(int unusg_statsed UNUSED_PARAM, const short event UNUSED_PARAM, void *h)
{
	struct timeval now;
	FILE *fh;	
	struct tdig_base *base;
	struct query_state *qry;

	base = h;	
	if(!base->qry_head )
		return;

	qry = base->qry_head; 

	if(! base->sentok )
		return;

	if (qry->out_filename) {
		fh= fopen(qry->out_filename, "a");
		if (!fh)
			crondlog(DIE9 "unable to append to '%s'", qry->out_filename);
	}
	else
		fh = stdout;  

	fprintf(fh, "RESULT { ");
	JS(id, "9201" ); 
	gettimeofday(&now, NULL); 
	JS1(time, %ld,  now.tv_sec);
	JU(sok , base->sentok);
	JU(rok , base->recvok);
	JU(sent , base->sentbytes);
	JU(recv , base->recvbytes);
	JU(serr , base->sendfail);
	JU(rerr , base->recvfail);
	JU(timeout , base->timeout);
	JU(short , base->shortpkt);
	JU(martian, base->martian);
	JU_NC(q, base->activeqry);

	fprintf(fh, " }\n");
	if (qry->out_filename) 
		fclose (fh);
	// reuse timeval now
	now.tv_sec =  DEFAULT_STATS_REPORT_INTERVEL;
	now.tv_usec =  0;
	event_add(&tdig_base->statsReportEvent, &now);
}


static void ChangetoDnsNameFormat(u_char *  dns, char* qry)
{
	int lock = 0, i;

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
	struct timeval asap = { 0, 0 };
	BLURT(LVL5 "freeing instance of %s ", qry->server_name);

	if(qry->err.size) 
	{
		buf_cleanup(&qry->err);
	} 
	if(qry->qbuf.size)  
		buf_cleanup(&qry->qbuf);

	if(qry->ressave  && qry->opt_evdns) {
		evutil_freeaddrinfo(qry->ressave);
		qry->ressave  = NULL;
		qry->ressent = NULL;
	}
	else if (qry->ressave )
	{
		freeaddrinfo(qry->ressave);
		qry->ressave  = NULL;
		qry->ressent = NULL;
	}
	qry->qst = STATUS_FREE;
	qry->wire_size = 0;

	if(qry->packet.size)
	{
		buf_cleanup(&qry->packet);
	}

	if(qry->opt_proto == 6)
		tu_cleanup(&qry->tu_env);

	if ( qry->opt_resolv_conf > Q_RESOLV_CONF ) {
		// this loop goes over servers in /etc/resolv.conf
		// select the next server and restart
		if(qry->opt_resolv_conf < tdig_base->resolv_max) {
			free (qry->server_name);
			qry->server_name = strdup(tdig_base->nslist[qry->opt_resolv_conf]);
			qry->opt_resolv_conf++;
			qry->qst = STATUS_NEXT_QUERY;
			evtimer_add(&qry->next_qry_timer, &asap);
			return;
		}
		else 
			qry->opt_resolv_conf++;
	}

	if(qry->base->done)
	{
		qry->base->done(qry);
	/*
		void (*terminator)(void *state);
		struct event_base *event_base;
		struct tdig_base *tbase;
		terminator = qry->base->done;
		event_base = qry->base->event_base;
		if(DnsBase) {
			evdns_base_free(DnsBase, 0);
			DnsBase = NULL;
		}
		tbase = qry->base;
		tdig_delete(qry);
		free(tbase);
		event_base_loopbreak(event_base);
		event_base_free(event_base);
		terminator(qry);
	*/
	}
	
}


static int tdig_delete(void *state)
{
	struct query_state *qry;

	qry = state;
	
	if (qry->qst )
		return 0;

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

	/* Delete timers */
	evtimer_del(&qry->noreply_timer);
	evtimer_del(&qry->nsm_timer);

	if((qry->next == qry->prev) && (qry->next == qry)) {
		qry->base->qry_head =  NULL;
		crondlog(LVL7 "deleted last query qry %s", qry->str_Atlas);
	}
	else {
#if  ENABLE_FEATURE_EVTDIG_DEBUG
		crondlog(LVL7 "deleted qry %s qry->prev %s qry->next %s qry_head %s", qry->str_Atlas,  qry->prev->str_Atlas,  qry->next->str_Atlas, qry->base->qry_head->str_Atlas);
		crondlog(LVL7 "old qry->next->prev %s qry->prev->next  %s", qry->next->prev->str_Atlas,  qry->prev->next->str_Atlas);
#endif
		if(qry->next)
			qry->next->prev = qry->prev; 
		if(qry->prev)
			qry->prev->next = qry->next;
		if(qry->base && qry->base->qry_head == qry) 
			qry->base->qry_head = qry->next;

#if  ENABLE_FEATURE_EVTDIG_DEBUG
		crondlog(LVL7 "new qry->next->prev %s qry->prev->next  %s", qry->next->prev->str_Atlas,    qry->prev->next->str_Atlas);
#endif
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
	if(qry->base) 
		qry->base->activeqry--;
	free(qry);
	qry  = NULL;
	return 1;
} 

void printErrorQuick (struct query_state *qry)
{
	FILE *fh; 
	struct timeval now;
	if (qry->out_filename)
	{
		fh= fopen(qry->out_filename, "a");
		if (!fh)
			crondlog(DIE9 "unable to append to '%s'",
					qry->out_filename);
	}
	else
		fh = stdout;

	fprintf(fh, "RESULT { ");
	if(qry->str_Atlas) 
	{
		JS(id,  qry->str_Atlas);
	}
	gettimeofday(&now, NULL);
	JS1(time, %ld,  now.tv_sec);

	snprintf(line, DEFAULT_LINE_LENGTH, "\"query busy\": \"too frequent. previous one is not done yet\"");
	fprintf(fh, "\"error\" : { %s }" , line);

	fprintf(fh, " }");
	fprintf(fh, "\n");
	if (qry->out_filename)
		fclose(fh);
}


void printReply(struct query_state *qry, int wire_size, unsigned char *result )
{
	int i, stop=0;
	unsigned char *qname, *reader;
	struct DNS_HEADER *dnsR = NULL;
	struct RES_RECORD answers[20]; //the replies from the DNS server
	void *ptr = NULL;
	char addrstr[100];
	FILE *fh; 
	//char buf[INET6_ADDRSTRLEN];
	u_int32_t serial;
	struct buf tmpbuf;
	char str[4]; 
	int iMax ;
	int flagAnswer = 1;
	int data_len;

	if (qry->out_filename)
	{
		fh= fopen(qry->out_filename, "a");
		if (!fh)
			crondlog(DIE9 "unable to append to '%s'",
					qry->out_filename);
	}
	else
		fh = stdout;

	fprintf(fh, "RESULT { ");
	if(qry->str_Atlas) 
	{
		JS(id,  qry->str_Atlas);
	}
	JS1(time, %ld,  qry->xmit_time.tv_sec);
	if ( qry->opt_resolv_conf > Q_RESOLV_CONF ) {
		JD (subid, qry->opt_resolv_conf);
		JD (submax, qry->base->resolv_max);
	}
	if( qry->ressent)
	{  // started to send query
	   // historic resaons only works with UDP 
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
		if(strcmp(addrstr, qry->server_name)) {
			JS(name,  qry->server_name);
		}
		JS(dst_addr, addrstr);
		JD(af, qry->ressent->ai_family == PF_INET6 ? 6 : 4);
	}
	else if(qry->dst_ai_family)
	{
		if(strcmp(qry->dst_addr_str, qry->server_name)) {
			JS(dst_name,  qry->server_name);
		}
		JS(dst_addr , qry->dst_addr_str);
		JD(af, qry->dst_ai_family == PF_INET6 ? 6 : 4);
	}
	else {
		JS(dst_name,  qry->server_name);
	}
	if(qry->loc_sin6.sin6_family) {
		line[0]  = '\0';
		getnameinfo((struct sockaddr *)&qry->loc_sin6,
				qry->loc_socklen, line, sizeof(line),
				NULL, 0, NI_NUMERICHOST);
		if(strlen(line)) 
			JS(src_addr, line); 
	}

	JS_NC(proto, qry->opt_proto == 6 ? "TCP" : "UDP" );
	if(qry->opt_qbuf && qry->qbuf.size) {
		str[0]  = '\0';
		buf_add(&qry->qbuf, str, 1);
		JC;
		JS_NC(qbuf, qry->qbuf.buf );
	} 

      
	if(result)
	{
		dnsR = (struct DNS_HEADER*) result;

		//point to the query portion
		qname =(unsigned char*)&result[sizeof(struct DNS_HEADER)];

		//move ahead of the dns header and the query field
		reader = &result[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];

		fprintf (fh, ", \"result\" : { ");
		fprintf (fh, " \"rt\" : %.3f", qry->triptime);
		fprintf (fh, " , \"size\" : %d", wire_size);
		fprintf (fh, " , \"ID\" : %d", ntohs(dnsR->id));
		/*
		fprintf (fh, " , \"RCODE\" : %d",  dnsR->rcode);
		fprintf (fh, " , \"AA\" : %d",  dnsR->aa);
		fprintf (fh, " , \"TC\" : %d",  dnsR->tc);
		*/
		fprintf (fh, " , \"ANCOUNT\" : %d ", ntohs(dnsR->ans_count ));
		fprintf (fh, " , \"QDCOUNT\" : %u ",ntohs(dnsR->q_count));
		fprintf (fh, " , \"NSCOUNT\" : %d" , ntohs(dnsR->ns_count));
		fprintf (fh, " , \"ARCOUNT\" : %d ",ntohs(dnsR->add_count));

		str[0]  = '\0'; 
		if(qry->opt_abuf) {
			JC;
			buf_init(&tmpbuf, -1);
			buf_add_b64(&tmpbuf, result, wire_size, 0);
			buf_add(&tmpbuf, str, 1);
			JS_NC(abuf, tmpbuf.buf );
			buf_cleanup(&tmpbuf); 
		}

		stop=0;  
		iMax = 0;
		
		if (dnsR->ans_count > 0)
		{
			iMax = MIN(2, ntohs(dnsR->ans_count));

			for(i=0;i<iMax;i++)
			{
				answers[i].name=ReadName(result,wire_size,
					reader-result,&stop);
				reader = reader + stop;

				answers[i].resource = (struct R_DATA*)(reader);
				reader = reader + sizeof(struct R_DATA);

				answers[i].rdata  = NULL;


				if(ntohs(answers[i].resource->type)==T_TXT) //txt
				{
					answers[i].rdata =  NULL;
					data_len = ntohs(answers[i].resource->data_len) - 1;

					if(flagAnswer) {
						fprintf (fh, ", \"answers\" : [ ");
						flagAnswer = 0;
					}
					if (flagAnswer == 0) {
						if(i > 0) 
							fprintf(fh, ", ");
						fprintf(fh, " { ");
					}
					fprintf(fh, " \"TYPE\" : \"TXT\"");
					fprintf(fh, " , \"NAME\" : \"%s.\" ",answers[i].name);
					print_txt_json(&result[reader-result+1], data_len, fh);
					reader = reader + ntohs(answers[i].resource->data_len);
					if(flagAnswer == 0) 
						fprintf(fh, " } ");

				}
				else if (ntohs(answers[i].resource->type)== T_SOA)
				{
					if(flagAnswer) {
						fprintf (fh, ", \"answers\" : [ ");
						flagAnswer = 0;
					}
					if (flagAnswer == 0) {
					if(i > 0) 
						fprintf(fh, ", ");
					fprintf(fh, " { ");
					}

	
					JS(TYPE, "SOA");
					JSDOT(NAME, answers[i].name);
					JU(TTL, ntohl(answers[i].resource->ttl));
					answers[i].rdata = ReadName(
						result,wire_size,
						reader-result,&stop);
					JSDOT( MNAME, answers[i].rdata);
					reader =  reader + stop;
					free(answers[i].rdata);
					answers[i].rdata = ReadName(
						result,wire_size,
						reader-result,&stop);
					JSDOT( RNAME, answers[i].rdata);
					reader =  reader + stop;
					serial = get32b(reader);
					JU_NC(SERIAL, serial);
					reader =  reader + 4;
					reader =  reader + 16; // skip REFRESH, RETRY, EXIPIRE, and MINIMUM
					if(flagAnswer == 0) 
						fprintf(fh, " } ");
				}
				else  
				{
					// JU(TYPE, ntohs(answers[i].resource->type));
					// JU_NC(RDLENGTH, ntohs(answers[i].resource->data_len))
					reader =  reader + ntohs(answers[i].resource->data_len);
				}
	
				fflush(fh);
				// free mem 
				if(answers[i].rdata != NULL) 
					free (answers[i].rdata); 
			}
			if(flagAnswer == 0) 
				fprintf (fh, " ]");
		}

		for(i=0;i<iMax;i++)
		{
			free(answers[i].name);
		}

		fprintf (fh , " }"); //result
	} 
	if(qry->err.size) 
	{
		line[0]  = '\0';
		buf_add(&qry->err, line, 1 );
		fprintf(fh, ", \"error\" : { %s }" , qry->err.buf);
	}
	fprintf(fh, " }");
	fprintf(fh, "\n");
	if (qry->out_filename)
		fclose(fh);
	free_qry_inst(qry);
}

unsigned char* ReadName(unsigned char *base, size_t size, size_t offset,
	int* count)
{
	unsigned char *name;
	unsigned int p=0,jumped=0, len;

	*count = 0;
	name = (unsigned char*)malloc(256);

	name[0]= '\0';

	//read the names in 3www6google3com format
	while(len= base[offset], len !=0)
	{
		if (len & 0xc0)
		{
			if ((len & 0xc0) != 0xc0)
			{
				/* Bad format */
				strcpy(name, "format-error");
				printf("format-error: len = %d\n",
					len);
				abort();
				return name;
			}

			offset= ((len & ~0xc0) << 8) | base[offset+1];
			if (offset >= size)
			{
				strcpy(name, "offset-error");
				printf("offset-error\n");
				abort();
				return name;
			}
			if(jumped==0)
			{
				/* if we havent jumped to another location
				 * then we can count up
				 */
				*count += 2;
			}
			jumped= 1;
			continue;
		}
		if (offset+len+1 > size)
		{
			strcpy(name, "buf-bounds-error");
			printf("buf-bounds-error\n");
			abort();
			return name;
		}

		if (p+len+1 > 255)
		{
			strcpy(name, "name-length-error");
			printf("name-length-error\n");
			abort();
			return name;
		}
		memcpy(name+p, base+offset+1, len);
		name[p+len]= '.';
		p += len+1;
		offset += len+1;
		
		if(jumped==0)
		{
			/* if we havent jumped to another location then we
			 * can count up 
			 */
			*count += len+1;
		}
	}

	if (!jumped)
		(*count)++;	/* Terminating zero length */

	name[p]= '\0'; //string complete

	if(p >  0)
		name[p-1]= '\0'; //remove the last dot
	return name;
}

/* get 4 bytes from memory
 * eg.  used to extract serial number from soa packet
 */
	u_int32_t
get32b (char *p)
{
	u_int32_t var;

	var = (0x000000ff & *(p)) << 24;
	var |= (0x000000ff & *(p+1)) << 16;
	var |= (0x000000ff & *(p+2)) << 8;
	var |= (0x000000ff & *(p+3));

	return (var);
}

/*
 * Copy data allowing for unaligned accesses in network byte order
 * (big endian).
 */
void ldns_write_uint16(void *dst, uint16_t data)
{
#ifdef ALLOW_UNALIGNED_ACCESSES
        * (uint16_t *) dst = htons(data);
#else
        uint8_t *p = (uint8_t *) dst;
        p[0] = (uint8_t) ((data >> 8) & 0xff);
        p[1] = (uint8_t) (data & 0xff);
#endif
}

uint16_t
ldns_read_uint16(const void *src)
{
#ifdef ALLOW_UNALIGNED_ACCESSES
        return ntohs(*(uint16_t *) src);
#else
        uint8_t *p = (uint8_t *) src;
        return ((uint16_t) p[0] << 8) | (uint16_t) p[1];
#endif
}

struct testops tdig_ops = { tdig_init, tdig_start, tdig_delete }; 
