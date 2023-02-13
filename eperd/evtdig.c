/*
 * Copyright (c) 2011-2014 RIPE NCC <atlas@ripe.net>
 * Copyright (c) 2009 Rocco Carbone <ro...@tecsiel.it>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */
//config:config EVTDIG
//config:       bool "evtdig"
//config:       default n
//config:       depends on EPERD
//config:       help
//config:          tiny dig event driven version. support only limited queries id.sever
//config:          txt chaos.  RIPE NCC 2011

//config:config FEATURE_EVTDIG_TLS
//config:       bool "Enable DNS over TLS."
//config:       default n
//config:       depends on EVTDIG
//config:       help
//config:        Enable DNS over TLS. 2016 IETF Dprive draft

//config:config FEATURE_EVTDIG_DEBUG
//config:       bool "Enable debug support in evtdig"
//config:       default n
//config:       depends on EVTDIG
//config:       help
//config:        extra debug info. Also may cause segfault or/and memory leak. Add at your own risk.

//applet:IF_EVTDIG(APPLET(evtdig, BB_DIR_ROOT, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_EVTDIG) += evtdig.o

//usage:#define evtdig_trivial_usage
//usage:	"-[46adtbhinqRr]"
//usage:	"[-A <atlas>][-B <bundle>][-I <interface>]"
//usage:	"\n\t[--ad]"
//usage:	"[--cd]"
//usage:	"[--client-subnet]"
//usage:	"[--cookies]"
//usage:	"[--do]"
//usage:	"\n\t[--edns0 <size>]"
//usage:	"[--edns-flags <value>]"
//usage:	"[--edns-option <value>]"
//usage:	"\n\t[--edns-version <value>]"
//usage:	"[--https]"
//usage:	"[--https-path <path>]"
//usage:	"\n\t[--ipv6-dest-option <size>]"
//usage:	"[--noabuf]"
//usage:	"[--nsid]"
//usage:	"[--out-file <name>]"
//usage:	"\n\t[--port <value>]"
//usage:	"[--p_probe_id]"
//usage:	"[--qbuf]"
//usage:	"[--read-response <name>]"
//usage:	"\n\t[--resolv]"
//usage:	"[--retry <count>]"
//usage:	"[--sni-cert-name <name>]"
//usage:	"\n\t[--timeout <ms>]"
//usage:	"[--tls]"
//usage:	"[--ttl]"
//usage:	"[--write-response <name>]"
//usage:	"\n\t[--type <type>][--class <class>][--query <name>]"
//usage:	"\n\t[--a <name>]"
//usage:	"[--aaaa <name>]"
//usage:	"[--any <name>]"
//usage:	"[--afsdb <name>]"
//usage:	"\n\t[--apl <name>]"
//usage:	"[--axfr <name>]"
//usage:	"[--caa <name>]"
//usage:	"[--cert <name>]"
//usage:	"\n\t[--cname <name>]"
//usage:	"[--dlv <name>]"
//usage:	"[--dname <name>]"
//usage:	"[--dnskey <name>]"
//usage:	"\n\t[--ds <name>]"
//usage:	"[--ipseckey <name>]"
//usage:	"[--loc <name>]"
//usage:	"\n\t[--mx <name>]"
//usage:	"[--naptr <name>]"
//usage:	"[--ns <name>]"
//usage:	"[--nsec <name>]"
//usage:	"\n\t[--nsec3 <name>]"
//usage:	"[--nsec3param <name>]"
//usage:	"[--ptr <name>]"
//usage:	"[--rrsig <name>]"
//usage:	"\n\t[--rp <name>]"
//usage:	"[--soa <name>]"
//usage:	"[--sig <name>]"
//usage:	"[--spf <name>]"
//usage:	"\n\t[--sshfp <name>]"
//usage:	"[--srv <name>]"
//usage:	"[--ta <name>]"
//usage:	"[--tlsa <name>]"
//usage:	"\n\t[--txt <name>]"
//usage:	"\n\t[--hostname.bind]"
//usage:	"[--id.server]"
//usage:	"[--version.bind]"
//usage:	"[--version.server]"
//usage:	"\n\t[<server>]"
//usage:#define evtdig_full_usage "\n\n"
//usage:	"\nOptions:"
//usage:	"\n\t-4                  Restrict to IPv4"
//usage:	"\n\t-6                  Restrict to IPv6"
//usage:	"\n\t-a                  Both IPv4 and IPv6"
//usage:	"\n\t-R                  Set recursion desired flag"
//usage:	"\n\t-t                  Use TCP"
//usage:	"\n\t-A <atlas>          Atlas measurement ID"
//usage:	"\n\t-B <bundle>         Atlas bundle ID"
//usage:	"\n\t-I <interface>      Outgoing interface"
//usage:	"\n\t--ad                Set AD (Authentic Data) bit"
//usage:	"\n\t--cd                Set CD (Checking Disabled) bit"
//usage:	"\n\t--client-subnet     Include edns-client-subnet option"
//usage:	"\n\t--cookies           Send and receive cookies"
//usage:	"\n\t-d|--do             Set DO (DNSSEC answer OK) bit"
//usage:	"\n\t-e|--edns0 <size>   Max. UDP message size"
//usage:	"\n\t--edns-flags <value>      EDNS flags field"
//usage:	"\n\t--edns-option <value>     Include empty EDNS option"
//usage:	"\n\t--edns-version <value>    Set EDNS version"
//usage:	"\n\t--https             Connect using HTTPS (HTTP2 over TLS)"
//usage:	"\n\t--https-path <path> Path for HTTPS (default /dns-query)"
//usage:	"\n\t--ipv6-dest-option <size> Include IPv6 dest. option"
//usage:	"\n\t--noabuf            Omit abuf from output"
//usage:	"\n\t-n|--nsid           Include NSID option"
//usage:	"\n\t-O|--out-file <name> Name of output file"
//usage:	"\n\t--port <value>      Destination port number"
//usage:	"\n\t--p_probe_id        Prepend probe ID to query name"
//usage:	"\n\t--qbuf              Include qbuf in output"
//usage:	"\n\t--read-response <name>    Read responses"
//usage:	"\n\t--resolv            Use system resolvers as targets"
//usage:	"\n\t--retry <count>     Retry query count times"
//usage:	"\n\t--sni-cert-name <name> Name to check in cert and SNI"
//usage:	"\n\t--timeout <ms>      Timeout waiting for reply"
//usage:	"\n\t--tls               Connect using TLS"
//usage:	"\n\t--ttl               Report TTL of reply"
//usage:	"\n\t--write-response <name>   Write responses"
//usage:	"\n\t--type <type>       Query type"
//usage:	"\n\t--class <class>     Query class"
//usage:	"\n\t--query <name>      Query name"
//usage:	"\n\t--a <name>          IPv4 address query"
//usage:	"\n\t--aaaa <name>       IPv6 address query"
//usage:	"\n\t--any <name>        Any available records"
//usage:	"\n\t--afsdb <name>      AFS Data Base location query"
//usage:	"\n\t--apl <name>        Lists of Address Prefixes query"
//usage:	"\n\t--axfr <name>       Transfer of an entire zone"
//usage:	"\n\t--caa <name>        Certification Authority Restriction"
//usage:	"\n\t--cert <name>       Certificate"
//usage:	"\n\t--cname <name>      The Canonical Name for an alias"
//usage:	"\n\t--dlv <name>        DNSSEC Lookaside Validation"
//usage:	"\n\t--dname <name>      DNAME"
//usage:	"\n\t--dnskey <name>     DNSKEY"
//usage:	"\n\t--ds <name>         Delegation Signer"
//usage:	"\n\t--ipseckey <name>   IPSECKEY"
//usage:	"\n\t--loc <name>        Location Information"
//usage:	"\n\t--mx <name>         Mail Exchange"
//usage:	"\n\t--naptr <name>      Naming Authority Pointer"
//usage:	"\n\t--ns <name>         Authoritative Name Server"
//usage:	"\n\t--nsec <name>       NSEC"
//usage:	"\n\t--nsec3 <name>      NSEC3"
//usage:	"\n\t--nsec3param <name> NSEC3PARAM"
//usage:	"\n\t--ptr <name>        Domain Name Pointer"
//usage:	"\n\t--rrsig <name>      RRSIG"
//usage:	"\n\t--rp <name>         Responsible Person"
//usage:	"\n\t-s|--soa <name>     Start Of A Zone Of Authority"
//usage:	"\n\t--sig <name>        Security Signature"
//usage:	"\n\t--spf <name>        Sender Policy Framework"
//usage:	"\n\t--sshfp <name>      SSH Key Fingerprint"
//usage:	"\n\t--srv <name>        Server Selection"
//usage:	"\n\t--ta <name>         DNSSEC Trust Authorities"
//usage:	"\n\t--tlsa <name>       TLSA"
//usage:	"\n\t--txt <name>        Text Strings"
//usage:	"\n\t-h|--hostname.bind  CHAOS TXT hostname.bind query"
//usage:	"\n\t-i|--id.server      CHAOS TXT id.server query"
//usage:	"\n\t-b|--version.bind   CHAOS TXT version.bind query"
//usage:	"\n\t-r|--version.server CHAOS TXT version.server query"

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
#include "http2.h"

#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/dns.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>
#define DQ(str) "\"" #str "\""
#define DQC(str) "\"" #str "\" : "
#define ADDRESULT buf_add(&qry->result, line, strlen(line))
#define AS(val)  buf_add(&qry->result, val, strlen (val))
#define JS(key, val) snprintf(line, DEFAULT_LINE_LENGTH, "\"" #key"\" : \"%s\" , ",  val), ADDRESULT  
#define JS_NC(key, val) snprintf(line, DEFAULT_LINE_LENGTH,"\"" #key"\" : \"%s\" ",  val), ADDRESULT 
#define JSDOT(key, val) snprintf(line, DEFAULT_LINE_LENGTH, "\"" #key"\" : \"%s.\" , ",  val), ADDRESULT
#define JS1(key, fmt, val) snprintf(line, DEFAULT_LINE_LENGTH, "\"" #key"\" : "#fmt" , ",  val), ADDRESULT
#define JD(key, val) snprintf(line, DEFAULT_LINE_LENGTH, "\"" #key"\" : %d , ",  val), ADDRESULT
#define JD_NC(key, val) snprintf(line, DEFAULT_LINE_LENGTH, "\"" #key"\" : %d ",  val), ADDRESULT
#define JU(key, val) snprintf(line, DEFAULT_LINE_LENGTH, "\"" #key"\" : %u , ",  val), ADDRESULT
#define JU_NC(key, val) snprintf(line, DEFAULT_LINE_LENGTH, "\"" #key"\" : %u",  val), ADDRESULT
#define JC snprintf(line, DEFAULT_LINE_LENGTH, ","), ADDRESULT

#define SAFE_PREFIX_REL ATLAS_DATA_NEW_REL

#define BLURT crondlog (LVL5 "%s:%d %s()", __FILE__, __LINE__,  __func__),crondlog
#define IAMHERE crondlog (LVL5 "%s:%d %s()", __FILE__, __LINE__,  __func__)

#undef MIN	/* just in case */
#undef MAX	/* also, just in case */
#define O_RESOLV_CONF  1003
#define O_PREPEND_PROBE_ID  1004
#define O_EVDNS 1005
#define O_RETRY 1006
#define O_TYPE 1007
#define O_CLASS 1008
#define O_QUERY 1009
#define O_OUTPUT_COBINED 1101
#define O_CD 1010
#define O_AD 1011

#if ENABLE_FEATURE_EVTDIG_TLS
#define O_TLS 1012
#endif

#define O_TTL 1013

#define O_HTTPS 1014
#define O_SNI_CERT_NAME 1015
#define O_HTTPS_PATH 1016

#define DNS_FLAG_RD 0x0100

#define MIN(a, b) (a < b ? a : b)
#define MAX(a, b) (a > b ? a : b)

#define ENV2QRY(env) \
	((struct query_state *)((char *)env - offsetof(struct query_state, tu_env)))

#define MAX_DNS_BUF_SIZE   5120
#define MAX_DNS_OUT_BUF_SIZE   512

/* Intervals and timeouts (all are in milliseconds unless otherwise specified) */
#define DEFAULT_NOREPLY_TIMEOUT 5000           /* 5000 msec - 0 is illegal      */
#define DEFAULT_LINE_LENGTH 256 
#define DEFAULT_STATS_REPORT_INTERVEL 180 		/* in seconds */
#define CONN_TO            5  /* TCP connection time out in seconds */
#define DEFAULT_RETRY_MAX 0 

/* state of the dns query */
#define STATUS_DNS_RESOLV 		1001
#define STATUS_TCP_CONNECTING 		1002
#define STATUS_TCP_CONNECTED 		1003
#define STATUS_TCP_WRITE 		1004
#define STATUS_NEXT_QUERY		1005
#define STATUS_RETRANSMIT_QUERY         1006
#define STATUS_PRINT_FREE         	1006
#define STATUS_SEND			1007
#define STATUS_WAIT_RESPONSE		1008
#define STATUS_FREE 			0

// seems the following are defined in header files we use

#ifndef ns_t_apl
#define ns_t_apl   42
#endif

#ifndef T_APL
#define T_APL ns_t_apl
#endif 

#ifndef ns_t_caa
#define ns_t_caa   257
#endif

#ifndef T_CAA
#define T_CAA ns_t_caa
#endif 

#ifndef ns_t_cert
#define ns_t_cert   37
#endif

#ifndef T_CERT
#define T_CERT ns_t_cert
#endif 

#ifndef ns_t_dname
#define ns_t_dname 39
#endif

#ifndef T_DNAME
#define T_DNAME ns_t_dname
#endif 

#ifndef ns_t_dlv
#define ns_t_dlv   32769
#endif

#ifndef T_DLV
#define T_DLV ns_t_dlv
#endif 

#ifndef ns_t_ds
#define ns_t_ds   43
#endif

#ifndef T_DS
#define T_DS ns_t_ds
#endif 

#ifndef ns_t_dnskey
#define ns_t_dnskey   48
#endif

#ifndef T_DNSKEY
#define T_DNSKEY ns_t_dnskey
#endif

#ifndef ns_t_ipseckey
#define ns_t_ipseckey   45
#endif

#ifndef T_IPSECKEY
#define T_IPSECKEY ns_t_ipseckey
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

#ifndef ns_t_nsec3
#define ns_t_nsec3   50
#endif

#ifndef T_NSEC3
#define T_NSEC3 ns_t_nsec3
#endif  

#ifndef ns_t_nsec3param
#define ns_t_nsec3param   51
#endif

#ifndef T_NSEC3PARAM
#define T_NSEC3PARAM ns_t_nsec3param
#endif  

#ifndef ns_t_spf
#define ns_t_spf   99
#endif

#ifndef T_SPF
#define T_SPF ns_t_spf
#endif

#ifndef ns_t_ta
#define ns_t_ta  32768
#endif

#ifndef T_TA
#define T_TA ns_t_ta
#endif

#ifndef ns_t_tlsa
#define ns_t_tlsa  52
#endif

#ifndef T_TLSA
#define T_TLSA ns_t_tlsa
#endif


#ifndef ns_t_sshfp
#define ns_t_sshfp   44
#endif

#ifndef T_SSHFP
#define T_SSHFP ns_t_sshfp
#endif

#define EDNS_OPT_CLIENT_SUBNET		 8

#define EDNS_OPT_COOKIE			10
#define DNS_CLIENT_COOKIE_LEN		 8
#define DNS_SERVER_COOKIE_MIN_LEN	 8
#define DNS_SERVER_COOKIE_MAX_LEN	32

#define RESP_PACKET		 1
#define RESP_PEERNAME		 2
#define RESP_SOCKNAME		 3
#define RESP_N_RESOLV		 4
#define RESP_RESOLVER		 5
#define RESP_LENGTH		 6
#define RESP_DATA		 7
#define RESP_CMSG		 8
#define RESP_TIMEOUT		 9
#define RESP_ADDRINFO		10
#define RESP_ADDRINFO_SA	11


/* Definition for various types of counters */
typedef uint32_t counter_t;

struct dns_cookie_state
{
	uint8_t client_secret[32];	/* 256 bits, we are using sha256 */
	uint8_t client_cookie[DNS_CLIENT_COOKIE_LEN];
	struct dns_server_cookie
	{
		uint8_t len;
		uint8_t cookie[DNS_SERVER_COOKIE_MAX_LEN];
	} server_cookies[MAXNS];
};

/* How to keep track of a DNS query session */
struct tdig_base {
	struct event_base *event_base;

	/* A circular list of user queries */
	struct query_state *qry_head;

	struct event statsReportEvent;

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
	void (*done)(void *state, int error);
};

static struct tdig_base *tdig_base;

/* How to keep track of each user query to send dns query */
struct query_state {

	struct tdig_base *base;
	char * name;                /* Host identifier as given by the user */
	char * infname;		    /* Bind to this interface (or address) */
	u_int16_t qryid;            /* query id 16 bit */
	struct event event;         /* Used to detect read events on udp socket   */
	int udp_fd;		    /* udp_fd */
	int wire_size;
	struct dns_cookie_state *cookie_state;

	struct bufferevent *bev_tcp;
	struct tu_env tu_env;

	int opt_v4_only ;
	int opt_v6_only ;
	int opt_AF;
	int opt_proto;
	int opt_edns0;
	int opt_edns_version;
	int opt_edns_flags;
	int opt_edns_option;
	int opt_ipv6_dest_option;
	int opt_dnssec;
	int opt_nsid;
	int opt_client_subnet;
	int opt_cookies;
	int opt_qbuf;
	int opt_abuf;
	int opt_resolv_conf;
	int opt_rd;
	int opt_ad;
	int opt_cd;
	int opt_prepend_probe_id;
	int opt_evdns;
	int opt_rset;
	int opt_retry_max;
	int opt_query_arg;
	unsigned opt_timeout;
	int retry;
	int resolv_i;
	bool opt_do_tls;
	bool opt_do_ttl;
	bool opt_do_https;
	char *sni_cert_name;
	char *https_path;
	bool client_cookie_mismatch;

	char * str_Atlas; 
	char * str_bundle; 
	u_int16_t qtype;
	u_int16_t qclass;

	char *macro_lookupname;
	char *lookupname;
	char *server_name;
	char *out_filename;
	char *port_as_char;

	/* Contents of resolv.conf during a measurement */
	int resolv_max;
	char *nslist[MAXNS];

	/* For fuzzing */
	char *response_out;
	char *response_in;

	uint32_t pktsize;              /* Packet size in bytes */
	struct addrinfo *res, *ressave, *ressent;

	struct event noreply_timer;    /* Timer to handle timeout */
	struct event nsm_timer;       /* Timer to send UDP */
	struct event next_qry_timer;  /* Timer event to start next query */
	struct event done_qry_timer;  /* Timer event to call done */

	time_t xmit_time;	
	struct timespec xmit_time_ts;	
	struct timespec qxmit_time_ts;	
	double triptime;
	double querytime;
	int rcvdttl;

	//tdig_callback_type user_callback;
	void *user_callback;
	void *user_pointer;            /* the pointer given to us for this qry   */

	/* these objects are kept in a circular list */
	struct query_state *next, *prev;

	struct buf err; 
	struct buf qbuf; 
	struct buf packet;
	struct buf result;
	int qst ; 
	char dst_addr_str[(INET6_ADDRSTRLEN+1)]; 
	char loc_addr_str[(INET6_ADDRSTRLEN+1)]; 
	unsigned short dst_ai_family ;
	unsigned short loc_ai_family ;
	struct sockaddr_in6 loc_sin6;
        socklen_t loc_socklen;

	/* For DNS over HTTP2 */
	struct http2_env *http2_env;

	u_char *outbuff;

	FILE *resp_file;	/* Fuzzing */
};
//DNS header structure
struct DNS_HEADER
{
	u_int16_t id;        // identification number

#if BYTE_ORDER == BIG_ENDIAN
	u_int16_t qr :1,     /* query/response flag               */
		  opcode :4, /* purpose of message                */
		  aa :1,     /* authoritive answer                */
		  tc :1,     /* truncated message                 */
		  rd :1,     /* recursion desired                 */

		  ra :1,     /* recursion available               */
		  z :1,      /* its z! reserved                   */
		  ad :1,     /* authenticated data                */
		  cd :1,     /* checking disabled                 */
		  rcode :4;  /* response code                     */
#elif BYTE_ORDER == LITTLE_ENDIAN || BYTE_ORDER == PDP_ENDIAN
	u_int16_t rd :1,     
		  tc :1,     
		  aa :1,     
		  opcode :4, 
		  qr :1,     

		  rcode :4,  
		  cd :1,     
		  ad :1,     
		  z :1,      
		  ra :1;     
#endif

	u_int16_t q_count;   /* number of question entries       */
	u_int16_t ans_count; /* number of answer entries         */
	u_int16_t ns_count;  /* number of authority entries      */
	u_int16_t add_count; /* number of resource entries       */
};

// EDNS OPT pseudo-RR : EDNS0
struct EDNS0_HEADER
{
	/** EDNS0 available buffer size, see RFC2671 */
	u_int16_t otype;
	uint16_t _edns_udp_size;
	u_int8_t _edns_ercode; // rcode extension 
	u_int8_t _edns_version; // EDNS version
	u_int16_t Z ;     // first bit is the D0 bit.
	uint16_t _edns_rdlen; // length of rdata
}; 

// EDNS OPT pseudo-RR : eg NSID RFC 5001 
struct EDNS_NSID 
{
	u_int16_t otype;
	u_int16_t olength; 	// length of option data
};

// Client Subnet option (RFC 7871)
struct EDNS_CLIENT_SUBNET
{
	u_int16_t otype;
	u_int16_t olength;
	u_int16_t cs_family;
	u_int8_t cs_src_prefix_len;
	u_int8_t cs_scope_prefix_len;
	// u_int8_t[] cs_address;
};

// DNS Cookies option (RFC 7873)
struct EDNS_COOKIES
{
	u_int16_t otype;
	u_int16_t olength;
	u_int8_t client_cookie[DNS_CLIENT_COOKIE_LEN];

	/* The server cookie could be smaller or even empty */
	u_int8_t server_cookie[DNS_SERVER_COOKIE_MAX_LEN];
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
	{ "aaaa", required_argument, NULL, (100000 + T_AAAA) },
	{ "any", required_argument, NULL, (100000 + T_ANY) },
	{ "afsdb", required_argument, NULL, (100000 + T_AFSDB) },
	{ "apl", required_argument, NULL, (100000 + T_APL) },
	{ "axfr", required_argument, NULL, (100000 + T_AXFR ) },  //yet to be tested.
	{ "caa", required_argument, NULL, (100000 + T_CAA) },
	{ "cert", required_argument, NULL, (100000 + T_CERT) },
	{ "cname", required_argument, NULL, (100000 + T_CNAME) },
	{ "dlv", required_argument, NULL, (100000 + T_DLV) },
	{ "dname", required_argument, NULL, (100000 + T_DNAME) },
	{ "dnskey", required_argument, NULL, (100000 + T_DNSKEY) },
	{ "ds", required_argument, NULL, (100000 + T_DS) },
	{ "ipseckey", required_argument, NULL, (100000 + T_IPSECKEY) },
	{ "key", required_argument, NULL, (100000 + T_KEY) },
	{ "loc", required_argument, NULL, (100000 + T_LOC) },
	{ "mx", required_argument, NULL, (100000 + T_MX ) },
	{ "naptr", required_argument, NULL, (100000 + T_NAPTR) },
	{ "ns", required_argument, NULL, (100000 + T_NS) },
	{ "nsec", required_argument, NULL, (100000 + T_NSEC) },
	{ "nsec3", required_argument, NULL, (100000 + T_NSEC3) },
	{ "nsec3param", required_argument, NULL, (100000 + T_NSEC3PARAM) },
	{ "ptr", required_argument, NULL, (100000 + T_PTR) },
	{ "rrsig", required_argument, NULL, (100000 + T_RRSIG) },
	{ "rp", required_argument, NULL, (100000 + T_RP) },
	{ "soa", required_argument, NULL, 's' },
	{ "sig", required_argument, NULL, (100000 + T_SIG) },
	{ "spf", required_argument, NULL, (100000 + T_SPF) },
	{ "sshfp", required_argument, NULL, (100000 + T_SSHFP) },
	{ "srv", required_argument, NULL, (100000 + T_SRV) },
	{ "ta", required_argument, NULL, (100000 + T_TA) },
	{ "tlsa", required_argument, NULL, (100000 + T_TLSA) },
	{ "tsig", required_argument, NULL, (100000 + T_TSIG) },
	{ "txt", required_argument, NULL, (100000 + T_TXT) },

	{ "type", required_argument, NULL, O_TYPE },
	{ "class", required_argument, NULL, O_CLASS },
	{ "query", required_argument, NULL, O_QUERY},

	// clas CHAOS
	{ "hostname.bind", no_argument, NULL, 'h' },
	{ "id.server", no_argument, NULL, 'i' },
	{ "version.bind", no_argument, NULL, 'b' },
	{ "version.server", no_argument, NULL, 'r' },

	// flags
	{ "c_output", no_argument, NULL, O_OUTPUT_COBINED},
	{ "ad", no_argument, NULL, O_AD},
	{ "cd", no_argument, NULL, O_CD},
	{ "client-subnet", no_argument, NULL, 'c' },
	{ "cookies", no_argument, NULL, 'C' },
	{ "do", no_argument, NULL, 'd' },
	{ "evdns", no_argument, NULL, O_EVDNS },
	{ "noabuf", no_argument, NULL, 1002 },
	{ "nsid", no_argument, NULL, 'n' },
	{ "p_probe_id", no_argument, NULL, O_PREPEND_PROBE_ID },
	{ "qbuf", no_argument, NULL, 1001 },
	{ "resolv", no_argument, NULL, O_RESOLV_CONF },
#if ENABLE_FEATURE_EVTDIG_TLS
	{ "tls", no_argument, NULL, O_TLS},
#endif
	{ "https", no_argument, NULL, O_HTTPS},
	{ "sni-cert-name", required_argument, NULL, O_SNI_CERT_NAME },
	{ "https-path", required_argument, NULL, O_HTTPS_PATH },
	{ "ttl", no_argument, NULL, O_TTL },

	{ "edns0", required_argument, NULL, 'e' },
	{ "edns-flags", required_argument, NULL, '2' },
	{ "edns-option", required_argument, NULL, '3' },
	{ "edns-version", required_argument, NULL, '1' },
	{ "ipv6-dest-option", required_argument, NULL, '5' },
	{ "out-file", required_argument, NULL, 'O' },
	{ "port", required_argument, NULL, 'p'},
	{ "retry",  required_argument, NULL, O_RETRY },
	{ "timeout", required_argument, NULL, 'T' },

	{ "write-response", required_argument, NULL, 200000 + 'W'},
	{ "read-response", required_argument, NULL, 200000 + 'R'},

	{ NULL, }
};
static char line[(DEFAULT_LINE_LENGTH+1)];

static void tdig_stats(int unused UNUSED_PARAM, const short event UNUSED_PARAM, void *h);
static int tdig_delete(void *state);
static int ChangetoDnsNameFormat(u_char *dns, size_t maxlen, char* qry);
struct tdig_base *tdig_base_new(struct event_base *event_base); 
void tdig_start (void *qry);
void printReply(struct query_state *qry, int wire_size, unsigned char *result);
void printErrorQuick (struct query_state *qry);
static void local_exit(void *state, int error);
static void *tdig_init(int argc, char *argv[],
	void (*done)(void *state, int error));
static void process_reply(void * arg, int nrecv, struct timespec now,
	struct msghdr *msgp);
static void update_server_cookie(struct query_state *qry, uint8_t *packet,
	int packlen);
static int get_edns_opt(int *optoffp, int target_code,
	uint8_t *packet, int packlen);
static int get_rr_len(int *namelenp, uint8_t *packet, int offset, int len,
	int question);
static int mk_dns_buff(struct query_state *qry,  u_char *packet,
	size_t packetlen) ;
int ip_addr_cmp (u_int16_t af_a, void *a, u_int16_t af_b, void *b);
static void udp_dns_cb(int err, struct evutil_addrinfo *ev_res, void *arg);
static void noreply_callback(int unused  UNUSED_PARAM, const short event UNUSED_PARAM, void *h);
static void free_qry_inst(struct query_state *qry);
static void ready_callback (int unused, const short event, void * arg);

u_int32_t get32b (unsigned char *p);
void ldns_write_uint16(void *dst, uint16_t data);
uint16_t ldns_read_uint16(const void *src);
unsigned char* ReadName(unsigned char *base, size_t size, size_t offset,
        int* count);
int dns_namelen(unsigned char *base, size_t offset, size_t size);

void print_txt_json(unsigned char *rdata, int txt_len,struct query_state *qry);

static void http2_reply_cb(void *ref, unsigned status,
	u_char *data, size_t len);
static void https_write_response(void *ref, void *buf, size_t len);
static size_t https_read_response(void *ref, void *buf, size_t len);

int evtdig_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int evtdig_main(int argc, char **argv) 
{ 
	struct query_state *qry;

	EventBase=event_base_new();
	if (!EventBase)
	{
		crondlog(LVL9 "ERROR: critical event_base_new failed"); /* exits */
	}

	qry = tdig_init(argc, argv, local_exit);
	if(!qry) {
		crondlog(DIE9 "ERROR: critical tdig_init failed"); /* exits */
		event_base_free	(EventBase);
		return 1;
	}

	DnsBase = evdns_base_new(EventBase, 1);
	if (!DnsBase) {
		crondlog(DIE9 "ERROR: critical evdns_base_new failed"); /* exits */
		event_base_free	(EventBase);
		return 1;
	}

	tdig_start(qry);  
	// printf ("starting query\n");

	event_base_dispatch (EventBase);
	event_base_loopbreak (EventBase);
	if(EventBase)
	event_base_free(EventBase);
	return 0;
}

void print_txt_json(unsigned char *rdata, int txt_len,struct query_state *qry)
{
        int i, len;

        AS("\"RDATA\" : [ \"");
	len= -1;
        for(i = 0; i < txt_len; i++) {
		if (len == 0)
		{
			AS("\", \"");
			len= -1;
		}
		if (len == -1)
		{
			len= *rdata;
			rdata++;
			continue;
		}
                if( (*rdata == 34  ) || (*rdata == 92  ))  {
                        snprintf(line, DEFAULT_LINE_LENGTH, "\\\\%03d", *(char *)rdata  );
			buf_add(&qry->result, line, strlen (line));
                }
                // Space - ~
                else if ((*rdata >= ' '  ) && (*rdata <= '~')) {
                        snprintf(line, DEFAULT_LINE_LENGTH, "%c", *(char *)rdata );
			buf_add(&qry->result, line, strlen (line));
                }
                else {
                        snprintf(line, DEFAULT_LINE_LENGTH, "\\\\%03d", *rdata   );
			buf_add(&qry->result, line, strlen (line));
                }
		len--;
                rdata++;
        }
        AS("\" ] ");
}

static void local_exit(void *state UNUSED_PARAM, int error)
{
	/*
	   qry->base->done(qry);
	   void (*terminator)(void *state);
	   struct event_base *event_base;
	   struct tdig_base *tbase;
	   terminator = qry->base->done;
	   event_base = qry->base->event_base;
	   if (DnsBase) {
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
	exit(error);
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

static int mk_dns_buff(struct query_state *qry,  u_char *packet,
	size_t packetlen) 
{
	struct DNS_HEADER *dns = NULL;
	u_char *qname, *p;
	struct QUESTION *qinfo = NULL;
	struct EDNS0_HEADER *e;
	struct EDNS_NSID *n;
	struct EDNS_CLIENT_SUBNET *cs;
	struct EDNS_COOKIES *cookies;
	uint16_t rdlen;
	int r, cookie_opt_len, ind, qnamelen, server_len;
	char *lookup_prepend;
	int probe_id;
	sha256_ctx_t sha256_ctx;
	uint8_t sha256_buf[32];

	dns = (struct DNS_HEADER *)packet;
	if (qry->response_in || qry->response_out)
	{
		qry->qryid= 12345;
	}
	else
	{
		r =  random();
		r %= 65535;

		// host is storing int host byte order
		qry->qryid = (uint16_t) r;
	}
	// crondlog(LVL5 "%s %s() : %d base address %p",__FILE__, __func__, __LINE__, qry->base);
	// BLURT(LVL5 "dns qyery id %d", qry->qryid);
	dns->id = (uint16_t) htons(qry->qryid); 
 
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

	dns->q_count = htons(1); /* we have only 1 question */
	dns->ans_count = 0;
	dns->ns_count = 0;
	dns->add_count = htons(0);

	if (qry->opt_resolv_conf ||  qry->opt_rd ) {
		dns->rd = 1;
	}

	if (qry->opt_ad)
		dns->ad = 1;
	if (qry->opt_cd)
		dns->cd = 1;

	//point to the query portion
	qname =(u_char *)&packet[sizeof(struct DNS_HEADER)];

	/* DNS limits the name lengths to 255 in DNS encoding. Verify that the
	 * buffer is big enough. Also include space for EDNS0 and NSID */
	qnamelen= 255;

	if (packetlen <
		sizeof(struct DNS_HEADER) +
		qnamelen + sizeof(struct QUESTION) +
		1 /* dummy dns name */ + sizeof(struct EDNS0_HEADER) +
		sizeof(struct EDNS_NSID) +
		sizeof(struct EDNS_CLIENT_SUBNET))
	{
		crondlog(DIE9 "mk_dns_buff: packet size too small, got %d",
			packetlen);
	}

	// should it be limited to clas C_IN ? 
	if(qry->opt_prepend_probe_id ) {
		probe_id = get_probe_id();
		probe_id =  MAX(probe_id, 0);


		lookup_prepend = xzalloc(DEFAULT_LINE_LENGTH +  sizeof(qry->lookupname));
		snprintf(lookup_prepend, (sizeof(qry->lookupname) +
			DEFAULT_LINE_LENGTH - 1),
			 "%d.%llu.%s", probe_id, (unsigned long long)qry->xmit_time,
			qry->lookupname);

		qnamelen= ChangetoDnsNameFormat(qname, qnamelen,
			lookup_prepend); // fill the query portion.

		free(lookup_prepend);
	}
	else {
		qnamelen= ChangetoDnsNameFormat(qname, qnamelen,
			qry->lookupname); // fill the query portion.
	}
	if (qnamelen == -1)
		return -1;

	qinfo =(struct QUESTION*)&packet[sizeof(struct DNS_HEADER) + qnamelen]; 

	qinfo->qtype = htons(qry->qtype);
	qinfo->qclass = htons(qry->qclass);

	qry->pktsize  = (sizeof(struct DNS_HEADER) + qnamelen +
		sizeof(struct QUESTION)) ;
	if(qry->opt_nsid || qry->opt_client_subnet || qry->opt_cookies ||
		qry->opt_dnssec || (qry->opt_edns0 > 512) ||
		qry->opt_edns_version != 0 ||
		qry->opt_edns_flags != 0 ||
		qry->opt_edns_option != 0) { 
		p= &packet[qry->pktsize];
		*p= 0;	/* encoding of '.' */
		qry->pktsize++;

		e=(struct EDNS0_HEADER*)&packet[ qry->pktsize ];
		e->otype = htons(ns_t_opt);
		e->_edns_udp_size = htons(qry->opt_edns0);
		e->_edns_version = qry->opt_edns_version;
		e->Z = htons(qry->opt_edns_flags);
		if(qry->opt_dnssec) {
			e->Z |= htons(0x8000);
		}
		e->_edns_rdlen =  htons(0);
#if 0
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
#endif

		qry->pktsize  += sizeof(struct EDNS0_HEADER) ;
		dns->add_count = htons(1);

		if(qry->opt_nsid ) {
			n=(struct EDNS_NSID*)&packet[ qry->pktsize ];
			rdlen= ntohs(e->_edns_rdlen);
			e->_edns_rdlen =
				htons(rdlen + sizeof(struct EDNS_NSID));
			n->otype = htons(3); 
			n->olength =  htons(0);
			qry->pktsize  += sizeof(struct EDNS_NSID);
		}
		if (qry->opt_client_subnet)
		{
			cs=(struct EDNS_CLIENT_SUBNET*)&packet[ qry->pktsize ];
			rdlen= ntohs(e->_edns_rdlen);
			e->_edns_rdlen =
				htons(rdlen + sizeof(struct EDNS_CLIENT_SUBNET));
			cs->otype = htons(EDNS_OPT_CLIENT_SUBNET); 
			cs->olength = htons(sizeof(struct EDNS_CLIENT_SUBNET) -
				offsetof(struct EDNS_CLIENT_SUBNET, cs_family));
			cs->cs_family= htons(qry->opt_AF == AF_INET ? 1 : 2);
			cs->cs_src_prefix_len= htons(0);
			cs->cs_scope_prefix_len= htons(0);
			qry->pktsize  += sizeof(struct EDNS_CLIENT_SUBNET);
		}
		if (qry->opt_cookies)
		{
			/* Create client cookie. We should use hmac, but it
			 * doesn't seem to be available. However, just using
			 * sha256 should be good enough.
			 */
			sha256_begin(&sha256_ctx);
			if (qry->opt_AF == AF_INET)
			{
				sha256_hash(&sha256_ctx,
					&((struct sockaddr_in *)&qry->
					loc_sin6)->sin_addr,
					sizeof((struct sockaddr_in *)&qry->
                                        loc_sin6)->sin_addr);
				sha256_hash(&sha256_ctx,
					&((struct sockaddr_in *)&qry->
					res->ai_addr)->sin_addr,
					sizeof((struct sockaddr_in *)&qry->
                                        res->ai_addr)->sin_addr);
			}
			else
			{
				sha256_hash(&sha256_ctx,
					&qry->loc_sin6.sin6_addr,
					sizeof(qry->loc_sin6.sin6_addr));
				sha256_hash(&sha256_ctx,
					&((struct sockaddr_in6 *)&qry->res->
					ai_addr)->sin6_addr,
					sizeof(((struct sockaddr_in6 *)&qry->
					res->ai_addr)->sin6_addr));
			}
			sha256_hash(&sha256_ctx,
				&qry->cookie_state->client_secret,
				sizeof(qry->cookie_state->client_secret));
			sha256_end(&sha256_ctx, sha256_buf);
			
			cookies=(struct EDNS_COOKIES *)&packet[ qry->pktsize ];

			/* Fill-in client cookie */
			memcpy(cookies->client_cookie,
				sha256_buf+sizeof(sha256_buf) -
				DNS_CLIENT_COOKIE_LEN, DNS_CLIENT_COOKIE_LEN);

			/* Save cookie to check reply */
			memcpy(qry->cookie_state->client_cookie,
				cookies->client_cookie,
				DNS_CLIENT_COOKIE_LEN);

			/* Select server cookie */
			if (qry->opt_resolv_conf)
				ind= qry->resolv_i;
			else
				ind= 0;
			server_len= qry->cookie_state->server_cookies[ind].len;
			assert(server_len >= 0 &&
				server_len <= DNS_SERVER_COOKIE_MAX_LEN);
			memcpy(cookies->server_cookie,
				qry->cookie_state->server_cookies[ind].cookie,
				server_len);

			cookie_opt_len= offsetof(struct EDNS_COOKIES,
				server_cookie[server_len]);

			rdlen= ntohs(e->_edns_rdlen);
			e->_edns_rdlen =
				htons(rdlen + cookie_opt_len);
			cookies->otype = htons(EDNS_OPT_COOKIE); 
			cookies->olength = htons(cookie_opt_len -
				offsetof(struct EDNS_COOKIES, client_cookie));
			qry->pktsize  += cookie_opt_len;
		}
		if(qry->opt_edns_option ) {
			/* Insert an empty option with this option code.
			 * Use struct EDNS_NSID because it is exacly the
			 * empty header we need.
			 */
			n=(struct EDNS_NSID*)&packet[ qry->pktsize ];
			rdlen= ntohs(e->_edns_rdlen);
			e->_edns_rdlen =
				htons(rdlen + sizeof(struct EDNS_NSID));
			n->otype = htons(qry->opt_edns_option); 
			n->olength =  htons(0);
			qry->pktsize  += sizeof(struct EDNS_NSID);
		}

		/* Transmit the request over the network */
	}

#if 0
	if(qry->pktsize) {
		buf_init(&pbuf, -1);
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
#endif

	return 0;
} 

/* Attempt to transmit a UDP DNS Request to a server. TCP is else where */
static void tdig_send_query_callback(int unused UNUSED_PARAM, const short event UNUSED_PARAM, void *h)
{
	int r, fd, on;
	sa_family_t af;
	struct query_state *qry = h;
	struct tdig_base *base = qry->base;
	uint32_t nsent = 0;
	u_char *outbuff= NULL;
	int err = 0; 
	struct timeval tv_noreply;
	struct addrinfo tmp_res;
	struct sockaddr_storage tmp_sockaddr;

	/* Clean the no reply timer (if any was previously set) */
	evtimer_del(&qry->noreply_timer);

	qry->qst = STATUS_SEND;
	outbuff = xzalloc(MAX_DNS_OUT_BUF_SIZE);
	bzero(outbuff, MAX_DNS_OUT_BUF_SIZE);
	//AA delete qry->outbuff = outbuff;
	qry->xmit_time= atlas_time();

	do {
		if (!qry->response_in && qry->udp_fd != -1)
		{
			event_del(&qry->event);
			close(qry->udp_fd);
			qry->udp_fd= -1;
		}

		if (qry->response_in)
		{
			size_t tmp_len;

			if (qry->udp_fd != -1)
				fd= qry->udp_fd;
			else
				fd= open(qry->response_in, O_RDONLY);
			if (fd == -1)
			{
				crondlog(DIE9 "unable to open '%s': %s",
				qry->response_in, strerror(errno));
			}

			tmp_len= sizeof(tmp_res);
			read_response(fd, RESP_ADDRINFO,
				&tmp_len, &tmp_res);
			assert(tmp_len == sizeof(tmp_res));
			tmp_len= sizeof(tmp_sockaddr);
			read_response(fd, RESP_ADDRINFO_SA,
				&tmp_len, &tmp_sockaddr);
			assert(tmp_len == tmp_res->ai_addrlen);
			tmp_res.ai_addr= (struct sockaddr *)&tmp_sockaddr;
			qry->res= &tmp_res;
		}

		if (qry->response_out)
		{
			write_response(qry->resp_file, RESP_ADDRINFO,
				sizeof(*qry->res), qry->res);
			write_response(qry->resp_file, RESP_ADDRINFO_SA,
				qry->res->ai_addrlen, qry->res->ai_addr);
		}

		af = ((struct sockaddr *)(qry->res->ai_addr))->sa_family;

		if (!qry->response_in)
		{
			if ((fd = socket(af, SOCK_DGRAM, 0) ) < 0 )
			{
				snprintf(line, DEFAULT_LINE_LENGTH,
					"%s \"socket\" : \"socket failed %s\"",
					qry->err.size ? ", " : "",
					strerror(errno));
				buf_add(&qry->err, line, strlen(line));
				printReply (qry, 0, NULL);
				free (outbuff);
				outbuff = NULL;
				return;
			} 
		}

		if (af == AF_INET6 && qry->opt_ipv6_dest_option != 0)
		{
			do_ipv6_option(fd, 1 /* dest */,
				qry->opt_ipv6_dest_option);
		}

		if (qry->opt_do_ttl)
		{
			on = 1;
			if (af == AF_INET6) {
				setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
					&on, sizeof(on));
			}
			else {
				setsockopt(fd, IPPROTO_IP, IP_RECVTTL,
					&on, sizeof(on));
			}
		}

		qry->udp_fd= fd;

		evutil_make_socket_nonblocking(fd); 

		event_assign(&qry->event, tdig_base->event_base, fd, 
			EV_READ | EV_PERSIST, ready_callback, qry);
		if (!qry->response_in)
			event_add(&qry->event, NULL);

		if (qry->infname)
		{
			if (bind_interface(fd, af, qry->infname) == -1)
			{
				snprintf(line, DEFAULT_LINE_LENGTH,
					"%s \"socket\" : \"bind_interface failed\"",
					qry->err.size ? ", " : "");
				buf_add(&qry->err, line, strlen(line));
				printReply (qry, 0, NULL);
				free (outbuff);
				outbuff = NULL;
				return;
			}
		}

		if (!qry->opt_resolv_conf)
		{
			r= atlas_check_addr(qry->res->ai_addr,
				qry->res->ai_addrlen);
			if (r == -1)
			{
				free (outbuff);
				outbuff = NULL;
				snprintf(line, DEFAULT_LINE_LENGTH,
				"%s \"reason\" : \"address not allowed\"",
					qry->err.size ? ", " : "");
				buf_add(&qry->err, line, strlen(line));

				/* Trigger printing of dst_addr */
				qry->ressent = qry->res;	

				printReply (qry, 0, NULL);
				return;
			}
		}

		if (qry->opt_resolv_conf && strcmp(qry->macro_lookupname,
			qry->lookupname) != 0)
		{
			/* We want $r to generate a new random number for 
			 * each resolver. 
			 */
			if (qry->lookupname)
			{
				free(qry->lookupname);
				qry->lookupname= NULL;
			}
			qry->lookupname=
				atlas_name_macro(qry->macro_lookupname);
		}
		qry->loc_socklen = sizeof(qry->loc_sin6);
		if (qry->response_in)
			;	/* No need to connect */
		else if (connect(qry->udp_fd, qry->res->ai_addr, qry->res->ai_addrlen) == -1)
		{
				snprintf(line, DEFAULT_LINE_LENGTH,
					"%s \"socket\" : \"connect failed %s\"",
					qry->err.size ? ", " : "",
					strerror(errno));
				buf_add(&qry->err, line, strlen(line));
				printReply (qry, 0, NULL);
				free (outbuff);
				outbuff = NULL;
				return;
		}

		if (qry->response_in)
		{
			size_t tmp_len;

			tmp_len= sizeof(qry->loc_sin6);
			read_response(qry->udp_fd, RESP_SOCKNAME,
				&tmp_len, &qry->loc_sin6);
			qry->loc_socklen= tmp_len;
		}
		else
		{
			if (getsockname(qry->udp_fd,
				(struct sockaddr *)&qry->loc_sin6,
				&qry->loc_socklen)  == -1) {
				snprintf(line, DEFAULT_LINE_LENGTH,
					"%s \"getsockname\" : \"%s\"",
					qry->err.size ? ", " : "",
					strerror(errno));
				buf_add(&qry->err, line, strlen(line));
			}
			if (qry->response_out)
			{
				write_response(qry->resp_file,
					RESP_SOCKNAME,
					qry->loc_socklen,
					&qry->loc_sin6);
			}
		}

		/* Assume that we are limited to one AF. mk_dns_buff needs
		 * to know for the client subnet option. We also need to
		 * know the local address for the cookie option.
		 */
		qry->opt_AF =
			((struct sockaddr *)(qry->res->ai_addr))->sa_family;

		r= mk_dns_buff(qry, outbuff, MAX_DNS_OUT_BUF_SIZE);
		if (r == -1)
		{
			/* Can't construct a DNS query */
			free (outbuff);
			outbuff = NULL;
			snprintf(line, DEFAULT_LINE_LENGTH,
				"%s \"err\" : \"unable to format DNS query\"",
				qry->err.size ? ", " : "");
			buf_add(&qry->err, line, strlen(line));
			printReply (qry, 0, NULL);
			return;
		}

		gettime_mono(&qry->xmit_time_ts);

		if (qry->response_in)
			nsent= qry->pktsize;
		else
		{
			nsent = send(qry->udp_fd, outbuff,qry->pktsize,
				MSG_DONTWAIT);
		}
		qry->ressent = qry->res;

		if (nsent == qry->pktsize) {

			/* One more DNS Query is sent */
			base->sentok++;
			base->sentbytes += nsent;
			err  = 0;
			/* Add the timer to handle no reply condition in the given timeout */
			msecstotv(qry->opt_timeout, &tv_noreply);
			if (!qry->response_in)
			{
				evtimer_add(&qry->noreply_timer, &tv_noreply);
			}
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
	qry->qst = STATUS_WAIT_RESPONSE;
	if (qry->response_in)
		ready_callback(0, 0, qry);
}
static void done_qry_cb(int unused  UNUSED_PARAM, const short event UNUSED_PARAM, void *h) {
	struct query_state *qry = h;
	qry->qst = STATUS_FREE;
	// BLURT(LVL5 "query %s is done call done",  qry->server_name);
	qry->base->done(qry, 0);
}

static void next_qry_cb(int unused  UNUSED_PARAM, const short event UNUSED_PARAM, void *h) {
	struct query_state *qry = h;
	// BLURT(LVL5 "next query for %s",  qry->server_name);
	tdig_start(qry);  
}

/* The callback to handle timeouts due to destination host unreachable condition */
static void noreply_callback(int unused  UNUSED_PARAM, const short event UNUSED_PARAM, void *h)
{
	struct timeval asap = { 1, 1 };
	struct query_state *qry = h;

	qry->base->timeout++;
	snprintf(line, DEFAULT_LINE_LENGTH, "%s \"timeout\" : %d", qry->err.size ? ", " : "", qry->opt_timeout);
	buf_add(&qry->err, line, strlen(line));

	if (qry->response_in)
	{
		size_t tmp_len;

		tmp_len= 0;

		if (qry->resp_file)
		{
			read_response_file(qry->resp_file, RESP_TIMEOUT,
				&tmp_len, NULL);
		}
		else
		{
			read_response(qry->udp_fd, RESP_TIMEOUT,
				&tmp_len, NULL);
		}
	}
	if (qry->response_out)
		write_response(qry->resp_file, RESP_TIMEOUT, 0, NULL);

	//BLURT(LVL5 "AAA timeout for %s retry %d/%d ", qry->server_name, qry->retry,  qry->opt_retry_max);

	if (qry->retry < qry->opt_retry_max) {
		qry->retry++;
		qry->qst = STATUS_RETRANSMIT_QUERY;
		free_qry_inst(qry);
		evtimer_add(&qry->next_qry_timer, &asap);
	} else {
		printReply (qry, 0, NULL);
	}

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
	struct timeval asap = { 0, 0 };
	qry = ENV2QRY(env);

       // if (env != &state->tu_env) abort();  // Why do i need this? AA

        switch(cause)
        {
        case TU_DNS_ERR:
		snprintf(line, DEFAULT_LINE_LENGTH, "%s \"TUDNS\" : \"%s\"", qry->err.size ? ", " : "", str );
		buf_add(&qry->err, line, strlen(line));
                break;

        case TU_SOCKET_ERR:

		snprintf(line, DEFAULT_LINE_LENGTH, "%s \"TUSOCKET\" : \"%s\"", qry->err.size ? ", " : "", str );
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

        case TU_BAD_ADDR:
		snprintf(line, DEFAULT_LINE_LENGTH, "%s \"TU_BAD_ADDR\" : true", qry->err.size ? ", " : "");
		buf_add(&qry->err, line, strlen(line));

		qry->dst_ai_family = env->dns_curr->ai_addr->sa_family;
		getnameinfo(env->dns_curr->ai_addr, env->dns_curr->ai_addrlen, qry->dst_addr_str, INET6_ADDRSTRLEN , NULL, 0, NI_NUMERICHOST);

		qry->ressent = qry->res;	/* Trigger printing of dst_addr */
                break;

        default:
		snprintf(line, DEFAULT_LINE_LENGTH, "%s \"TU_UNKNOWN\" : \"%d %s\"", qry->err.size ? ", " : "", cause, str );
                crondlog(DIE9 "reporterr: bad cause %d", cause);
		break;
        }
	if (qry->retry < qry->opt_retry_max) {
		qry->retry++;
		qry->qst = STATUS_RETRANSMIT_QUERY;
		free_qry_inst(qry);
		evtimer_add(&qry->next_qry_timer, &asap);
	} else {
		printReply (qry, 0, NULL);
	}
}

static void tcp_dnscount(struct tu_env *env, int count UNUSED_PARAM)
{
	struct query_state * qry;
	qry = ENV2QRY(env); 
	qry->qst = STATUS_SEND;
	// BLURT(LVL5 "dns count for %s : %d", qry->server_name , count);
}

static void tcp_beforeconnect(struct tu_env *env,
        struct sockaddr *addr, socklen_t addrlen)
{
	struct query_state * qry;
	qry = ENV2QRY(env); 
	qry->xmit_time= atlas_time();
	qry->dst_ai_family = addr->sa_family;
	// BLURT(LVL5 "time : %d",  qry->xmit_time);
	getnameinfo(addr, addrlen, qry->dst_addr_str, INET6_ADDRSTRLEN , NULL, 0, NI_NUMERICHOST);

	if (qry->response_out)
	{
		write_response(qry->resp_file, RESP_PEERNAME, addrlen,
			addr);
	}

	gettime_mono(&qry->xmit_time_ts);
}

static void tcp_connected(struct tu_env *env, struct bufferevent *bev)
{
	uint16_t payload_len ;
	u_char *outbuff;	
	u_char *wire;
	struct query_state * qry; 
	qry = ENV2QRY(env); 

	qry->loc_socklen= sizeof(qry->loc_sin6);
	if (qry->response_in)
	{
		size_t tmp_len;

		tmp_len= sizeof(qry->loc_sin6);
		read_response_file(qry->resp_file, RESP_SOCKNAME,
			&tmp_len, &qry->loc_sin6);
		qry->loc_socklen= tmp_len;
	}
	else
	{
		getsockname(bufferevent_getfd(bev),
			(struct sockaddr *)&qry->loc_sin6, &qry->loc_socklen);
		if (qry->response_out)
		{
			write_response(qry->resp_file, RESP_SOCKNAME,
				qry->loc_socklen, &qry->loc_sin6);
		}
	}

	qry->bev_tcp =  bev;
	outbuff = xzalloc(MAX_DNS_OUT_BUF_SIZE);
	bzero(outbuff, MAX_DNS_OUT_BUF_SIZE);
	mk_dns_buff(qry, outbuff, MAX_DNS_OUT_BUF_SIZE);
	payload_len = (uint16_t) qry->pktsize;
	if (qry->opt_do_https)
	{
		qry->http2_env= http2_init();
		http2_dns(qry->http2_env, qry->bev_tcp, qry->sni_cert_name,
			qry->port_as_char,
			qry->https_path ? qry->https_path : "/dns-query",
			outbuff, payload_len);
		wire= NULL;
	}
	else
	{
		wire = xzalloc (payload_len + 4);
		ldns_write_uint16(wire, qry->pktsize);
		memcpy(wire + 2, outbuff, qry->pktsize);
		if (!qry->response_in)
		{
			evbuffer_add(bufferevent_get_output(qry->bev_tcp),
			wire, (qry->pktsize +2));
		}
		qry->base->sentok++;
		qry->base->sentbytes+= (qry->pktsize +2);
		// BLURT(LVL5 "send %u bytes", payload_len );
	}

	if(qry->opt_qbuf) {
		buf_init(&qry->qbuf, -1);
		buf_add_b64(&qry->qbuf, outbuff, qry->pktsize, 0);
	}
	free(outbuff);
	free(wire);

	gettime_mono(&qry->qxmit_time_ts);
}

static void tcp_readcb(struct bufferevent *bev UNUSED_PARAM, void *ptr) 
{
        struct query_state *qry = ptr;
        int n, r, type;
        u_char b2[2];
        struct timespec rectime;
        struct evbuffer *input ;
        struct DNS_HEADER *dnsR = NULL;


        qry = ENV2QRY(ptr);
	// BLURT(LVL5 "TCP readcb %s", qry->server_name );

	if (qry->opt_do_https)
	{
		r= http2_dns_input(qry->http2_env, bev, http2_reply_cb,
			ptr, qry->response_out ? https_write_response : 0,
			qry->response_in ? https_read_response : 0);
		if (r == -1)
		{
			snprintf(line, DEFAULT_LINE_LENGTH,
				"%s \"TCPREAD\" : "
				" \"http2_dns_input failed\""
				, qry->err.size ? ", " : "");
			buf_add(&qry->err, line, strlen(line));	
			printReply (qry, 0, NULL);
		}
		return;
	}

	gettime_mono(&rectime);

	if( qry->packet.size && (qry->packet.size >= qry->wire_size)) {
		snprintf(line, DEFAULT_LINE_LENGTH, "%s \"TCPREADSIZE\" : "
				" \"red more bytes than expected %d, got %zu\""
				, qry->err.size ? ", " : ""
				, qry->wire_size, qry->packet.size);
		buf_add(&qry->err, line, strlen(line));	
		printReply (qry, 0, NULL);
		return;
	}

        bzero(qry->base->packet, MAX_DNS_BUF_SIZE);

	if (!qry->response_in)
		input = bufferevent_get_input(bev);
	else
		input= NULL;	/* lint */
        if(qry->wire_size == 0) {
		if (qry->response_in)
		{
			size_t tmp_len;

			tmp_len= sizeof(b2);

			peek_response_file(qry->resp_file, &type);
			if (type == RESP_TIMEOUT)
			{
				noreply_callback(0, 0, qry);
				return;
			}
			read_response_file(qry->resp_file,
				RESP_LENGTH, &tmp_len, b2);
			if (tmp_len != sizeof(b2))
			{
				crondlog(
				DIE9 "tcp_readcb: error reading from '%s'",
					qry->response_in);
			}
			n= tmp_len;
		}
		else
			n = evbuffer_remove(input, b2, 2 );
		// printf("got %d bytes for response size\n", n);
		if(n == 2){
			if (qry->response_out)
			{
				write_response(qry->resp_file,
					RESP_LENGTH, sizeof(b2), b2);
			}
			qry->wire_size = ldns_read_uint16(b2);
			buf_init(&qry->packet, -1);
		}
		else {

			snprintf(line, DEFAULT_LINE_LENGTH, "%s \"TCPREAD\" : \"expected 2 bytes and got %d\"", qry->err.size ? ", " : "", n );
			buf_add(&qry->err, line, strlen(line));	
		}
	} 

	/* We need at least a header */
	if (qry->wire_size < sizeof(struct DNS_HEADER))
	{
		snprintf(line, DEFAULT_LINE_LENGTH, "%s \"TCPREADSIZE\" : "
				" \"reply too small, got %zu\""
				, qry->err.size ? ", " : ""
				, (size_t)qry->wire_size);
		buf_add(&qry->err, line, strlen(line));	
		printReply (qry, 0, NULL);
		return;
	}
	for (;;) {
		if (qry->response_in)
		{
			size_t tmp_len;

			tmp_len= sizeof(line);
			read_response_file(qry->resp_file,
				RESP_DATA, &tmp_len, line);
			n= tmp_len;
		}
		else
			n = evbuffer_remove(input,line , DEFAULT_LINE_LENGTH );
		// printf("got %d bytes for data size\n", n);
		if (n <= 0)
		{
			if (qry->response_in)
			{
				noreply_callback(0,0,qry);
			}
			break;
		}
		if (qry->response_out)
		{
			write_response(qry->resp_file,
				RESP_DATA, n, line);
		}
		buf_add(&qry->packet, line, n);
		// crondlog(LVL5 "in readcb %s %s got %d bytes, need %d", qry->str_Atlas, qry->server_name,  qry->packet.size, qry->wire_size);
		if(qry->wire_size == qry->packet.size) {
			// crondlog(LVL5 "in readcb %s %s red %d bytes ", qry->str_Atlas, qry->server_name,  qry->wire_size);
			// crondlog(LVL5 "qry pointer address readcb %p qry.id, %d", qry->qryid);
			// crondlog(LVL5 "DBG: base pointer address readcb %p",  qry->base );
			dnsR = (struct DNS_HEADER*) qry->packet.buf;
			if ( ntohs(dnsR->id)  == qry->qryid ) {
				qry->triptime = (rectime.tv_sec -
					qry->xmit_time_ts.tv_sec)*1000 +
					(rectime.tv_nsec -
					qry->xmit_time_ts.tv_nsec)/1e6;
				qry->querytime = (rectime.tv_sec -
					qry->qxmit_time_ts.tv_sec)*1000 +
					(rectime.tv_nsec -
					qry->qxmit_time_ts.tv_nsec)/1e6;
				printReply (qry, qry->packet.size, (unsigned char *)qry->packet.buf);
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

static void https_write_response(void *ref, void *buf, size_t len)
{
        struct query_state *qry;

        qry = ENV2QRY(ref);

	write_response(qry->resp_file, RESP_DATA, len, buf);
}

static size_t https_read_response(void *ref, void *buf, size_t len)
{
	size_t tmp_len;
        struct query_state *qry;

        qry = ENV2QRY(ref);

	tmp_len= len;
	read_response_file(qry->resp_file, RESP_DATA, &tmp_len, buf);
	return tmp_len;
}

static void http2_reply_cb(void *ref, unsigned status,
	u_char *data, size_t len)
{
        struct query_state *qry;
        struct DNS_HEADER *dnsR = NULL;
        struct timespec rectime;

        qry = ENV2QRY(ref);

	gettime_mono(&rectime);

	if (status != 200)
	{
		bzero(line, DEFAULT_LINE_LENGTH);
		snprintf(line, DEFAULT_LINE_LENGTH,
			" %s \"error\" : \"http2 request failed with %d\"",
			qry->err.size ? ", " : "", status);
		buf_add(&qry->err, line, strlen(line));
		printReply (qry, 0, NULL);
		return;
	}
	dnsR = (struct DNS_HEADER*) data;
	if ( ntohs(dnsR->id)  == qry->qryid ) {
		qry->triptime = (rectime.tv_sec -
			qry->xmit_time_ts.tv_sec)*1000 +
			(rectime.tv_nsec -
			qry->xmit_time_ts.tv_nsec)/1e6;
		qry->querytime = (rectime.tv_sec -
			qry->qxmit_time_ts.tv_sec)*1000 +
			(rectime.tv_nsec -
			qry->qxmit_time_ts.tv_nsec)/1e6;
		printReply (qry, len,
			(unsigned char *)data);
	}
	else {
		bzero(line, DEFAULT_LINE_LENGTH);
		snprintf(line, DEFAULT_LINE_LENGTH,
		" %s \"idmismatch\" : \"mismatch id from http2\"",
			qry->err.size ? ", " : "");
		buf_add(&qry->err, line, strlen(line));
		printReply (qry, 0, NULL);
	}
}

static void tcp_writecb(struct bufferevent *bev UNUSED_PARAM, void *ptr UNUSED_PARAM) 
{
	/*
	struct query_state * qry; 
	qry = ENV2QRY(ptr); 
	*/
	// BLURT(LVL5 "TCP writecb");
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

static void process_reply(void * arg, int nrecv, struct timespec now,
	struct msghdr *msgp)
{
	int rcvdttl;
	struct DNS_HEADER *dnsR = NULL;
	struct tdig_base * base;
	struct query_state * qry;
	struct cmsghdr *cmsgptr;

	qry= arg;
	base= qry->base;

	rcvdttl= -42;
	if (msgp)
	{
		for (cmsgptr= CMSG_FIRSTHDR(msgp); cmsgptr; 
			cmsgptr= CMSG_NXTHDR(msgp, cmsgptr))
		{
			if (cmsgptr->cmsg_len == 0)
				break;	/* Can this happen? */
			if (cmsgptr->cmsg_level == IPPROTO_IP &&
				cmsgptr->cmsg_type == IP_TTL)
			{
				rcvdttl= *(int *)CMSG_DATA(cmsgptr);
				continue;
			}
			if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
				cmsgptr->cmsg_type == IPV6_HOPLIMIT)
			{
				rcvdttl= *(int *)CMSG_DATA(cmsgptr);
				continue;
			}
			fprintf(stderr, "process_reply: level %d, type %d\n",
				cmsgptr->cmsg_level, cmsgptr->cmsg_type);
		}
	}

	if (nrecv < sizeof (struct DNS_HEADER)) {
		base->shortpkt++;
		return;
	}

	dnsR = (struct DNS_HEADER*) base->packet;
	base->recvok++; 


	// crondlog(LVL7 "DBG: base address process reply %p, nrec %d", base, nrecv);
	if (ntohs(dnsR->id) != qry->qryid)
	{
		base->martian++;
		crondlog(LVL7 "DBG: wrong id %d for qry, expected %d",
			ntohs(dnsR->id), qry->qryid);
		return;
	}

	qry->base->recvbytes += nrecv;
	qry->triptime = (now.tv_sec-qry->xmit_time_ts.tv_sec)*1000 +
		(now.tv_nsec-qry->xmit_time_ts.tv_nsec)/1e6;
	qry->rcvdttl= rcvdttl;

	/* Clean the noreply timer */
	evtimer_del(&qry->noreply_timer);

	if (qry->opt_cookies)
		update_server_cookie(qry, base->packet, nrecv);

	printReply (qry, nrecv, base->packet);
	return;
}

static void update_server_cookie(struct query_state *qry, uint8_t *packet,
	int packlen)
{
	int ind, optlen, optoff;

	/* Should wipe server cookie first. */
	fprintf(stderr, "update_server_cookie: should wipe server cookie\n");

	/* Select server cookie */
	if (qry->opt_resolv_conf)
		ind= qry->resolv_i;
	else
		ind= 0;
	qry->cookie_state->server_cookies[ind].len= 0;

	optlen= get_edns_opt(&optoff, EDNS_OPT_COOKIE, packet, packlen);
	if (optlen == -1)
	{
		return;
	}

	/* We expect a server cookie */
	if (optlen < DNS_CLIENT_COOKIE_LEN + DNS_SERVER_COOKIE_MIN_LEN ||
		optlen > DNS_CLIENT_COOKIE_LEN + DNS_SERVER_COOKIE_MAX_LEN)
	{
		/* Wrong size */
		printf("update_server_cookie: wrong size\n");
		return;
	}

	/* Check if client cookie matches */
	if (memcmp(qry->cookie_state->client_cookie, packet+optoff,
		DNS_CLIENT_COOKIE_LEN) != 0)
	{
		qry->client_cookie_mismatch= 1;
		/* Should report cookie mismatch */
		printf("update_server_cookie: client cookie mismatch\n");
		return;
	}

	/* Should update server cookie */

	qry->cookie_state->server_cookies[ind].len=
		optlen-DNS_CLIENT_COOKIE_LEN;;
	memcpy(qry->cookie_state->server_cookies[ind].cookie,
		packet+optoff+DNS_CLIENT_COOKIE_LEN,
		qry->cookie_state->server_cookies[ind].len);
}

static int get_edns_opt(int *optoffp, int target_code,
	uint8_t *packet, int packlen)
{
	int i, l, o, is_question, qcount, recs_to_skip;
	int namelen, opt_code, opt_len, opt_o, rdata_o, rdlen, rr_o, type;
	struct DNS_HEADER *dnsR = NULL;

	dnsR = (struct DNS_HEADER*) packet;

	qcount= ntohs(dnsR->q_count);
	recs_to_skip= qcount +
		ntohs(dnsR->ans_count ) +
		ntohs(dnsR->ns_count) +
		ntohs(dnsR->add_count);
	o= sizeof(struct DNS_HEADER);
	for (i= 0; i<recs_to_skip; i++)
	{
		is_question= (i<qcount);
		l= get_rr_len(&namelen, packet, o, packlen,
			is_question);
		if (l == -1)
		{
			printf("get_edns_opt: bad rr\n");
			return -1;
		}
		rr_o= o+namelen;
		rdata_o = rr_o + /*type*/ 2 + /*class*/ 2 + /*ttl*/ 4 +
			/* rdlength*/ 2;
		rdlen= o + l - rdata_o;
		o += l;
		if (!is_question)
		{
			/* Is this the ENDS0 op RR? */
			if (namelen != 1)
				continue;
			type= (packet[rr_o] << 8) | packet[rr_o+1];
			if (type != ns_t_opt)
				continue;
			break;
		}
	}
	if (i >= recs_to_skip)
	{
		printf("get_edns_opt: no OPT RR\n");
		return -1;	/* No OPT RR */
	}
	opt_o= 0;
	for (opt_o= 0; opt_o+4 <= rdlen;)
	{
		opt_code= (packet[rdata_o + opt_o] << 8) |
			packet[rdata_o + opt_o + 1];
		opt_len= (packet[rdata_o + opt_o +2] << 8) |
                        packet[rdata_o + opt_o + 3];
		if (opt_o + 4 + opt_len > rdlen)
		{
			printf("get_edns_opt: no option header\n");
			return -1;
		}
		printf("get_edns_opt: code %d\n", opt_code);
		if (opt_code == target_code)
		{
			*optoffp= rdata_o + opt_o + 4;
			return opt_len;
		}
		opt_o += 4 + opt_len;
	}

	/* Not found */
	return -1;
}

static int get_rr_len(int *namelenp, uint8_t *packet, int offset, int len,
	int question)
{
	int label_len, name_len, rdlength, rr_len;

	/* Handle name */
	name_len= 0;
	for(;;)
	{
		if (offset+name_len >= len)
			return -1;
		label_len= packet[offset+name_len];
		if (label_len > 63)
		{
			if (label_len < 192)
				return -1;	/* bogus */
			name_len += 2;
			break;
		}
		else if (label_len == 0)
		{
			name_len++;
			break;
		}
		name_len += label_len+1;
	}

	*namelenp= name_len;

	if (question)
		return name_len + /*qtype*/ 2 + /*qclass*/ 2;

	rr_len= name_len + /*type*/ 2 + /*class*/ 2 + /*ttl*/ 4;
	if (offset+rr_len+2 > len)
		return -1;
	rdlength= (packet[offset+rr_len] << 8) | packet[offset+rr_len+1];

	rr_len += 2 + rdlength;

	return rr_len;
}

static void ready_callback (int unused UNUSED_PARAM, const short event UNUSED_PARAM, void * arg)
{
	struct query_state * qry;
	int nrecv;
	struct timespec rectime;
	struct msghdr msg;
	struct iovec iov[1];
	struct sockaddr_in remote;
	char cmsgbuf[256];

	qry = arg;

	if (qry->response_in)
	{
		int type;

		peek_response(qry->udp_fd, &type);
		if (type == RESP_TIMEOUT)
		{
			noreply_callback(0, 0, qry);
			return;
		}
	}

	
	/* Time the packet has been received */
	gettime_mono(&rectime);

	bzero(qry->base->packet, MAX_DNS_BUF_SIZE);

	iov[0].iov_base= qry->base->packet;
	iov[0].iov_len= sizeof(qry->base->packet);
	msg.msg_name= &remote;
	msg.msg_namelen= sizeof(remote);
	msg.msg_iov= iov;
	msg.msg_iovlen= 1;
	msg.msg_control= cmsgbuf;
	msg.msg_controllen= sizeof(cmsgbuf);
	msg.msg_flags= 0;			/* Not really needed */

	/* Receive data from the network */
	if (qry->response_in)
	{
		size_t tmp_len;

		tmp_len= sizeof(qry->base->packet);
		read_response(qry->udp_fd, RESP_PACKET, &tmp_len,
			qry->base->packet);
		nrecv= tmp_len;

		tmp_len= sizeof(remote);
		read_response(qry->udp_fd, RESP_PEERNAME, &tmp_len,
			&remote);
		if (tmp_len != sizeof(remote))
		{
			crondlog(
			DIE9 "ready_callback: error reading from '%s'",
				qry->response_in);
		}

		tmp_len= sizeof(cmsgbuf);
		read_response(qry->udp_fd, RESP_CMSG, &tmp_len, cmsgbuf);
		msg.msg_controllen= tmp_len;
	}
	else
	{
		nrecv= recvmsg(qry->udp_fd, &msg, MSG_DONTWAIT);
	}
	if (nrecv < 0) {
		/* One more failure */
		qry->base->recvfail++;
		return ;
	}
	if (qry->response_out)
	{
		write_response(qry->resp_file, RESP_PACKET, nrecv,
			qry->base->packet);
		write_response(qry->resp_file, RESP_PEERNAME, sizeof(remote),
			&remote);
		write_response(qry->resp_file, RESP_CMSG, msg.msg_controllen,
			cmsgbuf);
	}

	process_reply(arg, nrecv, rectime, &msg);
	return;
} 

static bool argProcess (int argc, char *argv[], struct query_state *qry )
{
	char *validated_fn= NULL;

	if( qry->opt_resolv_conf) {
		qry->resolv_i = 0;
	}
	else if (optind != argc-1)  {
		crondlog(LVL9 "ERROR no server IP address in input");
		tdig_delete(qry);
		return TRUE;
	}
	else 
		qry->server_name = strdup(argv[optind]);

	if (qry->macro_lookupname == NULL) {
		crondlog(LVL9 "ERROR no query in command line");
		tdig_delete(qry);
		return TRUE;
	}

	if (qry->macro_lookupname[strlen(qry->macro_lookupname) - 1] != '.') {
		crondlog(LVL9 "ERROR query %s does not end with a dot ",
			qry->macro_lookupname);
		tdig_delete(qry);
		return TRUE;
	}

	if (qry->out_filename)
	{
		validated_fn= rebased_validated_filename(qry->out_filename,
			SAFE_PREFIX_REL);
		if (validated_fn == NULL)
		{
			crondlog(LVL8 "insecure file '%s'", qry->out_filename);
			tdig_delete(qry);
			return TRUE;
		}
		free(qry->out_filename);
		qry->out_filename= validated_fn; validated_fn= NULL;
	}
	if (qry->response_in)
	{
		validated_fn= rebased_validated_filename(qry->response_in,
			ATLAS_FUZZING_REL);
		if (!validated_fn)
		{
			crondlog(LVL8 "insecure fuzzing file '%s'",
				qry->response_in);
			tdig_delete(qry);
			return TRUE;
		}
		free(qry->response_in);
		qry->response_in= validated_fn; validated_fn= NULL;
	}
	if (qry->response_out)
	{
		validated_fn= rebased_validated_filename(qry->response_out,
			ATLAS_FUZZING_REL);
		if (!validated_fn)
		{
			crondlog(LVL8 "insecure fuzzing file '%s'",
				qry->response_out);
			tdig_delete(qry);
			return TRUE;
		}
		free(qry->response_out);
		qry->response_out= validated_fn; validated_fn= NULL;
	}

	if(qry->opt_v6_only  == 0)
	{
		qry->opt_v4_only = 1;
		qry->opt_AF = AF_INET;
	}

#if ENABLE_FEATURE_EVTDIG_TLS
	if (qry->opt_do_tls || qry->opt_do_https)
	{
		qry->opt_proto = 6; /* switch to TCP for TLS and HTTPS */
	}
#endif

	if (qry->port_as_char == NULL) 
	{
#if ENABLE_FEATURE_EVTDIG_TLS
	      if (qry->opt_do_https)
	      {
		qry->port_as_char = strdup("443");
	      } 
	      else if (qry->opt_do_tls)
	      {
		qry->port_as_char = strdup("853");
	      } 
	      else 
#endif
	      {
		qry->port_as_char = strdup("53");
	      }
	}
	return FALSE;
}

/* this called for each query/line in eperd */
static void *tdig_init(int argc, char *argv[],
	void (*done)(void *state, int error))
{
	char *check;
	struct query_state *qry;
	int c, r, fd;

	if (!tdig_base)
		tdig_base = tdig_base_new(EventBase);

	if (!tdig_base) {
		crondlog(LVL8 "tdig_base_new failed");
		return NULL;
	}

	tdig_base->done = done;

	qry=xzalloc(sizeof(*qry));

	// initialize per query state variables;
	qry->qtype = T_TXT; /* TEXT */
	qry->qclass = C_CHAOS;
	qry->opt_v4_only = 0; 
	qry->opt_v6_only = 0; 
	qry->str_Atlas = NULL;
	qry->str_bundle = NULL;
	qry->out_filename = NULL;
	qry->opt_proto = 17; 
	qry->cookie_state = NULL;
	qry->udp_fd = -1;
	qry->server_name = NULL;
	qry->infname = NULL;
	tdig_base->activeqry++;
	qry->qst = STATUS_FREE;
	qry->retry  = 0;
	qry->resolv_i = 0;
	qry->opt_retry_max = DEFAULT_RETRY_MAX;
	qry->wire_size = 0;
	qry->triptime = 0;
	qry->opt_edns0 = 512; 
	qry->opt_edns_version = 0;
	qry->opt_edns_flags = 0;
	qry->opt_edns_option = 0;
	qry->opt_ipv6_dest_option = 0;
	qry->opt_dnssec = 0;
	qry->opt_nsid = 0; 
	qry->opt_client_subnet = 0; 
	qry->opt_cookies = 0; 
	qry->opt_qbuf = 0; 
	qry->opt_abuf = 1; 
	qry->opt_rd = 0;
	qry->opt_ad = 0;
	qry->opt_cd = 0;
	qry->opt_evdns = 0;
	qry->opt_rset = 0;
	qry->opt_prepend_probe_id = 0;
	qry->ressave = NULL;
	qry->ressent = NULL;
	buf_init(&qry->err, -1);
	buf_init(&qry->packet, -1);
	qry->opt_resolv_conf = 0;
	qry->macro_lookupname = NULL;
	qry->lookupname = NULL;
	qry->port_as_char = NULL;
	qry->dst_ai_family = 0;
	qry->loc_ai_family = 0;
	qry->loc_sin6.sin6_family = 0;
	qry->result.offset = qry->result.size = qry->result.maxsize= 0;
	qry->result.buf = NULL;
	qry->rcvdttl= -42;
	qry->opt_query_arg = 0;
	qry->opt_timeout= DEFAULT_NOREPLY_TIMEOUT;
	qry->opt_do_tls = 0;
	qry->opt_do_ttl = 0;
	qry->opt_do_https = 0;
	qry->sni_cert_name = NULL;
	qry->https_path = NULL;
	qry->resp_file= NULL;
	qry->http2_env= NULL;

	/* initialize callbacks : */
	/* sendpacket  called by UDP send */
	evtimer_assign(&qry->nsm_timer, tdig_base->event_base,
		tdig_send_query_callback, qry);
	/* no reply timeout for udp  queries */
	evtimer_assign(&qry->noreply_timer, tdig_base->event_base,
		noreply_callback, qry); 

	/* callback/timer used for restarting query by --resolve */
	evtimer_assign(&qry->next_qry_timer, tdig_base->event_base, next_qry_cb, qry);
	evtimer_assign(&qry->done_qry_timer, tdig_base->event_base, done_qry_cb, qry);

	optind = 0;
	while (c= getopt_long(argc, argv, "46adD:e:tbhinqO:Rrs:A:B:I:?", longopts, NULL), c != -1) {
		switch(c) {
			case '1':
				qry->opt_edns_version=
					strtoul(optarg, &check, 10);
				break;
			case '2':
				qry->opt_edns_flags=
					strtoul(optarg, &check, 0);
				break;
			case '3':
				qry->opt_edns_option=
					strtoul(optarg, &check, 0);
				break;

			case '4':
				qry->opt_v4_only = 1;
				qry->opt_AF = AF_INET;
				break;

			case '5':
				qry->opt_ipv6_dest_option=
					strtoul(optarg, &check, 10);
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
				if (!validate_atlas_id(optarg))
				{
					crondlog(LVL8 "bad atlas ID '%s'",
						optarg);
					tdig_delete(qry);
					return NULL;
				}
				qry->str_Atlas = strdup(optarg);
				break;

			case 'B':
				if (!validate_atlas_id(optarg))
				{
					crondlog(LVL8 "bad bundle ID '%s'",
						optarg);
					tdig_delete(qry);
					return NULL;
				}
				qry->str_bundle= strdup(optarg);
				break;

			case 'b':
				qry->macro_lookupname =
					strdup ("version.bind.");
				break;
		
			case 'c':
				qry->opt_client_subnet = 1;
				break;
			case 'C':
				qry->opt_cookies = 1;
				break;

			case 'd':
				qry->opt_dnssec = 1;
				break;

			case 'e':
				qry->opt_edns0= strtoul(optarg, &check, 10);
				break;

			case 'h':
				qry->macro_lookupname =
					strdup("hostname.bind.");
				break;

			case 'i':
				qry->macro_lookupname = strdup("id.server.");
				break;
			case 'I':
				free(qry->infname);
				qry->infname= strdup(optarg);
				break;

			case 'n':
				qry->opt_nsid = 1;
				break;

			case 'p':
				qry->port_as_char = strdup(optarg);
				break;

			case 'O':
				qry->out_filename = strdup(optarg);
				break;

			case 'r':
				qry->macro_lookupname =
					strdup("version.server.");
				break;

			case 'R':
				qry->opt_rd = 1;
				break;

			case 's':
				qry->qtype = T_SOA;
				qry->qclass = C_IN;
				qry->macro_lookupname = strdup(optarg);
				break;

			case 't':
				qry->opt_proto = 6;
				break;

			case 'T' :
				qry->opt_timeout = strtoul(optarg, NULL, 10);
				break;

			case 1001:
				qry->opt_qbuf = 1;
				break;

			case 1002:
				qry->opt_abuf = 0;
				break;


#if ENABLE_FEATURE_EVTDIG_TLS
			case O_TLS:
				qry->opt_do_tls = 1;
				break;
#endif

			case O_TTL:
				qry->opt_do_ttl = 1;
				break;

			case O_HTTPS:
				qry->opt_do_https = 1;
				break;

			case O_SNI_CERT_NAME:
				qry->sni_cert_name = strdup(optarg);
				break;

			case O_HTTPS_PATH:
				qry->https_path = strdup(optarg);
				break;

			case O_TYPE:
				qry->qtype = strtoul(optarg, &check, 10);
				if ((qry->qtype >= 0 ) && 
						(qry->qclass < 65536)) {

					if (! qry->qclass ) 
						qry->qclass = C_IN;

					break;
				}
				else {
					fprintf(stderr, "ERROR unknown Q "
							"--typae %s ??. 0 - "
							"65535\n", optarg); 
					tdig_delete(qry);
					return (0);
				}
				break;

			case O_AD:
				qry->opt_ad = 1;
				break;

			case O_CD:
				qry->opt_cd = 1;
				break;

			case O_CLASS:
				qry->qclass = strtoul(optarg, &check, 10);
				if ((qry->qclass  >= 0 ) && 
						(qry->qclass < 65536)) {
					break;
				}
				else {
					fprintf(stderr, "ERROR unknown Q class"
							" --class %s ??. 0 - "
							"65535\n", optarg); 
					tdig_delete(qry);
					return (0);
				}

			case O_RETRY :
				qry->opt_query_arg = 1;
				qry->opt_retry_max = strtoul(optarg, NULL, 10);
				break;

			case O_QUERY:
				qry->opt_query_arg  = 1;
				qry->macro_lookupname = strdup(optarg);
				break;

			case O_RESOLV_CONF :
				qry->opt_resolv_conf = 1;
				qry->opt_v6_only = 1;
				qry->opt_v4_only = 1;
				qry->opt_rset = 1;
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
				qry->macro_lookupname = strdup(optarg);
				break;

			case (100000 + T_AAAA ):
				qry->qtype = T_AAAA ;
				qry->qclass = C_IN;
				qry->macro_lookupname = strdup(optarg);
				break;

			case (100000 + T_AFSDB ):
				qry->qtype = T_AFSDB ;
				qry->qclass = C_IN;
				qry->macro_lookupname = strdup(optarg);
				break;

			case (100000 + T_ANY):
				qry->qtype = T_ANY ;
				qry->qclass = C_IN;
				qry->macro_lookupname = strdup(optarg);
				break;

			case (100000 + T_APL):
				qry->qtype = T_APL ;
				qry->qclass = C_IN;
				qry->macro_lookupname = strdup(optarg);
				break;

			case (100000 + T_AXFR ):
				qry->qtype = T_AXFR ;
				qry->qclass = C_IN;
				qry->macro_lookupname = strdup(optarg);
				break;

			case (100000 + T_CAA):
				qry->qtype = T_CAA ;
				qry->qclass = C_IN;
				qry->macro_lookupname = strdup(optarg);
				break;

			case (100000 + T_CERT):
				qry->qtype = T_CERT ;
				qry->qclass = C_IN;
				qry->macro_lookupname = strdup(optarg);
				break;

			case (100000 + T_CNAME):
				qry->qtype = T_CNAME;
				qry->qclass = C_IN;
				qry->macro_lookupname = strdup(optarg);
				break;

			case (100000 + T_DLV):
				qry->qtype = T_DLV;
				qry->qclass = C_IN;
				qry->macro_lookupname = strdup(optarg);
				break; 

			case (100000 + T_DNAME):
				qry->qtype = T_DNAME;
				qry->qclass = C_IN;
				qry->macro_lookupname = strdup(optarg);
				break;

			case (100000 + T_DNSKEY):
				qry->qtype = T_DNSKEY;
				qry->qclass = C_IN;
				qry->macro_lookupname = strdup(optarg);
				break;

			case (100000 + T_DS):
				qry->qtype = T_DS;
				qry->qclass = C_IN;
				qry->macro_lookupname  = strdup(optarg);
				break;

			case (100000 + T_IPSECKEY):
				qry->qtype = T_IPSECKEY;
				qry->qclass = C_IN;
				qry->macro_lookupname  = strdup(optarg);
				break;

			case (100000 + T_LOC):
				qry->qtype = T_LOC;
				qry->qclass = C_IN;
				qry->macro_lookupname  = strdup(optarg);
				break;

			case (100000 + T_MX):
				qry->qtype = T_MX;
				qry->qclass = C_IN;
				qry->macro_lookupname = strdup(optarg);
				break;

			case (100000 + T_NAPTR):
				qry->qtype = T_NAPTR;
				qry->qclass = C_IN;
				qry->macro_lookupname = strdup(optarg);
				break;

			case (100000 + T_NS):
				qry->qtype = T_NS;
				qry->qclass = C_IN;
				qry->macro_lookupname = strdup(optarg);
				break;

			case (100000 + T_NSEC):
				qry->qtype = T_NSEC;
				qry->qclass = C_IN;
				qry->macro_lookupname = strdup(optarg);
				break;

			case (100000 + T_NSEC3):
				qry->qtype = T_NSEC3;
				qry->qclass = C_IN;
				qry->macro_lookupname = strdup(optarg);
				break;

			case (100000 + T_NSEC3PARAM):
				qry->qtype = T_NSEC3PARAM;
				qry->qclass = C_IN;
				qry->macro_lookupname = strdup(optarg);
				break;

			case (100000 + T_PTR):
				qry->qtype = T_PTR;
				qry->qclass = C_IN;
				qry->macro_lookupname = strdup(optarg);
				break;

			case (100000 + T_RRSIG):
				qry->qtype = T_RRSIG;
				qry->qclass = C_IN;
				qry->macro_lookupname = strdup(optarg);
				break;

			case (100000 + T_RP):
				qry->qtype = T_RP;
				qry->qclass = C_IN;
				qry->macro_lookupname = strdup(optarg);
				break;

			case (100000 + T_SIG):
				qry->qtype = T_SIG;
				qry->qclass = C_IN;
				qry->macro_lookupname = strdup(optarg);
				break;

			case (100000 + T_SPF):
				qry->qtype = T_SPF;
				qry->qclass = C_IN;
				qry->macro_lookupname = strdup(optarg);
				break;

			case (100000 + T_SRV):
				qry->qtype = T_SRV;
				qry->qclass = C_IN;
				qry->macro_lookupname = strdup(optarg);
				break;

			case (100000 + T_SSHFP):
				qry->qtype = T_SSHFP;
				qry->qclass = C_IN;
				qry->macro_lookupname = strdup(optarg);
				break;

			case (100000 + T_TA):
				qry->qtype = T_TA;
				qry->qclass = C_IN;
				qry->macro_lookupname =  strdup(optarg);
				break;

			case (100000 + T_TLSA):
				qry->qtype = T_TLSA;
				qry->qclass = C_IN;
				qry->macro_lookupname =  strdup(optarg);
				break;

			case (100000 + T_TSIG):
				qry->qtype = T_TSIG;
				qry->qclass = C_IN;
				qry->macro_lookupname =  strdup(optarg);
				break;

			case (100000 + T_TXT):
				qry->qtype = T_TXT;
				qry->qclass = C_IN;
				qry->macro_lookupname =  strdup(optarg);
				break;

			case 200000 + 'W':
				if (qry->response_out) free(qry->response_out);
				qry->response_out= strdup(optarg);
				break;

			case 200000 + 'R':
				if (qry->response_in) free(qry->response_in);
				qry->response_in= strdup(optarg);
				break;

			default:
				fprintf(stderr, "ERROR unknown option %d ??\n", c); 
				tdig_delete(qry);
				return (0);
				break;
		}
	}

	if(argProcess(argc, argv, qry))
			return NULL;

	qry->opt_evdns = 1;	/* Always enabled, leave the old code in
				 * place for now.
				 */

	if (qry->opt_cookies)
	{
		qry->cookie_state= malloc(sizeof(*qry->cookie_state));
		memset(qry->cookie_state, '\0', sizeof(*qry->cookie_state));

		/* Get secret */
		fd= open("/dev/urandom", O_RDONLY);
		if (fd == -1)
		{
			crondlog(LVL8 "unable to open /dev/urandom");
			return NULL;
		}
		r= read(fd, qry->cookie_state->client_secret,
			sizeof(qry->cookie_state->client_secret));
		close(fd);
		if (r != sizeof(qry->cookie_state->client_secret))
		{
			crondlog(LVL8 "unable to read from /dev/urandom");
			return NULL;
		}
	}

	qry->base = tdig_base;

	/* insert this qry into the list of queries */
	if (!tdig_base->qry_head) {
		qry->next = qry->prev = qry;
		tdig_base->qry_head = qry;
		tdig_stats( 0, 0, tdig_base); // call this first time to initial values.
		// crondlog(LVL7 "new head qry %s qry->prev %s qry->next %s", qry->str_Atlas,  qry->prev->str_Atlas,  qry->next->str_Atlas);
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
	struct timeval tv;

	tdig_base= xzalloc(sizeof( struct tdig_base));
	if (tdig_base == NULL)
	{
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

	memset(tdig_base, 0, sizeof(struct tdig_base));
	tdig_base->event_base = event_base;

	//memset(&tdig_base-->loc_sin6, '\0', sizeof(tdig_base-->loc_sin6));
	//tdig_base-->loc_socklen= 0;

	evtimer_assign(&tdig_base->statsReportEvent, tdig_base->event_base, tdig_stats, tdig_base);

	// Define the callback to handle UDP Reply 
	// add the raw file descriptor to those monitored for read events 

	tv.tv_sec =  DEFAULT_STATS_REPORT_INTERVEL;
	tv.tv_usec =  0;
	event_add(&tdig_base->statsReportEvent, &tv);

	return tdig_base;
}

static void udp_dns_cb(int err, struct evutil_addrinfo *ev_res, void *arg) {
	struct query_state *qry;
	qry= arg;
	if (err)  {
		snprintf(line, DEFAULT_LINE_LENGTH, "\"evdns_getaddrinfo\": "
				"\"%s %s\"", qry->server_name, 
				evutil_gai_strerror(err));
		buf_add(&qry->err, line, strlen(line));
		printReply (qry, 0, NULL);
		return ;

	}
	else {
		qry->res = ev_res;
		qry->ressave = ev_res;
		qry->qst = STATUS_SEND;
		tdig_send_query_callback(0, 0, qry);
	}
}

void tdig_start (void *arg)
{
	struct timeval asap = { 0, 0 };
	struct timeval interval;

	int i, err_num;
	size_t len;
	struct query_state *qry;
	struct addrinfo hints, *res;
	char port[] = "domain";
	struct sockaddr_in6 sin6;
	char strbuf[256];

	qry= arg;

	qry->client_cookie_mismatch= false;

	switch(qry->qst)
	{
		case STATUS_FREE :
			/* Macro processing */
			if (qry->lookupname)
			{
				free(qry->lookupname);
				qry->lookupname= NULL;
			}
			qry->lookupname=
				atlas_name_macro(qry->macro_lookupname);
			if (qry->lookupname == NULL)
			{
				snprintf(line, DEFAULT_LINE_LENGTH,
				"\"err\": \"macro expansion failed\"");
				buf_add(&qry->err, line, strlen(line));
				printReply (qry, 0, NULL);
				return;
			}

			/* Get time in case we don't send any packet */
			qry->xmit_time= atlas_time();
			qry->resolv_i = 0;
			// crondlog(LVL5 "RESOLV QUERY FREE %s resolv_max %d", qry->server_name,  qry->resolv_max);
			if( qry->opt_resolv_conf) {
				if (qry->response_in)
				{
					if (qry->udp_fd == -1)
					{
						qry->udp_fd=
							open(qry->response_in,
							O_RDONLY);
						if (qry->udp_fd == -1)
						{
							crondlog(
						DIE9 "unable to open '%s': %s",
							qry->response_in,
							strerror(errno));
						}
					}
					len= sizeof(qry->resolv_max);
					read_response(qry->udp_fd,
						RESP_N_RESOLV, &len,
						&qry->resolv_max);
					if (len != sizeof(qry->resolv_max))
					{
						crondlog(
				DIE9 "tdig_start: error reading from '%s'",
							qry->response_in);
					}
					for (i= 0; i<qry->resolv_max; i++)
					{
						len= sizeof(strbuf)-1;
						read_response(qry->udp_fd,
							RESP_RESOLVER, &len,
							strbuf);
						strbuf[len]= '\0';
						qry->nslist[i]= strdup(strbuf);
					}
				}
				else
				{
					get_local_resolvers (qry->nslist,
						&qry->resolv_max,
						qry->infname);
				}
				// crondlog(LVL5 "AAA RESOLV QUERY FREE %s resolv_max %d %d", qry->server_name,  qry->resolv_max, qry->resolv_i);
				if (qry->response_out)
				{
					if (!qry->resp_file)
					{
						qry->resp_file=
							fopen(qry->response_out,
							 "w");
						if (!qry->resp_file)
						{
							crondlog(	
						DIE9 "unable to write to '%s'",
								qry->
								response_out);
						}
					}

					write_response(qry->resp_file,
						RESP_N_RESOLV,
						sizeof(qry->resolv_max),
						&qry->resolv_max);
					for (i= 0; i<qry->resolv_max; i++)
					{
						write_response(qry->resp_file,
							RESP_RESOLVER,
							strlen(qry->nslist[i]),
							qry->nslist[i]);
					}
				}
				if(qry->resolv_max ) {
					free(qry->server_name);
					qry->server_name = NULL;
					qry->server_name =
						strdup(qry->nslist
						[qry->resolv_i]);
				}
				else {
					crondlog(LVL5 "AAA RESOLV QUERY FREE %s resolv_max is zero %d i %d", qry->server_name,  qry->resolv_max, qry->resolv_i);
					free(qry->server_name);
					qry->server_name = NULL;
					snprintf(line, DEFAULT_LINE_LENGTH, "\"nameserver\": \"no local resolvers found\"");
					buf_add(&qry->err, line, strlen(line));
					printReply (qry, 0, NULL);
					return;
				}
			}
			break;

		case STATUS_NEXT_QUERY :
		case STATUS_RETRANSMIT_QUERY:
			break;
		default:
			printErrorQuick(qry);
			return ;
	}

	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = 0;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = 0;

	qry->xmit_time= atlas_time();
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

	if (qry->response_out && !qry->resp_file)
	{
		qry->resp_file= fopen(qry->response_out, "w");
		if (!qry->resp_file)
		{
			crondlog(DIE9 "unable to write to '%s'",
				qry->response_out);
		}
	}

	if(qry->opt_proto == 17) {  //UDP 
		if (qry->response_in)
		{
			qry->res = NULL;
			qry->ressave = NULL;
			qry->qst = STATUS_SEND;
			tdig_send_query_callback(0, 0, qry);
		}
		else if(qry->opt_evdns ) {
			// use EVDNS asynchronous call 
			evdns_getaddrinfo(DnsBase, qry->server_name, qry->port_as_char, &hints, udp_dns_cb, qry);
		}
		else {
			// using getaddrinfo; blocking call
			if ( ( err_num  = getaddrinfo(qry->server_name, port , &hints, &res)))
			{
				snprintf(line, DEFAULT_LINE_LENGTH, "%s \"getaddrinfo\": \"port %s, AF %d %s\"", qry->err.size ? ", " : "",  port,  hints.ai_family, gai_strerror(err_num));
				buf_add(&qry->err, line, strlen(line));
				printReply (qry, 0, NULL);
				return ;
			}

			qry->res = res;
			qry->ressave = res;

			evtimer_add(&qry->nsm_timer, &asap);
			qry->qst =  STATUS_SEND;
		}
	}
	else { // TCP Query

		qry->wire_size =  0;
		// crondlog(LVL5 "TCP QUERY %s", qry->server_name);
		interval.tv_sec = CONN_TO;
		interval.tv_usec= 0;

		if (qry->response_in)
		{
			size_t len;

			qry->resp_file= fopen(qry->response_in, "r");
			if (!qry->resp_file)
			{
				crondlog(DIE9 "unable to read from '%s'",
					qry->response_in);
			}

			len= sizeof(sin6);
			read_response_file(qry->resp_file, RESP_PEERNAME,
				&len, &sin6);
			tcp_beforeconnect(&qry->tu_env,
				(struct sockaddr *)&sin6, len);
			tcp_connected(&qry->tu_env, NULL);
			tcp_writecb(NULL, &qry->tu_env);
			while(qry->resp_file != NULL)
				tcp_readcb(NULL, &qry->tu_env);
			// report(qry);
		}
		else
		{
			tu_connect_to_name (&qry->tu_env,   qry->server_name,
					qry->opt_do_tls, qry->opt_do_https,
					qry->port_as_char,
					&interval, &hints, qry->infname,
					qry->sni_cert_name,
					qry->sni_cert_name,
					tcp_timeout_callback, tcp_reporterr,
					tcp_dnscount, tcp_beforeconnect,
					tcp_connected, tcp_readcb, tcp_writecb);
		}

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
	struct timeval interval;
	FILE *fh;	
	struct tdig_base *base;
	struct query_state *qry_h;
	struct query_state *qry;

	base = h;	
	if(!base->qry_head )
		return;

	qry_h = base->qry_head; 

	if(! base->sentok )
		return;


	if(qry_h->base->done) {
		interval.tv_sec =  DEFAULT_STATS_REPORT_INTERVEL;
		interval.tv_usec =  0;
		event_add(&tdig_base->statsReportEvent, &interval);
		return;
	}

	if (qry_h->out_filename) {
		fh= fopen(qry_h->out_filename, "a");
		if (!fh) {
			crondlog(LVL8 "evtdig: unable to append to '%s'", qry_h->out_filename);
			return;
		}
	}
	else
		fh = stdout;  

	qry=xzalloc(sizeof(*qry));

	AS("RESULT { ");
	JS(id, "9201" ); 
	AS(atlas_get_version_json_str());
	AS(", ");
	gettimeofday(&now, NULL);
	JS1(time, %llu,  (unsigned long long)now.tv_sec);
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

	AS(" }\n");
	fwrite(qry->result.buf, qry->result.size, 1 , fh);
	if (qry_h->out_filename) 
		fclose (fh);

	buf_cleanup(&qry->result);
	free(qry);

	interval.tv_sec =  DEFAULT_STATS_REPORT_INTERVEL;
	interval.tv_usec =  0;
	event_add(&tdig_base->statsReportEvent, &interval);
}


/* Convert a string into DNS format. This is for a query so no compression.
 * DNS format is a length byte followed by the contents of a label. We
 * can assume that length of the DNS format is one larger than the original
 * string because of the dots (except for just '.' where the length is the
 * same).
 */
static int ChangetoDnsNameFormat(u_char *dns, size_t maxlen, char* qry)
{
	size_t qrylen, labellen;
	char *src, *e;
	u_char *dst;

	qrylen= strlen(qry);

	if (qrylen+1 > maxlen)
	{
		// printf("ChangetoDnsNameFormat: name too long\n");
		return -1;	/* Doesn't fit */
	}

	if (strcmp(qry, ".") == 0)
	{
		/* This doesn't fit in our regular schedule */
		dns[0]= 0;
		return 1;
	}

	src= qry;
	dst= dns;
	for (; src[0] != '\0' && dst < dns+maxlen;)
	{
		e= strchr(src, '.');
		if (e == NULL)
		{
			// printf("ChangetoDnsNameFormat: no trailing dot\n");
			return -1;	/* qry does not end in a '.' */
		}

		labellen= e-src;
		if (labellen > 63)
		{
			// printf("ChangetoDnsNameFormat: label too long\n");
			return -1;	/* Can't do more than 63 */
		}
		if (labellen == 0)
		{
			// printf("ChangetoDnsNameFormat: empty label\n");
			return -1;	/* Take care of lonely '.' earlier */
		}

		*dst= labellen;
		dst++;
		memcpy(dst, src, labellen);
		src= e+1;
		dst += labellen;
	}

	/* End, at a trailing null label */
	*dst= 0;
	dst++;

	return dst-dns;
} 


static void free_qry_inst(struct query_state *qry)
{
	int i;
	struct timeval asap = { 1, 0 };
	// BLURT(LVL5 "freeing instance of %s ", qry->server_name);

	if (qry->response_in)
	{
		asap.tv_sec= 0;
		asap.tv_usec= 1;
	}

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
	qry->wire_size = 0;

	if(qry->packet.size)
	{
		buf_cleanup(&qry->packet);
	}

	if(qry->opt_proto == 6)
	{
		if (!qry->response_in)
			tu_cleanup(&qry->tu_env);
	}

	if (qry->udp_fd != -1)
	{
		if (qry->response_in && qry->resolv_i < qry->resolv_max)
		{
			/* Keep input open */
		}
		else
		{
			event_del(&qry->event);
			close(qry->udp_fd);
			qry->udp_fd= -1;
		}
	}

	if ( qry->opt_resolv_conf) {
		// this loop goes over servers in /etc/resolv.conf
		// select the next server and restart
		if(qry->resolv_i < qry->resolv_max) {
			if(qry->server_name) {
				free (qry->server_name);
				qry->server_name = NULL;
			}
			if (qry->nslist[qry->resolv_i] == NULL)
			{
				crondlog(DIE9 "free_qry_inst: qry %p, no resolver at index %d, max %d", qry, qry->resolv_i, qry->resolv_max);
			}
			qry->server_name = strdup(qry->nslist[qry->resolv_i]);
			qry->qst = STATUS_NEXT_QUERY;
			evtimer_add(&qry->next_qry_timer, &asap);
			return;
		}
	}

	for (i= 0; i<MAXNS; i++)
	{
		if (qry->nslist[i])
		{
			free(qry->nslist[i]);
			qry->nslist[i]= NULL;
		}
	}

	if (qry->http2_env)
	{
		http2_free(qry->http2_env);
		qry->http2_env= NULL;
	}

	switch(qry->qst){
		case STATUS_RETRANSMIT_QUERY:
			break;

		default:
			qry->qst =  STATUS_FREE;
			if(qry->base->done) {
				evtimer_add(&qry->done_qry_timer, &asap);
			}
			if (qry->resp_file)
			{
				fclose(qry->resp_file);
				qry->resp_file= NULL;
			}
			break;
	}
}


static int tdig_delete(void *state)
{
	int i;
	struct query_state *qry;

	qry = state;
	
	if (qry->qst )
		return 0;

	if (qry->cookie_state)
	{
		free(qry->cookie_state);
		qry->cookie_state= NULL;
	}
	if(qry->out_filename)
	{ 
		free(qry->out_filename);
		qry->out_filename = NULL ;
	}
	if(qry->macro_lookupname) 
	{
		free(qry->macro_lookupname);
		qry->macro_lookupname = NULL;
	}
	if(qry->lookupname) 
	{
		free(qry->lookupname);
		qry->lookupname = NULL;
	}
	if(qry->infname)
	{
		free(qry->infname);
		qry->infname = NULL;
	}
	if (qry->port_as_char)
	{
		free(qry->port_as_char);
		qry->port_as_char = NULL;
	}
	if (qry->sni_cert_name)
	{
		free(qry->sni_cert_name);
		qry->sni_cert_name= NULL;
	}
	if (qry->https_path)
	{
		free(qry->https_path);
		qry->https_path = NULL;
	}

	/* Delete timers */
	evtimer_del(&qry->noreply_timer);
	evtimer_del(&qry->nsm_timer);

	if((qry->next == qry->prev) && (qry->next == qry)) {
		qry->base->qry_head =  NULL;
		crondlog(LVL7 "deleted last query qry %s", qry->str_Atlas);
	}
	else {
#if ENABLE_FEATURE_EVTDIG_DEBUG
		crondlog(LVL7 "deleted qry %s qry->prev %s qry->next %s qry_head %s", qry->str_Atlas,  qry->prev->str_Atlas,  qry->next->str_Atlas, qry->base->qry_head->str_Atlas);
		crondlog(LVL7 "old qry->next->prev %s qry->prev->next  %s", qry->next->prev->str_Atlas,  qry->prev->next->str_Atlas);
#endif
		if(qry->next)
			qry->next->prev = qry->prev; 
		if(qry->prev)
			qry->prev->next = qry->next;
		if(qry->base && qry->base->qry_head == qry) 
			qry->base->qry_head = qry->next;

#if ENABLE_FEATURE_EVTDIG_DEBUG
		crondlog(LVL7 "new qry->next->prev %s qry->prev->next  %s", qry->next->prev->str_Atlas,    qry->prev->next->str_Atlas);
#endif
	}
	if( qry->str_Atlas) 
	{
		free( qry->str_Atlas);
		qry->str_Atlas = NULL;
	}
	if( qry->str_bundle) 
	{
		free( qry->str_bundle);
		qry->str_bundle = NULL;
	}
	if(qry->server_name)
	{
		free(qry->server_name);
		qry->server_name = NULL;
	} 
	for (i= 0; i<MAXNS; i++)
	{
		if (qry->nslist[i])
		{
			free(qry->nslist[i]);
			qry->nslist[i]= NULL;
		}
	}
	if (qry->udp_fd != -1)
	{
		event_del(&qry->event);
		close(qry->udp_fd);
		qry->udp_fd= -1;
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
	if (qry->out_filename)
	{
		fh= fopen(qry->out_filename, "a");
		if (!fh){
			crondlog(LVL8 "evtdig: unable to append to '%s'",
					qry->out_filename);
			return;
		}
	}
	else
		fh = stdout;

	fprintf(fh, "RESULT { ");
	fprintf(fh, "%s,", atlas_get_version_json_str());
	fprintf(fh, "\"id\" : 9202 ,");
	fprintf(fh, "\"time\" : %llu ,",  (unsigned long long)atlas_time());

	fprintf(fh, "\"error\" : [{ ");
	fprintf(fh, "\"query busy\": \"not starting a new one. previous one is not done yet\"}");
	if(qry->str_Atlas)
	{
		fprintf(fh, ",{");
		fprintf(fh, "\"id\" : \"%s\"",  qry->str_Atlas);
		if (qry->str_bundle)
			fprintf(fh, ",\"bundle\" : %s",  qry->str_bundle);
		fprintf(fh, ",\"start time\" : %llu",  (unsigned long long)qry->xmit_time);
		if(qry->retry) {
			fprintf(fh, ",\"retry\": %d",  qry->retry);
			
		}	
		if(qry->opt_retry_max) {
			fprintf(fh, ",\"retry max\": %d",  qry->opt_retry_max);
		}	
		fprintf(fh, "}");
	}
	fprintf(fh,"]}");

	fprintf(fh, "\n");
	if (qry->out_filename)
		fclose(fh);
}

void printReply(struct query_state *qry, int wire_size, unsigned char *result)
{
	int i, stop=0;
	struct DNS_HEADER *dnsR = NULL;
	struct RES_RECORD answers[20]; //the replies from the DNS server
	void *ptr = NULL;
	FILE *fh; 
	char addrstr[INET6_ADDRSTRLEN];
	u_int32_t serial;
	int iMax ;
	int flagAnswer = 0;
	int data_len, len;
	int write_out = FALSE;
	unsigned offset;
	unsigned char *name1= NULL, *name2= NULL;

	int lts = get_timesync();

	if(! qry->result.size){
		buf_init(&qry->result, -1);

		AS("RESULT { ");

		if(qry->str_Atlas) 
		{
			JS(id,  qry->str_Atlas);
			if (qry->str_bundle) {
				JS1(bundle, %s, qry->str_bundle);
			}
		}

		AS(atlas_get_version_json_str());
		AS(", ");
		if (qry->opt_rset){
			JS1(time, %llu,  (unsigned long long)qry->xmit_time);
			JD(lts,lts);
			AS("\"resultset\" : [ {");
		}

	}
	else if(qry->opt_rset) {
		AS (",{");
	}

	JS1(time, %llu,  (unsigned long long)qry->xmit_time);
	JD(lts,lts);

	if (qry->response_in || qry->response_out)
		ssl_version= "test 0.0.0";

	if ((qry->opt_do_tls || qry->opt_do_https) && ssl_version != NULL)
		JS(sslvers, ssl_version);

	if ( qry->opt_resolv_conf ) {
		JD (subid, (qry->resolv_i+1));
		JD (submax, qry->resolv_max);
	}

	if( qry->ressent && qry->server_name)
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
		inet_ntop (qry->ressent->ai_family, ptr, addrstr, INET6_ADDRSTRLEN);
		if(strcmp(addrstr, qry->server_name)) {
			JS(name,  qry->server_name);
		}
		JS(dst_addr, addrstr);
		JS(dst_port, qry->port_as_char);
		JD(af, qry->ressent->ai_family == PF_INET6 ? 6 : 4);
	}
	else if(qry->dst_ai_family && qry->server_name)
	{
		if(strcmp(qry->dst_addr_str, qry->server_name)) {
			JS(dst_name,  qry->server_name);
		}
		JS(dst_addr , qry->dst_addr_str);
		JS(dst_port, qry->port_as_char);
		JD(af, qry->dst_ai_family == PF_INET6 ? 6 : 4);
	}
	else if(qry->server_name) {
			JS(dst_name,  qry->server_name);
	}
	
	if(qry->loc_sin6.sin6_family) {
		getnameinfo((struct sockaddr *)&qry->loc_sin6,
				qry->loc_socklen, addrstr, INET6_ADDRSTRLEN,
				NULL, 0, NI_NUMERICHOST);
		if(strlen(addrstr)) 
			JS(src_addr, addrstr); 
	}
	
	if(qry->retry) {
		JS1(retry, %d,  qry->retry);
	}

	if (qry->rcvdttl >= 0)
		JD(ttl,  qry->rcvdttl);

	JS_NC(proto, qry->opt_proto == 6 ? "TCP" : "UDP" );

	if(qry->opt_qbuf && qry->qbuf.size) {
		AS(",\"qbuf\" : \"");
		buf_add(&qry->result,  qry->qbuf.buf,  qry->qbuf.size);
		AS("\" ");
	} 

	if(result)
	{
		snprintf(line, DEFAULT_LINE_LENGTH, ",\"result\" : { \"rt\" : %.3f,", qry->triptime);
		buf_add(&qry->result,line, strlen(line));

		if (qry->opt_proto == 6)
		{
			/* Add query time for TCP */
			snprintf(line, DEFAULT_LINE_LENGTH, "\"qt\" : %.3f,", qry->querytime);
			buf_add(&qry->result,line, strlen(line));
		}

		JD_NC (size,  wire_size);

		if(qry->opt_abuf) {
			snprintf(line, DEFAULT_LINE_LENGTH, ", \"abuf\" : \"");
			buf_add(&qry->result,line, strlen(line));
			buf_add_b64(&qry->result, result, wire_size, 0);
			AS("\"");
		}

		if (qry->client_cookie_mismatch)
		{
			snprintf(line, DEFAULT_LINE_LENGTH, ", \"client-cookie-mismatch\" : true");
			buf_add(&qry->result,line, strlen(line));
		}

		if (wire_size < sizeof(struct DNS_HEADER))
			goto truncated;

		dnsR = (struct DNS_HEADER*) result;

		buf_add(&qry->result, ",", 1);
		JU (ID, ntohs(dnsR->id));

		/*
		fprintf (fh, " , \"RCODE\" : %d",  dnsR->rcode);
		fprintf (fh, " , \"AA\" : %d",  dnsR->aa);
		fprintf (fh, " , \"TC\" : %d",  dnsR->tc);
		*/
		JU (ANCOUNT, ntohs(dnsR->ans_count ));
		JU (QDCOUNT, ntohs(dnsR->q_count));
		JU (NSCOUNT, ntohs(dnsR->ns_count));
		JU_NC (ARCOUNT, ntohs(dnsR->add_count));

		/* Start just after header */
		offset= sizeof(struct DNS_HEADER);

		len= dns_namelen(result, offset, wire_size);
		if (len == -1)
			goto truncated;

		offset += len + sizeof(struct QUESTION);

		if (offset > wire_size)
			goto truncated;

		stop=0;  
		iMax = 0;
		
		if (dnsR->ans_count > 0)
		{
			iMax = MIN(2, ntohs(dnsR->ans_count));

			memset(answers, '\0', sizeof(answers));

			for(i=0;i<iMax;i++)
			{
				answers[i].name=ReadName(result,wire_size,
					offset,&stop);
				if (stop == -1)
					goto truncated;
				offset += stop;

				if (offset + sizeof(struct R_DATA) > 
					wire_size)
				{
					/* Report error? */
					goto truncated;
				}

				answers[i].resource =
					(struct R_DATA*)(result+offset);
				offset += sizeof(struct R_DATA);

				answers[i].rdata  = NULL;

				if(ntohs(answers[i].resource->type)==T_TXT) //txt
				{
					data_len = ntohs(answers[i].resource->data_len);

					if (offset+data_len > wire_size)
						goto truncated;

					if(flagAnswer == 0) {
						AS(",\"answers\" : [ {");
						flagAnswer++;
					}
					else if (flagAnswer >  0) {
							AS(", {");
					}
					flagAnswer++;
					JS (TYPE, "TXT");
					JS (NAME, answers[i].name);
					print_txt_json(result+offset,
						data_len, qry);
					offset += data_len;
					AS("}");

				}
				else if (ntohs(answers[i].resource->type)== T_SOA)
				{
					name1= name2= NULL;
					name1 = ReadName(
						result,wire_size,
						offset,&stop);
					if (stop == -1)
						goto truncated;
					offset += stop;
					name2 = ReadName(
						result,wire_size,
						offset,&stop);
					if (stop == -1)
					{
						free(name1); name1= NULL;
						goto truncated;
					}
					offset += stop;
					if (offset+5*4 > wire_size)
					{
						free(name1); name1= NULL;
						free(name2); name2= NULL;
						goto truncated;
					}

					if(flagAnswer == 0) {
						AS(",\"answers\" : [ { ");
					}
					else if (flagAnswer > 0) {
						AS(",{ ");
					}
					flagAnswer++;

					JS(TYPE, "SOA");
					JSDOT(NAME, answers[i].name);
					JU(TTL, ntohl(answers[i].resource->ttl));
					JSDOT( MNAME, name1);
					free(name1); name1= NULL;
					JSDOT( RNAME, name2);
					free(name2); name2= NULL;

					serial = get32b(result+offset);
					JU_NC(SERIAL, serial);
					offset += 4;

					offset += 4*4; // skip REFRESH, RETRY, EXIPIRE, and MINIMUM
						AS(" } ");
				}
				else  
				{
					data_len = ntohs(answers[i].
						resource->data_len);

					if (offset+data_len > wire_size)
						goto truncated;

					offset += data_len;
				}
	
				// free mem 
				if(answers[i].rdata != NULL) 
					free (answers[i].rdata); 
			}
			if(flagAnswer > 0) 
				AS(" ]");
		}

		for(i=0;i<iMax;i++)
		{
			free(answers[i].name);
		}

truncated:
		AS (" }"); //result {
	} 
	if(qry->err.size) 
	{
		AS(", \"error\" : {");
		buf_add(&qry->result,qry->err.buf, qry->err.size);
		AS("}"); 
	}

	/* end of result only JSON closing brackets from here on */

	if(qry->opt_rset) {
			AS("}");  /* resultset : [{ } */
	}
	else {
		write_out = TRUE;
	}

	if(qry->opt_resolv_conf){
		qry->resolv_i++;

		if(qry->resolv_i >= qry->resolv_max) {
			write_out = TRUE;
			if(qry->opt_rset) {
				AS ("]"); /* reseultset : [{}] */
			}
		}
	}

	if(write_out && qry->result.size){
		if (qry->out_filename)
		{
			fh= fopen(qry->out_filename, "a");
			if (!fh) {
				crondlog(LVL8 "evtdig: unable to append to '%s'",
						qry->out_filename);
			}
		}
		else
			fh = stdout;
		if (fh) {
			AS (" }\n");   /* RESULT { } */
			fwrite(qry->result.buf, qry->result.size, 1 , fh);
		}
		buf_cleanup(&qry->result);

		if (qry->out_filename)
			fclose(fh);
	}
	qry->retry = 0;
	free_qry_inst(qry);
}

unsigned char* ReadName(unsigned char *base, size_t size, size_t offset,
	int* count)
{
	unsigned char *name;
	unsigned int p=0,jumped=0, jump_count=0, len;
	size_t noffset;

	*count = 0;
	name = (unsigned char*)malloc(256);

	name[0]= '\0';

	//read the names in 3www6google3com format
	while(offset < size && (len= base[offset], len !=0))
	{
		if (len & 0xc0)
		{
			if ((len & 0xc0) != 0xc0)
			{
				/* Bad format */
				snprintf((char *)name, sizeof(name),
					"format-error at %lu: value 0x%x",
					(unsigned long)offset, len);
				*count= -1;
				free(name); name= NULL;
				return name;
			}

			noffset= ((len & ~0xc0) << 8) | base[offset+1];
			if (noffset >= size)
			{
				snprintf((char *)name, sizeof(name),
					"offset-error at %lu: offset %lu",
					(unsigned long)offset, (unsigned long)noffset);
				*count= -1;
				free(name); name= NULL;
				return name;
			}

			if (jump_count > 256)
			{
				/* Too many */
				snprintf((char *)name, sizeof(name),
					"too many redirects at %lu",
						(unsigned long)offset);
				*count= -1;
				free(name); name= NULL;
				return name;
			}

			offset= noffset;
			if(jumped==0)
			{
				/* if we havent jumped to another location
				 * then we can count up
				 */
				*count += 2;
			}
			jumped= 1;
			jump_count++;
			continue;
		}
		if (offset+len+1 > size)
		{
			snprintf((char *)name, sizeof(name),
				"buf-bounds-error at %lu: len %d",
					(unsigned long)offset, len);
			*count= -1;
			free(name); name= NULL;
			return name;
		}

		if (p+len+1 > 255)
		{
			snprintf((char *)name, sizeof(name),
					"name-length-error at %lu: len %d",
					(unsigned long)offset, p+len+1);
			*count= -1;
			free(name); name= NULL;
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

int dns_namelen(unsigned char *base, size_t offset, size_t size)
{
	size_t start_offset;
	unsigned int len;

	start_offset= offset;

	//figure out the length of a name in 3www6google3com format
	while(offset < size)
	{
		len= base[offset];
		if (len & 0xc0)
		{
			if ((len & 0xc0) != 0xc0)
			{
				/* Bad format */
				return -1;
			}

			offset++;
			break;
		}
		if (offset+len+1 > size)
		{
			return -1;
		}

		offset += len+1;

		if (len == 0)
			break;
	}

	return offset-start_offset;
}

/* get 4 bytes from memory
 * eg.  used to extract serial number from soa packet
 */
	u_int32_t
get32b (unsigned char *p)
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
