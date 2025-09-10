/*
 * Copyright (c) 2013-2014 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * traceroute.c
 */

#include "libbb.h"
#include <assert.h>
#include <event2/dns.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

/* Platform-specific includes */
#ifdef __FreeBSD__
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_var.h>
#include <netinet/tcp_var.h>
#else
/* Linux and other systems */
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include "eperd.h"
#include "atlas_path.h"

#ifdef __APPLE__
#ifndef IPV6_PKTINFO
#define IPV6_PKTINFO 46
#endif
#ifndef IPV6_HOPLIMIT
#define IPV6_HOPLIMIT 47
#endif
#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO 36
#endif
#ifndef IPV6_RECVHOPLIMIT
#define IPV6_RECVHOPLIMIT 37
#endif
#endif

/* Platform-specific struct member handling */
#ifdef __FreeBSD__
/* FreeBSD uses different struct member names */
#define TCP_SOURCE tcphdr->th_sport
#define TCP_DEST tcphdr->th_dport
#define TCP_SEQ tcphdr->th_seq
#define TCP_ACK tcphdr->th_ack
#define TCP_OFF tcphdr->th_off
#define TCP_FLAGS tcphdr->th_flags
#define TCP_WINDOW tcphdr->th_win
#define TCP_CHECKSUM tcphdr->th_sum
#define TCP_URGENT tcphdr->th_urp

#define UDP_SOURCE udphdr->uh_sport
#define UDP_DEST udphdr->uh_dport
#define UDP_LEN udphdr->uh_ulen
#define UDP_CHECKSUM udphdr->uh_sum
#else
/* Linux and other systems */
#define TCP_SOURCE tcphdr->source
#define TCP_DEST tcphdr->dest
#define TCP_SEQ tcphdr->seq
#define TCP_ACK tcphdr->ack_seq
#define TCP_OFF tcphdr->doff
#define TCP_FLAGS tcphdr->flags
#define TCP_WINDOW tcphdr->window
#define TCP_CHECKSUM tcphdr->check
#define TCP_URGENT tcphdr->urg_ptr

#define UDP_SOURCE udphdr->source
#define UDP_DEST udphdr->dest
#define UDP_LEN udphdr->len
#define UDP_CHECKSUM udphdr->check
#endif


/* Define missing TCP header struct members as aliases */
#ifndef seq
#define seq th_seq
#endif
#ifndef ack_seq
#define ack_seq th_ack
#endif
#ifndef doff
#define doff th_off
#endif
#ifndef syn
#define syn th_flags
#endif
#ifndef fin
#define fin th_flags
#endif
#ifndef rst
#define rst th_flags
#endif
#ifndef psh
#define psh th_flags
#endif
#ifndef ack
#define ack th_flags
#endif
#ifndef urg
#define urg th_flags
#endif

/* Helper macros for TCP flags - platform independent */
#define TCP_SYN_FLAG 0x02
#define TCP_FIN_FLAG 0x01
#define TCP_RST_FLAG 0x04
#define TCP_PSH_FLAG 0x08
#define TCP_ACK_FLAG 0x10
#define TCP_URG_FLAG 0x20

/* Platform-independent byte order detection */
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__)
#define IS_LITTLE_ENDIAN (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#elif defined(__BYTE_ORDER) && defined(__LITTLE_ENDIAN)
#define IS_LITTLE_ENDIAN (__BYTE_ORDER == __LITTLE_ENDIAN)
#elif defined(_BYTE_ORDER) && defined(_LITTLE_ENDIAN)
#define IS_LITTLE_ENDIAN (_BYTE_ORDER == _LITTLE_ENDIAN)
#elif defined(BYTE_ORDER) && defined(LITTLE_ENDIAN)
#define IS_LITTLE_ENDIAN (BYTE_ORDER == LITTLE_ENDIAN)
#elif defined(__i386__) || defined(__x86_64__) || defined(__arm__) || defined(__aarch64__)
#define IS_LITTLE_ENDIAN 1
#elif defined(__powerpc__) || defined(__sparc__) || defined(__mips__)
#define IS_LITTLE_ENDIAN 0
#else
/* Default to little endian for most modern systems */
#define IS_LITTLE_ENDIAN 1
#endif

/* Platform-specific IPv6 constants and socket options */
#ifdef __FreeBSD__
/* FreeBSD-specific constants */
#ifndef SOL_IPV6
#define SOL_IPV6 IPPROTO_IPV6
#endif

#ifndef IPV6_UNICAST_HOPS
#define IPV6_UNICAST_HOPS 16
#endif

#ifndef IPV6_PMTUDISC_DO
#define IPV6_PMTUDISC_DO 2
#endif

#ifndef IPV6_PMTUDISC_DONT
#define IPV6_PMTUDISC_DONT 0
#endif

#ifndef IPV6_MTU_DISCOVER
#define IPV6_MTU_DISCOVER 23
#endif

#ifndef IP_PMTUDISC_DO
#define IP_PMTUDISC_DO 2
#endif

#ifndef IP_PMTUDISC_DONT
#define IP_PMTUDISC_DONT 0
#endif

#ifndef IP_MTU_DISCOVER
#define IP_MTU_DISCOVER 10
#endif

#ifndef ICMP_TIME_EXCEEDED
#define ICMP_TIME_EXCEEDED 11
#endif

#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH 3
#endif
#else
/* Linux and other systems */
#ifndef SOL_IPV6
#define SOL_IPV6 IPPROTO_IPV6
#endif

#ifndef IPV6_UNICAST_HOPS
#define IPV6_UNICAST_HOPS 16
#endif

#ifndef IPV6_PMTUDISC_DO
#define IPV6_PMTUDISC_DO 2
#endif

#ifndef IPV6_PMTUDISC_DONT
#define IPV6_PMTUDISC_DONT 0
#endif

#ifndef IPV6_MTU_DISCOVER
#define IPV6_MTU_DISCOVER 23
#endif

#ifndef IP_PMTUDISC_DO
#define IP_PMTUDISC_DO 2
#endif

#ifndef IP_PMTUDISC_DONT
#define IP_PMTUDISC_DONT 0
#endif

#ifndef IP_MTU_DISCOVER
#define IP_MTU_DISCOVER 10
#endif

#ifndef ICMP_TIME_EXCEEDED
#define ICMP_TIME_EXCEEDED 11
#endif

#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH 3
#endif
#endif

#define SAFE_PREFIX_REL ATLAS_DATA_NEW_REL

/* Platform-specific function wrappers */
#ifdef __FreeBSD__
/* FreeBSD-specific socket option handling */
static inline int set_ipv6_unicast_hops(int sock, int hops) {
    return setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, sizeof(hops));
}

static inline int set_ipv6_mtu_discover(int sock, int value) {
    return setsockopt(sock, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &value, sizeof(value));
}

static inline int set_ip_ttl(int sock, int ttl) {
    return setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
}

static inline int set_ip_mtu_discover(int sock, int value) {
    return setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &value, sizeof(value));
}
#else
/* Linux and other systems */
static inline int set_ipv6_unicast_hops(int sock, int hops) {
    return setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, sizeof(hops));
}

static inline int set_ipv6_mtu_discover(int sock, int value) {
    return setsockopt(sock, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &value, sizeof(value));
}

static inline int set_ip_ttl(int sock, int ttl) {
    return setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
}

static inline int set_ip_mtu_discover(int sock, int value) {
    return setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &value, sizeof(value));
}
#endif

/* Platform-specific compatibility macros */
#if defined(__FreeBSD__) || defined(__APPLE__)
/* FreeBSD/macOS use different field names for TCP header */
#define tcp_source th_sport
#define tcp_dest th_dport
#define tcp_check th_sum
/* UDP header fields are the same on FreeBSD/macOS and Linux */
#else
/* Linux and other systems */
#define tcp_source source
#define tcp_dest dest
#define tcp_check check
#define uh_dport dest
#define uh_ulen len
#define uh_sum check
#endif

#define TRACEROUTE_OPT_STRING ("!46IUFrTa:b:c:f:g:i:m:p:t:w:z:A:B:O:S:H:D:R:W:")

#define OPT_4	(1 << 0)
#define OPT_6	(1 << 1)
#define OPT_I	(1 << 2)
#define OPT_U	(1 << 3)
#define OPT_F	(1 << 4)
#define OPT_r	(1 << 5)
#define OPT_T	(1 << 6)

#define IPHDR              20
#define ICMP6_HDR 	(sizeof(struct icmp6_hdr))
#define TCP_HDR		(sizeof(*tcphdr))

#define BASE_PORT	(0x8000 + 666)
#define SRC_BASE_PORT	(20480)
#define MAX_DATA_SIZE   (4096)

#define DBQ(str) "\"" #str "\""

#define ICMPEXT_VERSION_SHIFT 4

#define ICMPEXT_MPLS	1
#define ICMPEXT_MPLS_IN	1

#define MPLS_LABEL_SHIFT 12
#define MPLS_EXT_SHIFT 9
#define MPLS_EXT_MASK 0x7
#define MPLS_S_BIT 0x100
#define MPLS_TTL_MASK 0xff

#define IP6_TOS(ip6_hdr) ((ntohl((ip6_hdr)->ip6_flow) >> 20) & 0xff)

#define RESP_PACKET		1
#define RESP_PEERNAME		2
#define RESP_SOCKNAME		3
#define RESP_PROTO		4
#define RESP_RCVDTTL		5
#define RESP_RCVDTCLASS		6
#define RESP_SENDTO		7
#define RESP_ADDRINFO		8
#define RESP_ADDRINFO_SA	9

struct trtbase
{
	struct event_base *event_base;

	int my_pid;

	struct trtstate **table;
	int tabsiz;

	/* For standalone traceroute. Called when a traceroute instance is
	 * done. Just one pointer for all instances. It is up to the caller
	 * to keep it consistent.
	 */
	void (*done)(void *state, int error);

	/* Leave some space for headers. The various traceroute variations
	 * have to check that it fits.
	 */
	u_char packet[MAX_DATA_SIZE+128];
};

struct trtstate
{
	/* Parameters */
	char *atlas;
	char *bundle_id;
	char *hostname;
	char *destportstr;
	char *out_filename;
	char *interface;
	char do_icmp;
	char do_tcp;
	char do_udp;
	char do_v6;
	char dont_fragment;
	char delay_name_res;
	char trtcount;
	unsigned short maxpacksize;
	unsigned short hbhoptsize;
	unsigned short destoptsize;
	unsigned char firsthop;
	unsigned char maxhops;
	unsigned char gaplimit;
	unsigned char parismod;
	unsigned char parisbase;
	unsigned duptimeout;
	unsigned timeout;
	int tos;

	char *response_in;	/* Fuzzing */
	char *response_out;

	/* Base and index in table */
	struct trtbase *base;
	int index;

	struct sockaddr_in6 sin6;
	socklen_t socklen;
	struct sockaddr_in6 loc_sin6;
	socklen_t loc_socklen;

	int sent;
	uint8_t hop;
	uint16_t paris;
	uint16_t seq;
	unsigned short curpacksize;
	
	int socket_icmp;		/* Socket for sending and receiving
					 * ICMPs */
	struct event event_icmp;	/* Event for this socket */
	int socket_tcp;			/* Socket for sending and receiving
					 * raw TCP */
	struct event event_tcp;		/* Event for this socket */

	uint8_t last_response_hop;	/* Hop at which we last got something
					 * back.
					 */
	unsigned done:1;		/* We got something from the target
					 * host or a destination unreachable.
					 */
	unsigned not_done:1;		/* Not got something else */
	unsigned lastditch:1;		/* In last-ditch hop */
	unsigned busy:1;		/* Busy, do not start another one */
	unsigned gotresp:1;		/* Got a response to the last packet
					 * we sent. For dup detection.
					 */
	unsigned dnsip:1;		/* Busy with dns name resolution */
	unsigned no_src:1;		/* Did not bind yet */
	struct evutil_addrinfo *dns_res;
	struct evutil_addrinfo *dns_curr;

	time_t starttime;
	struct timespec xmit_time;

	struct timespec start_time;	/* At the moment only for
					 * DNS resolution
					 */
	double ttr;			/* Time to resolve a name, in ms */

	struct event timer;

	unsigned long min;
	unsigned long max;
	unsigned long sum;
	int sentpkts;
	int rcvdpkts;
	int duppkts;

	char *result;
	size_t reslen;
	size_t resmax;
	char open_result;

	FILE *resp_file_out;	/* Fuzzing */
};

static struct trtbase *trt_base;

struct v4_ph
{
	struct in_addr src;
	struct in_addr dst;
	uint8_t zero;
	uint8_t proto;
	uint16_t len;
};

struct v6_ph
{
	struct in6_addr src;
	struct in6_addr dst;
	uint32_t len;
	uint8_t zero[3];
	uint8_t nxt;
};

struct v6info
{
	uint16_t fuzz;
	uint32_t pid;
	uint32_t id;
	uint32_t seq;
	struct timespec tv;
};

static int create_socket(struct trtstate *state, int do_tcp);
static void ready_callback4(int __attribute((unused)) unused,
	const short __attribute((unused)) event, void *s);
static void ready_tcp4(int __attribute((unused)) unused,
	const short __attribute((unused)) event, void *s);
static void ready_callback6(int __attribute((unused)) unused,
	const short __attribute((unused)) event, void *s);
static void noreply_callback(int __attribute((unused)) unused,
	const short __attribute((unused)) event, void *s);

static int in_cksum(unsigned short *buf, int sz)
{
	int nleft = sz;
	int sum = 0;
	unsigned short *w = buf;
	unsigned short ans = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(unsigned char *) (&ans) = *(unsigned char *) w;
		sum += ans;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	ans = ~sum;
	return ans;
}

static int in_cksum_udp(struct v4_ph *v4_ph, struct udphdr *udp, 
	unsigned short *buf, int sz)
{
	int nleft = sz;
	int sum = 0;
	unsigned short *w = buf;
	unsigned short ans = 0;

	nleft= sizeof(*v4_ph);
	w= (unsigned short *)v4_ph;
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (udp)
	{
		nleft= sizeof(*udp);
		w= (unsigned short *)udp;
		while (nleft > 1) {
			sum += *w++;
			nleft -= 2;
		}
	}

	nleft= sz;
	w= buf;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(unsigned char *) (&ans) = *(unsigned char *) w;
		sum += ans;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	ans = ~sum;
	return ans;
}

static int in_cksum_icmp6(struct v6_ph *v6_ph, unsigned short *buf, int sz)
{
	int nleft = sz;
	int sum = 0;
	unsigned short *w = buf;
	unsigned short ans = 0;

	nleft= sizeof(*v6_ph);
	w= (unsigned short *)v6_ph;
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	nleft= sz;
	w= buf;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(unsigned char *) (&ans) = *(unsigned char *) w;
		sum += ans;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	ans = ~sum;
	return ans;
}

static void add_str(struct trtstate *state, const char *str)
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

static void report(struct trtstate *state)
{
	int r;
	FILE *fh;
	const char *proto;
	struct addrinfo *ai;
	char namebuf[NI_MAXHOST];
	struct addrinfo hints;

	event_del(&state->timer);

	if (state->out_filename)
	{
		fh= fopen(state->out_filename, "a");
		if (!fh)
			crondlog(DIE9 "traceroute: unable to append to '%s'",
				state->out_filename);
	}
	else
		fh= stdout;

	fprintf(fh, "RESULT { ");
	if (state->atlas)
	{
		fprintf(fh, DBQ(id) ":" DBQ(%s)
			", %s"
			", " DBQ(lts) ":%d"
			", " DBQ(time) ":%llu"
			", " DBQ(endtime) ":%llu, ",
			state->atlas, atlas_get_version_json_str(),
			get_timesync(),
			(unsigned long long)state->starttime,
			(unsigned long long)atlas_time());
		if (state->bundle_id)
			fprintf(fh, DBQ(bundle) ":%s, ", state->bundle_id);
	}

	fprintf(fh, DBQ(dst_name) ":" DBQ(%s),
		state->hostname);

	/* Check if hostname is numeric or had to be resolved */
	memset(&hints, '\0', sizeof(hints));
	hints.ai_flags= AI_NUMERICHOST;
	r= getaddrinfo(state->hostname, NULL, &hints, &ai);
	if (r == 0)
	{
		/* Getaddrinfo succeded so hostname is an address literal */
		freeaddrinfo(ai);
	}
	else
	{
		/* Assume that name resolution was required */
		fprintf(fh, ", " DBQ(ttr) ":%f", state->ttr);
	}

	if (!state->dnsip)
	{
		getnameinfo((struct sockaddr *)&state->sin6, state->socklen,
			namebuf, sizeof(namebuf), NULL, 0, NI_NUMERICHOST);

		fprintf(fh, ", " DBQ(dst_addr) ":" DBQ(%s), namebuf);
	}
	if (!state->dnsip && !state->no_src)
	{
		namebuf[0]= '\0';
		getnameinfo((struct sockaddr *)&state->loc_sin6,
			state->loc_socklen,
			namebuf, sizeof(namebuf), NULL, 0, NI_NUMERICHOST);

		fprintf(fh, ", " DBQ(src_addr) ":" DBQ(%s), namebuf);
	}

	if (state->do_icmp)
		proto= "ICMP";
	else if (state->do_tcp)
		proto= "TCP";
	else
		proto= "UDP";
	fprintf(fh, ", " DBQ(proto) ":" DBQ(%s) ", " DBQ(af) ": %d",
		proto,
		state->dnsip ? (state->do_v6 ? 6 : 4) :
		(state->sin6.sin6_family == AF_INET6 ? 6 : 4));

	fprintf(fh, ", " DBQ(size) ":%d", state->maxpacksize);
	if (state->parismod)
	{
		fprintf(fh, ", " DBQ(paris_id) ":%d", state->paris);
	}
	fprintf(fh, ", " DBQ(result) ": [ %s ] }\n", state->result);

	free(state->result);
	state->result= NULL;

	if (state->out_filename)
		fclose(fh);

	/* Kill the event and close socket */
	if (state->socket_icmp != -1)
	{
		event_del(&state->event_icmp);
		close(state->socket_icmp);
		state->socket_icmp= -1;
	}
	if (state->socket_tcp != -1)
	{
		event_del(&state->event_tcp);
		close(state->socket_tcp);
		state->socket_tcp= -1;
	}

	state->busy= 0;

	if (state->base->done)
		state->base->done(state, 0);
}

static int set_tos(struct trtstate *state, int sock, int af, int inner)
{
	int r;
	char line[80];

	if (!state->tos)
		return 0;	/* Nothing to do */

	if (state->response_in)
		return 0;	/* Nothing to do */

	if (af == AF_INET6)
	{
		r= setsockopt(sock, IPPROTO_IPV6, IPV6_TCLASS, &state->tos,
			sizeof(state->tos));
	}
	else
	{
		r= setsockopt(sock, IPPROTO_IP, IP_TOS, &state->tos,
			sizeof(state->tos));
	}

	if (r == -1)
	{
		crondlog(LVL7 "setting %s failed with '%s'",
			af == AF_INET6 ? "traffic class" : "ToS",
			strerror(errno));

		snprintf(line, sizeof(line),
			"%s" DBQ(error) ":"
		DBQ(setting %s failed)
			"%s", inner ? (state->sent ? " }, { " : "{ ") : ", ",
			af == AF_INET6 ? "traffic class" : "ToS",
			inner ? " } ] }" : " }");
		add_str(state, line);
		report(state);
		return -1;
	}

	return 0;
}

static void send_pkt(struct trtstate *state)
{
	int r, hop, len, on, sock, serrno;
	uint16_t sum, val;
	unsigned usum;
	struct trtbase *base;
	struct icmp *icmp_hdr;
	struct icmp6_hdr *icmp6_hdr;
	struct v6info *v6info;
	struct tcphdr *tcphdr;
	struct v4_ph v4_ph;
	struct v6_ph v6_ph;
	struct udphdr udp;
	struct timeval interval;
	struct sockaddr_in6 sin6copy;
	char line[80];
	char id[]= "http://atlas.ripe.net Atlas says Hi!";
	struct r_errno
	{
		int r;
		int error;
	} r_errno;

	state->gotresp= 0;

	base= state->base;

	if (state->sent >= state->trtcount)
	{
		add_str(state, " } ] }");
		if (state->hop >= state->maxhops ||
			(state->done && !state->not_done))
		{
			/* We are done */
			if (state->resp_file_out)
			{
				r= 0;
				write_response(state->resp_file_out,
					RESP_SENDTO, sizeof(r), &r);
			}
			report(state);
			return;
		}

		state->hop++;
		state->sent= 0;
		state->done= 0;
		state->not_done= 0;

		if (state->hop - state->last_response_hop > 
			state->gaplimit)
		{
#if 0
			printf("gaplimit reached: %d > %d + %d\n",
				state->hop, state->last_response_hop,
				state->gaplimit);
#endif
			if (state->lastditch)
			{
				/* Also done with last-ditch probe. */
				if (state->resp_file_out)
				{
					r= 0;
					write_response(state->resp_file_out,
						RESP_SENDTO, sizeof(r), &r);
				}
				report(state);
				return;
			}
			state->lastditch= 1;
			state->hop= 255;
		}

		snprintf(line, sizeof(line),
			", { " DBQ(hop) ":%d, " DBQ(result) ": [ ", state->hop);
		add_str(state, line);
		state->open_result= 0;
	}
	state->seq++;

	gettime_mono(&state->xmit_time);

	if (state->sin6.sin6_family == AF_INET6)
	{
		hop= state->hop;

		if (state->do_tcp)
		{
			if (state->response_in)
				sock= open("/dev/null", O_RDWR);
			else
			{
				sock= socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
			}
			if (sock == -1)
			{
				crondlog(DIE9 "socket failed");
			}

			on= 1;
			setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on,
				sizeof(on));

#if 1
			if (state->hbhoptsize != 0)
			{
				do_ipv6_option(sock, 0 /* hbh */,
					 state->hbhoptsize);
			}
			if (state->destoptsize != 0)
			{
				do_ipv6_option(sock, 1 /* dest */,
					 state->destoptsize);
			}
#endif

			if (set_tos(state, sock, AF_INET6, 1 /*inner*/) == -1)
			{
				close(sock);
				return;
			}

			/* Bind to source addr/port */
			if (state->response_in)
				r= 0;	/* No need to bind */
			else
			{
				r= bind(sock,
					(struct sockaddr *)&state->loc_sin6,
					state->loc_socklen);
			}
			if (r == -1)
			{
				serrno= errno;

				snprintf(line, sizeof(line),
		"%s{ " DBQ(error) ":" DBQ(bind failed: %s) " } ] }",
					state->sent ? " }, " : "",
					strerror(serrno));
				add_str(state, line);
				report(state);
				close(sock);
				return;
			}

			tcphdr= (struct tcphdr *)base->packet;
			memset(tcphdr, '\0', sizeof(*tcphdr));

			len= sizeof(*tcphdr);

			tcphdr->th_seq= htonl((state->index) << 16 | state->seq);
			tcphdr->th_off= len / 4;
			tcphdr->th_flags= TCP_SYN_FLAG;

			if (len+state->curpacksize > sizeof(base->packet))
			{
				crondlog(
			DIE9 "base->packet too small, need at least %d",
					len+state->curpacksize);
			}
			if (state->curpacksize > 0)
			{
				memset(&base->packet[len], '\0',
					state->curpacksize);
				strcpy((char *)&base->packet[len], id);
				len += state->curpacksize;
			}

			{
				int  offset = 2;
				setsockopt(sock, IPPROTO_IPV6, IPV6_CHECKSUM,
					&offset, sizeof(offset));
			}

			memset(&v6_ph, '\0', sizeof(v6_ph));
			v6_ph.src= state->loc_sin6.sin6_addr;
			v6_ph.dst= state->sin6.sin6_addr;
			v6_ph.len= htonl(len);
			v6_ph.nxt= IPPROTO_TCP;
			tcphdr->th_sport= state->loc_sin6.sin6_port;
			tcphdr->th_dport= state->sin6.sin6_port;
			tcphdr->th_sum= 0;

			sum= in_cksum_icmp6(&v6_ph, 
				(unsigned short *)base->packet, len);
			
			tcphdr->tcp_check= sum;

			/* Set hop count */
			setsockopt(sock, SOL_IPV6, IPV6_UNICAST_HOPS,
				&hop, sizeof(hop));

			/* Set/clear don't fragment */
			on= (state->dont_fragment ? IPV6_PMTUDISC_DO :
				IPV6_PMTUDISC_DONT);
			setsockopt(sock, IPPROTO_IPV6,
					IPV6_MTU_DISCOVER, &on, sizeof(on));

			sin6copy= state->sin6;
			sin6copy.sin6_port= 0;
			if (state->response_in)
			{
				size_t rlen;

				rlen= sizeof(r_errno);
				read_response(state->socket_icmp, RESP_SENDTO,
					&rlen, &r_errno);
				if (rlen != sizeof(r_errno))
				{
					crondlog(DIE9
			"send_pkt: error reading r_errno from '%s'",
						state->response_in);
				}
				r= r_errno.r;
				serrno= r_errno.error;
			}
			else
			{
				r= sendto(sock, base->packet, len, 0,
					(struct sockaddr *)&sin6copy,
					state->socklen);
				serrno= errno;
				if (state->resp_file_out)
				{
					r_errno.r= r;
					r_errno.error= serrno;
					write_response(state->resp_file_out,
						RESP_SENDTO,
						sizeof(r_errno), &r_errno);
				}
			}

#if 0
 { static int doit=1; if (doit && r != -1)
 	{ serrno= ENOSYS; r= -1; } doit= !doit; }
#endif
			close(sock);

			if (r == -1)
			{
				if (serrno != EACCES &&
					serrno != ECONNREFUSED &&
					serrno != EMSGSIZE)
				{
					snprintf(line, sizeof(line),
			"%s{ " DBQ(error) ":" DBQ(sendto failed: %s) " } ] }",
						state->sent ? " }, " : "",
						strerror(serrno));
					add_str(state, line);
					report(state);
					return;
				}
			}
		}
		else if (state->do_icmp)
		{
			/* Set hop count */
			setsockopt(state->socket_icmp, SOL_IPV6,
				IPV6_UNICAST_HOPS, &hop, sizeof(hop));

			/* Set/clear don't fragment */
			on= (state->dont_fragment ? IPV6_PMTUDISC_DO :
				IPV6_PMTUDISC_DONT);
			setsockopt(state->socket_icmp, IPPROTO_IPV6,
					IPV6_MTU_DISCOVER, &on, sizeof(on));

			do_ipv6_option(state->socket_icmp, 0 /* hbh */,
					 state->hbhoptsize);
			do_ipv6_option(state->socket_icmp, 1 /* dest */,
					 state->destoptsize);

			icmp6_hdr= (struct icmp6_hdr *)base->packet;
			icmp6_hdr->icmp6_type= ICMP6_ECHO_REQUEST;
			icmp6_hdr->icmp6_code= 0;
			icmp6_hdr->icmp6_cksum= 0;
			icmp6_hdr->icmp6_id= htons(base->my_pid);
			icmp6_hdr->icmp6_seq= htons(state->seq);

			v6info= (struct v6info *)&icmp6_hdr[1];
			v6info->fuzz= 0;
			v6info->pid= htonl(base->my_pid);
			v6info->id= htonl(state->index);
			v6info->seq= htonl(state->seq);
			v6info->tv= state->xmit_time;

			len= sizeof(*v6info);

			if (state->curpacksize < len)
				state->curpacksize= len;
			if (ICMP6_HDR+state->curpacksize >
				sizeof(base->packet))
			{
				crondlog(
			DIE9 "base->packet too small, need at least %d",
					ICMP6_HDR+state->curpacksize);
			}

			if (state->curpacksize > len)
			{
				memset(&base->packet[ICMP6_HDR+len], '\0',
					state->curpacksize-len);
				strcpy((char *)&base->packet[ICMP6_HDR+len],
					id);
				len= state->curpacksize;
			}

			len += ICMP6_HDR;

			if (state->parismod)
			{
				memset(&v6_ph, '\0', sizeof(v6_ph));
				v6_ph.src= state->loc_sin6.sin6_addr;
				v6_ph.dst= state->sin6.sin6_addr;
				v6_ph.len= htonl(len);
				v6_ph.nxt= IPPROTO_ICMPV6;

				sum= in_cksum_icmp6(&v6_ph,
					(unsigned short *)base->packet, len);

				/* Avoid 0 */
				val= state->paris + 1;

				sum= ntohs(sum);
				usum= sum + (0xffff - val);
				sum= usum + (usum >> 16);

				v6info->fuzz= htons(sum);

				sum= in_cksum_icmp6(&v6_ph, 
					(unsigned short *)base->packet, len);

#if 0
				printf(
			"send_pkt: seq %d, paris %d, cksum= htons(0x%x)\n",
					state->seq, state->paris,
					ntohs(sum));
#endif
			}

			memset(&sin6copy, '\0', sizeof(sin6copy));
			sin6copy.sin6_family= AF_INET6;
			sin6copy.sin6_addr= state->sin6.sin6_addr;

			if (state->response_in)
			{
				size_t rlen;

				rlen= sizeof(r_errno);
				read_response(state->socket_icmp, RESP_SENDTO,
					&rlen, &r_errno);
				if (rlen != sizeof(r_errno))
				{
					crondlog(DIE9
			"send_pkt: error reading r_errno from '%s'",
						state->response_in);
				}
				r= r_errno.r;
				serrno= r_errno.error;
			}
			else
			{
				r= sendto(state->socket_icmp, base->packet,
					len, 0, (struct sockaddr *)&sin6copy,
					sizeof(sin6copy));
				serrno= errno;
				if (state->resp_file_out)
				{
					r_errno.r= r;
					r_errno.error= serrno;
					write_response(state->resp_file_out,
						RESP_SENDTO,
						sizeof(r_errno), &r_errno);
				}
			}

#if 0
 { static int doit=1; if (doit && r != -1)
 	{ serrno= ENOSYS; r= -1; } doit= !doit; }
#endif

			if (r == -1)
			{
				if (serrno != EMSGSIZE)
				{
					snprintf(line, sizeof(line),
			"%s{ " DBQ(error) ":" DBQ(sendto failed: %s) " } ] }",
						state->sent ? " }, " : "",
						strerror(serrno));
					add_str(state, line);
					report(state);
					return;
				}
			}
		}
		else if (state->do_udp)
		{
			if (state->response_in)
				sock= open("/dev/null", O_RDWR);
			else
			{
				sock= socket(AF_INET6, SOCK_DGRAM, 0);
			}
			if (sock == -1)
			{
				crondlog(DIE9 "socket failed");
			}

			on= 1;
			setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on,
				sizeof(on));

			if (state->hbhoptsize != 0)
			{
				do_ipv6_option(sock, 0 /* hbh */,
					 state->hbhoptsize);
			}
			if (state->destoptsize != 0)
			{
				do_ipv6_option(sock, 1 /* dest */,
					 state->destoptsize);
			}

			if (set_tos(state, sock, AF_INET6, 1 /*inner*/) == -1)
			{
				close(sock);
				return;
			}

			/* Bind to source addr/port */
			if (state->response_in)
				r= 0;	/* No need to bind */
			else
			{
				r= bind(sock,
					(struct sockaddr *)&state->loc_sin6,
					state->loc_socklen);
			}
			if (r == -1)
			{
				serrno= errno;

				snprintf(line, sizeof(line),
		"%s{ " DBQ(error) ":" DBQ(bind failed: %s) " } ] }",
					state->sent ? " }, " : "",
					strerror(serrno));
				add_str(state, line);
				report(state);
				close(sock);
				return;
			}

			/* Set port */
			if (state->parismod)
			{
				state->sin6.sin6_port= htons(BASE_PORT +
					state->paris);
			}
			else
			{
				state->sin6.sin6_port= htons(BASE_PORT +
					state->seq);
			}

			/* Set hop count */
			setsockopt(sock, SOL_IPV6, IPV6_UNICAST_HOPS,
				&hop, sizeof(hop));

			/* Set/clear don't fragment */
			on= (state->dont_fragment ? IPV6_PMTUDISC_DO :
				IPV6_PMTUDISC_DONT);
			setsockopt(sock, IPPROTO_IPV6,
					IPV6_MTU_DISCOVER, &on, sizeof(on));

			v6info= (struct v6info *)base->packet;
			v6info->fuzz= 0;
			v6info->pid= htonl(base->my_pid);
			v6info->id= htonl(state->index);
			v6info->seq= htonl(state->seq);
			v6info->tv= state->xmit_time;

#if 0
			printf(
"send_pkt: IPv6 UDP: pid = htonl(%d), id = htonl(%d), seq = htonl(%d)\n",
				ntohl(v6info->pid),
				ntohl(v6info->id),
				ntohl(v6info->seq));
#endif

			len= sizeof(*v6info);

			if (state->curpacksize < len)
				state->curpacksize= len;
			if (state->curpacksize > len)
			{
				memset(&base->packet[len], '\0',
					state->curpacksize-len);
				strcpy((char *)&base->packet[len], id);
				len= state->curpacksize;
			}

			if (state->response_in)
			{
				size_t rlen;

				rlen= sizeof(r_errno);
				read_response(state->socket_icmp, RESP_SENDTO,
					&rlen, &r_errno);
				if (rlen != sizeof(r_errno))
				{
					crondlog(DIE9
			"send_pkt: error reading r_errno from '%s'",
						state->response_in);
				}
				r= r_errno.r;
				serrno= r_errno.error;
			}
			else
			{
				r= sendto(sock, base->packet, len, 0,
					(struct sockaddr *)&state->sin6,
					state->socklen);
				serrno= errno;
				if (state->resp_file_out)
				{
					r_errno.r= r;
					r_errno.error= serrno;
					write_response(state->resp_file_out,
						RESP_SENDTO,
						sizeof(r_errno), &r_errno);
				}
			}

#if 0
 { static int doit=1; if (doit && r != -1)
 	{ serrno= ENOSYS; r= -1; } doit= !doit; }
#endif
			close(sock);

			if (r == -1)
			{
				if (serrno != EACCES &&
					serrno != ECONNREFUSED &&
					serrno != EMSGSIZE)
				{
					snprintf(line, sizeof(line),
			"%s{ " DBQ(error) ":" DBQ(sendto failed: %s) " } ] }",
						state->sent ? " }, " : "",
						strerror(serrno));
					add_str(state, line);
					report(state);
					return;
				}
			}
		}
	}
	else
	{
#if 0
		printf(
"send_pkt: sending IPv4 packet, do_icmp %d, parismod %d, index %d, state %p\n",
			state->do_icmp, state->parismod, state->index, state);
#endif

		if (state->do_tcp)
		{
			if (state->response_in)
				sock= open("/dev/null", O_RDWR);
			else
			{
				sock= socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
			}
			if (sock == -1)
			{
				crondlog(DIE9 "socket failed");
			}

			on= 1;
			setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on,
				sizeof(on));

			if (set_tos(state, sock, AF_INET, 1 /*inner*/) == -1)
			{
				close(sock);
				return;
			}

			/* Bind to source addr/port */
			if (state->response_in)
				r= 0;
			else
			{
				r= bind(sock,
					(struct sockaddr *)&state->loc_sin6,
					state->loc_socklen);
			}
#if 0
 { static int doit=1; if (doit && r != -1)
 { errno= ENOSYS; r= -1; } doit= !doit; }
#endif
			if (r == -1)
			{
				serrno= errno;

				snprintf(line, sizeof(line),
		"%s{ " DBQ(error) ":" DBQ(bind failed: %s) " } ] }",
					state->sent ? " }, " : "",
					strerror(serrno));
				add_str(state, line);
				report(state);
				close(sock);
				return;
			}

			hop= state->hop;

			tcphdr= (struct tcphdr *)base->packet;
			memset(tcphdr, '\0', sizeof(*tcphdr));

			len= sizeof(*tcphdr);

			tcphdr->th_seq= htonl((state->index) << 16 | state->seq);
			tcphdr->th_off= len / 4;
			tcphdr->th_flags= TCP_SYN_FLAG;

			if (len+state->curpacksize > sizeof(base->packet))
			{
				crondlog(
			DIE9 "base->packet too small, need at least %d",
					len+state->curpacksize);
			}
			if (state->curpacksize > 0)
			{
				memset(&base->packet[len], '\0',
					state->curpacksize);
				strcpy((char *)&base->packet[len], id);
				len += state->curpacksize;
			}

			v4_ph.src= ((struct sockaddr_in *)&state->loc_sin6)->
				sin_addr;
			v4_ph.dst= ((struct sockaddr_in *)&state->sin6)->
				sin_addr;
			v4_ph.zero= 0;
			v4_ph.proto= IPPROTO_TCP;
			v4_ph.len= htons(len);
			tcphdr->th_sport=
				((struct sockaddr_in *)&state->loc_sin6)->
				sin_port;
			tcphdr->th_dport= ((struct sockaddr_in *)&state->sin6)->
				sin_port;
			tcphdr->th_sum= 0;

			sum= in_cksum_udp(&v4_ph, NULL,
				(unsigned short *)base->packet, len);
			
			tcphdr->tcp_check= sum;

#if 0
			if (state->parismod)
			{
				/* Make sure that the sequence number ends
				 * up in the checksum field. We can't store
				 * 0. So we add 1.
				 */
				if (state->seq == 0)
					state->seq++;
				val= state->seq;
			}
			else
			{
				/* Use id+1 */
				val= state->index+1;
			}

			sum= ntohs(sum);
			usum= sum + (0xffff - val);
			sum= usum + (usum >> 16);

			base->packet[0]= sum >> 8;
			base->packet[1]= sum;

			sum= in_cksum_udp(&udp_ph, &udp,
				(unsigned short *)base->packet, len);
#endif

			/* Set hop count */
			setsockopt(sock, IPPROTO_IP, IP_TTL,
				&hop, sizeof(hop));

			/* Set/clear don't fragment */
			on= (state->dont_fragment ? IP_PMTUDISC_DO :
				IP_PMTUDISC_DONT);
			setsockopt(sock, IPPROTO_IP,
				IP_MTU_DISCOVER, &on, sizeof(on));

			if (state->response_in)
			{
				size_t rlen;

				rlen= sizeof(r_errno);
				read_response(state->socket_icmp, RESP_SENDTO,
					&rlen, &r_errno);
				if (rlen != sizeof(r_errno))
				{
					crondlog(DIE9
			"send_pkt: error reading r_errno from '%s'",
						state->response_in);
				}
				r= r_errno.r;
				serrno= r_errno.error;
			}
			else
			{
				r= sendto(sock, base->packet, len, 0,
					(struct sockaddr *)&state->sin6,
					state->socklen);
				serrno= errno;
				if (state->resp_file_out)
				{
					r_errno.r= r;
					r_errno.error= serrno;
					write_response(state->resp_file_out,
						RESP_SENDTO,
						sizeof(r_errno), &r_errno);
				}
			}

#if 0
 { static int doit=0; if (doit && r != -1)
 	{ serrno= ENOSYS; r= -1; } doit= !doit; }
#endif

			close(sock);
			if (r == -1)
			{
				if (serrno != EMSGSIZE)
				{
					serrno= errno;

					snprintf(line, sizeof(line),
			"%s{ " DBQ(error) ":" DBQ(sendto failed: %s) " } ] }",
						state->sent ? " }, " : "",
						strerror(serrno));
					add_str(state, line);
					report(state);
					return;
				}
			}
		}
		else if (state->do_icmp)
		{
			hop= state->hop;

			icmp_hdr= (struct icmp *)base->packet;
			icmp_hdr->icmp_type= ICMP_ECHO;
			icmp_hdr->icmp_code= 0;
			icmp_hdr->icmp_cksum= 0;
			icmp_hdr->icmp_id= htons(state->index | 
				(instance_id << TRT_ICMP4_INSTANCE_ID_SHIFT));
			icmp_hdr->icmp_seq= htons(state->seq);
			icmp_hdr->icmp_data[0]= '\0';
			icmp_hdr->icmp_data[1]= '\0';

			len= offsetof(struct icmp, icmp_data[2]);

			/* currpacksize is the amount of data after the
			 * ICMP header. len is the minimal amount of data
			 * including the ICMP header. Later len becomes
			 * the packet size including ICMP header.
			 */
			if (ICMP_MINLEN+state->curpacksize < len)
				state->curpacksize= len-ICMP_MINLEN;
			if (ICMP_MINLEN+state->curpacksize >
				sizeof(base->packet))
			{
				crondlog(
			DIE9 "base->packet too small, need at least %d",
					ICMP_MINLEN+state->curpacksize);
			}
			if (ICMP_MINLEN+state->curpacksize > len)
			{
				memset(&base->packet[len], '\0',
					ICMP_MINLEN+state->curpacksize-len);
				strcpy((char *)&base->packet[len], id);
				len= ICMP_MINLEN+state->curpacksize;
			}

			if (state->parismod)
			{
				sum= in_cksum((unsigned short *)icmp_hdr, len);

				sum= ntohs(sum);
				usum= sum + (0xffff - state->paris);
				sum= usum + (usum >> 16);

				icmp_hdr->icmp_data[0]= sum >> 8;
				icmp_hdr->icmp_data[1]= sum;
			}

			icmp_hdr->icmp_cksum=
				in_cksum((unsigned short *)icmp_hdr, len);

#if 0
			printf(
			"send_pkt: seq %d, paris %d, icmp_cksum= htons(%d)\n",
				state->seq, state->paris,
				ntohs(icmp_hdr->icmp_cksum));
#endif

			/* Set hop count */
			setsockopt(state->socket_icmp, IPPROTO_IP, IP_TTL,
				&hop, sizeof(hop));

			/* Set/clear don't fragment */
			on= (state->dont_fragment ? IP_PMTUDISC_DO :
				IP_PMTUDISC_DONT);
			setsockopt(state->socket_icmp, IPPROTO_IP,
				IP_MTU_DISCOVER, &on, sizeof(on));

			if (state->response_in)
			{
				size_t rlen;

				rlen= sizeof(r_errno);
				read_response(state->socket_icmp, RESP_SENDTO,
					&rlen, &r_errno);
				if (rlen != sizeof(r_errno))
				{
					crondlog(DIE9
			"send_pkt: error reading r_errno from '%s'",
						state->response_in);
				}
				r= r_errno.r;
				serrno= r_errno.error;
			}
			else
			{
				r= sendto(state->socket_icmp, base->packet,
					len, 0,
					(struct sockaddr *)&state->sin6,
					state->socklen);
				serrno= errno;
				if (state->resp_file_out)
				{
					r_errno.r= r;
					r_errno.error= serrno;
					write_response(state->resp_file_out,
						RESP_SENDTO,
						sizeof(r_errno), &r_errno);
				}
			}

#if 0
 { static int doit=1; if (doit && r != -1)
 	{ serrno= ENOSYS; r= -1; } doit= !doit; }
#endif

			if (r == -1)
			{
				if (serrno != EMSGSIZE)
				{
					snprintf(line, sizeof(line),
			"%s{ " DBQ(error) ":" DBQ(sendto failed: %s) " } ] }",
						state->sent ? " }, " : "",
						strerror(serrno));
					add_str(state, line);
					report(state);
					return;
				}
			}
		}
		else if (state->do_udp)
		{
			sock= socket(AF_INET, SOCK_DGRAM, 0);
			if (sock == -1)
			{
				crondlog(DIE9 "socket failed");
			}

			on= 1;
			setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on,
				sizeof(on));

			if (set_tos(state, sock, AF_INET, 1 /*inner*/) == -1)
			{
				close(sock);
				return;
			}

			/* Bind to source addr/port */
			if (state->response_in)
				r= 0;
			else
			{
				r= bind(sock,
					(struct sockaddr *)&state->loc_sin6,
					state->loc_socklen);
			}
#if 0
 { static int doit=1; if (doit && r != -1)
 { errno= ENOSYS; r= -1; } doit= !doit; }
#endif
			if (r == -1)
			{
				serrno= errno;

				snprintf(line, sizeof(line),
		"%s{ " DBQ(error) ":" DBQ(bind failed: %s) " } ] }",
					state->sent ? " }, " : "",
					strerror(serrno));
				add_str(state, line);
				report(state);
				close(sock);
				return;
			}

			hop= state->hop;

			/* Set port */
			if (state->parismod)
			{
				((struct sockaddr_in *)&state->sin6)->sin_port=
					htons(BASE_PORT + state->paris);
			}
			else
			{
				((struct sockaddr_in *)&state->sin6)->sin_port=
					htons(BASE_PORT + state->seq);
			}

			base->packet[0]= '\0';
			base->packet[1]= '\0';
			len= 2;	/* We need to fudge checksum */

			if (state->curpacksize < len)
				state->curpacksize= len;
			if (state->curpacksize > len)
			{
				memset(&base->packet[len], '\0',
					state->curpacksize-len);
				strcpy((char *)&base->packet[len], id);
				len= state->curpacksize;
			}

			v4_ph.src= ((struct sockaddr_in *)&state->loc_sin6)->
				sin_addr;
			v4_ph.dst= ((struct sockaddr_in *)&state->sin6)->
				sin_addr;
			v4_ph.zero= 0;
			v4_ph.proto= IPPROTO_UDP;
			v4_ph.len= htons(sizeof(udp)+len);
			udp.uh_sport=
				((struct sockaddr_in *)&state->loc_sin6)->
				sin_port;
			udp.uh_dport= ((struct sockaddr_in *)&state->sin6)->
				sin_port;
			udp.uh_ulen= v4_ph.len;
			udp.uh_sum= 0;

			sum= in_cksum_udp(&v4_ph, &udp,
				(unsigned short *)base->packet, len);

			if (state->parismod)
			{
				/* Make sure that the sequence number ends
				 * up in the checksum field. We can't store
				 * 0. So we add 1.
				 */
				if (state->seq == 0)
					state->seq++;
				val= state->seq;
			}
			else
			{
				/* Use id+1 */
				val= state->index+1;
			}

			sum= ntohs(sum);
			usum= sum + (0xffff - val);
			sum= usum + (usum >> 16);

			base->packet[0]= sum >> 8;
			base->packet[1]= sum;

			sum= in_cksum_udp(&v4_ph, &udp,
				(unsigned short *)base->packet, len);

			/* Set hop count */
			setsockopt(sock, IPPROTO_IP, IP_TTL,
				&hop, sizeof(hop));

			/* Set/clear don't fragment */
			on= (state->dont_fragment ? IP_PMTUDISC_DO :
				IP_PMTUDISC_DONT);
			setsockopt(sock, IPPROTO_IP,
				IP_MTU_DISCOVER, &on, sizeof(on));

			if (state->response_in)
			{
				size_t rlen;

				rlen= sizeof(r_errno);
				read_response(state->socket_icmp, RESP_SENDTO,
					&rlen, &r_errno);
				if (rlen != sizeof(r_errno))
				{
					crondlog(DIE9
			"send_pkt: error reading r_errno from '%s'",
						state->response_in);
				}
				r= r_errno.r;
				serrno= r_errno.error;
			}
			else
			{
				r= sendto(sock, base->packet, len, 0,
					(struct sockaddr *)&state->sin6,
					state->socklen);
				serrno= errno;
				if (state->resp_file_out)
				{
					r_errno.r= r;
					r_errno.error= serrno;
					write_response(state->resp_file_out,
						RESP_SENDTO,
						sizeof(r_errno), &r_errno);
				}
			}

#if 0
 { static int doit=0; if (doit && r != -1)
 	{ errno= ENOSYS; r= -1; } doit= !doit; }
#endif
			close(sock);
			if (r == -1)
			{
				if (serrno != EMSGSIZE)
				{
					serrno= errno;

					snprintf(line, sizeof(line),
			"%s{ " DBQ(error) ":" DBQ(sendto failed: %s) " } ] }",
						state->sent ? " }, " : "",
						strerror(serrno));
					add_str(state, line);
					report(state);
					return;
				}
			}
		}
	}

	if (state->open_result)
		add_str(state, " }, ");
	add_str(state, "{ ");
	state->open_result= 0;

	/* Increment packets sent */
	state->sent++;

	/* Set timer */
	interval.tv_sec= state->timeout/1000000;
	interval.tv_usec= state->timeout % 1000000;
	evtimer_add(&state->timer, &interval);

	if (state->response_in)
	{
		if (state->sin6.sin6_family == AF_INET6)
			ready_callback6(0, 0, state);
		else
			ready_callback4(0, 0, state);
	}
}

static void do_mpls(struct trtstate *state, unsigned char *packet,
	size_t size)
{
	int o, exp, s, ttl;
	uint32_t v, label;
	char line[256];

	add_str(state, ", " DBQ(mpls) ": [");

	for (o= 0; o+4 <= size; o += 4)
	{
		v= (ntohl(*(uint32_t *)&packet[o]));
		label= (v >> MPLS_LABEL_SHIFT);
		exp= ((v >> MPLS_EXT_SHIFT) & MPLS_EXT_MASK);
		s= !!(v & MPLS_S_BIT);
		ttl= (v & MPLS_TTL_MASK);

		snprintf(line, sizeof(line), "%s { " DBQ(label) ":%d, "
			DBQ(exp) ":%d, " DBQ(s) ":%d, " DBQ(ttl) ":%d }",
			o == 0 ? "" : ",",
			label, exp, s, ttl);
		add_str(state, line);
	}

	add_str(state, " ]");
}

static void do_icmp_multi(struct trtstate *state,
	unsigned char *packet, size_t size, int pre_rfc4884)
{
	int o, len;
	uint16_t cksum;
	uint8_t class, ctype, version;
	char line[256];

	if (size < 4)
	{
		printf("do_icmp_multi: not enough for ICMP extension header\n");
		return;
	}
	cksum= in_cksum((unsigned short *)packet, size);
	if (cksum != 0)
	{
		/* There is also an option for a zero checksum. */
		if (!pre_rfc4884)
		{
#if 0
			printf("do_icmp_multi: bad checksum\n");
#endif
		}
		return;
	}

	version= (*(uint8_t *)packet >> ICMPEXT_VERSION_SHIFT);

	snprintf(line, sizeof(line), ", " DBQ(icmpext) ": { "
		DBQ(version) ":%d" ", " DBQ(rfc4884) ":%d",
		version, !pre_rfc4884);
	add_str(state, line);

	add_str(state, ", " DBQ(obj) ": [");

	o= 4;
	while (o+4 < size)
	{
		len= ntohs(*(uint16_t *)&packet[o]);
		class= packet[o+2];
		ctype= packet[o+3];

		snprintf(line, sizeof(line), "%s { " DBQ(class) ":%d, "
			DBQ(type) ":%d",
			o == 4 ? "" : ",", class, ctype);
		add_str(state, line);

		if (len < 4 || o+len > size)
		{
			add_str(state, " }");
#if 0
			printf("do_icmp_multi: bad len %d\n", len);
#endif
			break;
		}
		if (class == ICMPEXT_MPLS && ctype == ICMPEXT_MPLS_IN)
			do_mpls(state, packet+o+4, len-4);
		o += len;

		add_str(state, " }");
	}

	add_str(state, " ] }");
}

static void ready_callback4(int __attribute((unused)) unused,
	const short __attribute((unused)) event, void *s)
{
	struct trtbase *base;
	struct trtstate *state;
	int hlen, ehlen, ind, nextmtu, late, isDup, icmp_prefixlen, offset;
	unsigned seq, srcport;
	ssize_t nrecv;
	socklen_t slen;
	struct ip *ip, *eip;
	struct icmp *icmp, *eicmp;
	struct tcphdr *etcp;
	struct udphdr *eudp;
	double ms;
	struct timespec now;
	struct timeval interval;
	struct sockaddr_in remote;
	char line[80];

	state= s;
	base= state->base;

	if (state->response_in)
	{
		int type;
		uint8_t proto;
		size_t len;

		peek_response(state->socket_icmp, &type);
		if (type == RESP_SENDTO)
		{
			send_pkt(s);
			return;
		}

		/* Get proto before getting the time. The reason is that
		 * When creating the output file we directly go to 
		 * ready_tcp4.
		*/

		len= sizeof(proto);
		read_response(state->socket_icmp, RESP_PROTO,
			&len, &proto);
		if (len != sizeof(proto))
		{
			crondlog(DIE9
			"ready_callback4: error reading proto from '%s'",
				state->response_in);
		}

		if (proto == 0)
		{
			noreply_callback(0, 0, state);
			return;	/* Timeout */
		}
		if (proto == 6)
		{
			ready_tcp4(0, 0, s);
			return;
		}
		if (proto != 1)
		{
			fprintf(stderr, "ready_callback4: proto != 1\n");
			return;
		}
	}

	gettime_mono(&now);

	slen= sizeof(remote);
	if (state->response_in)
	{
		size_t len;

		len= sizeof(base->packet);
		read_response(state->socket_icmp, RESP_PACKET,
			&len, base->packet);
		nrecv= len;

		len= sizeof(remote);
		read_response(state->socket_icmp, RESP_PEERNAME,
			&len, &remote);
		if (len != sizeof(remote))
		{
			crondlog(DIE9
			"ready_callback4: error reading remote from '%s'",
				state->response_in);
		}
	}
	else
	{
		nrecv= recvfrom(state->socket_icmp, base->packet, sizeof(base->packet),
			MSG_DONTWAIT, (struct sockaddr *)&remote, &slen);
	}
	if (nrecv == -1)
	{
		/* Strange, read error */
		printf("ready_callback4: read error '%s'\n", strerror(errno));
		return;
	}
	// printf("ready_callback4: got packet\n");

	if (state->resp_file_out)
	{
		uint8_t proto= 1;

		write_response(state->resp_file_out, RESP_PROTO,
			sizeof(proto), &proto);
		write_response(state->resp_file_out, RESP_PACKET,
			nrecv, base->packet);
		write_response(state->resp_file_out, RESP_PEERNAME,
			sizeof(remote), &remote);
	}

	ip= (struct ip *)base->packet;
	hlen= ip->ip_hl*4;

	if (nrecv < hlen + ICMP_MINLEN || ip->ip_hl < 5)
	{
		/* Short packet */
		printf("ready_callback4: too short %d\n", (int)nrecv);
		return;
	}

	icmp= (struct icmp *)(base->packet+hlen);

	if (icmp->icmp_type == ICMP_TIME_EXCEEDED ||
		icmp->icmp_type == ICMP_DEST_UNREACH)
	{
		eip= &icmp->icmp_ip;
		ehlen= eip->ip_hl*4;

		/* Make sure the packet we have is big enough */
		if (nrecv < hlen + ICMP_MINLEN + ehlen || eip->ip_hl < 5)
		{
			printf("ready_callback4: too short %d\n", (int)nrecv);
			return;
		}

		if (eip->ip_p == IPPROTO_TCP)
		{
			/* Now check if there is also a TCP header in the
			 * packet
			 */
			if (nrecv < hlen + ICMP_MINLEN + ehlen + 8)
			{
				printf("ready_callback4: too short %d\n",
					(int)nrecv);
				return;
			}

			/* ICMP only guarantees 8 bytes! */
			etcp= (struct tcphdr *)((char *)eip+ehlen);

			/* Quick check if the source port is in range */
#if defined(__FreeBSD__) || defined(__APPLE__)
			srcport= ntohs(etcp->th_sport);
#else
			srcport= ntohs(etcp->source);
#endif
			if (srcport < SRC_BASE_PORT ||
				srcport >= SRC_BASE_PORT+base->tabsiz)
			{
#if 0
				printf(
	"ready_callback4: unknown TCP port in ICMP: %d\n", srcport);
#endif
				return;	/* Not for us */
			}

			/* We store the id in high order 16 bits of the
			 * sequence number
			 */
			ind= ntohl(etcp->seq) >> 16;

			if (ind != state->index)
				state= NULL;
			if (state && state->sin6.sin6_family != AF_INET)
				state= NULL;
			if (state && !state->do_tcp)
				state= NULL;	

			if (!state)
			{
				/* Nothing here */
				printf(
				"ready_callback4: no state for ind %d\n",
					ind);
				return;
			}

#if 0
			printf("ready_callback4: from %s",
				inet_ntoa(remote.sin_addr));
			printf(" for %s hop %d\n",
				inet_ntoa(((struct sockaddr_in *)
				&state->sin6)->sin_addr), state->hop);
#endif

			if (!state->busy)
			{
#if 0
				printf(
			"ready_callback4: index (%d) is not busy\n",
					ind);
#endif
				return;
			}

			late= 0;
			isDup= 0;

			/* Sequence number is in seq field */
			seq= ntohl(etcp->seq) & 0xffff;

			if (state->open_result)
				add_str(state, " }, { ");

			if (seq != state->seq)
			{
				if (seq > state->seq)
				{
#if 0
					printf(
	"ready_callback4: mismatch for seq, got 0x%x, expected 0x%x (for %s)\n",
						seq, state->seq,
						state->hostname);
#endif
					return;
				}
				late= 1;

				snprintf(line, sizeof(line), DBQ(late) ":%d",
					state->seq-seq);
				add_str(state, line);
			}
			else if (state->gotresp)
			{
				isDup= 1;
				add_str(state, " " DBQ(dup) ":true");
			}

			if (!late && !isDup)
				state->last_response_hop= state->hop;

			ms= (now.tv_sec-state->xmit_time.tv_sec)*1000 +
				(now.tv_nsec-state->xmit_time.tv_nsec)/1e6;

			snprintf(line, sizeof(line),
				"%s" DBQ(from) ":" DBQ(%s),
				(late || isDup) ? ", " : "",
				inet_ntoa(remote.sin_addr));
			add_str(state, line);
			snprintf(line, sizeof(line),
				", " DBQ(ttl) ":%d, " DBQ(size) ":%d",
				ip->ip_ttl, (int)nrecv - IPHDR - ICMP_MINLEN);
			add_str(state, line);
			if (!late)
			{
				snprintf(line, sizeof(line),
					", " DBQ(rtt) ":%.3f", ms);
				add_str(state, line);
			}

			if (eip->ip_ttl != 1)
			{
				snprintf(line, sizeof(line),
					", " DBQ(ittl) ":%d", eip->ip_ttl);
				add_str(state, line);
			}
			if (eip->ip_tos != 0 || state->tos != 0)
			{
				snprintf(line, sizeof(line),
					", " DBQ(itos) ":%d", eip->ip_tos);
				add_str(state, line);
			}

			if (memcmp(&eip->ip_src,
				&((struct sockaddr_in *)&state->loc_sin6)->
				sin_addr, sizeof(eip->ip_src)) != 0)
			{
				printf("ready_callback4: changed source %s\n",
					inet_ntoa(eip->ip_src));
				printf("ready_callback4: expected %s\n",
					inet_ntoa(((struct sockaddr_in *)&state->loc_sin6)->sin_addr));
			}
			if (memcmp(&eip->ip_dst,
				&((struct sockaddr_in *)&state->sin6)->
				sin_addr, sizeof(eip->ip_dst)) != 0)
			{
				snprintf(line, sizeof(line),
					", " DBQ(edst) ":" DBQ(%s),
					inet_ntoa(eip->ip_dst));
				add_str(state, line);
			}
			if (memcmp(&ip->ip_dst,
				&((struct sockaddr_in *)&state->loc_sin6)->
				sin_addr, sizeof(eip->ip_src)) != 0)
			{
				printf("ready_callback4: weird destination %s\n",
					inet_ntoa(ip->ip_dst));
			}

#if 0
			printf("ready_callback4: from %s, ttl %d",
				inet_ntoa(remote.sin_addr), ip->ip_ttl);
			printf(" for %s hop %d\n",
				inet_ntoa(((struct sockaddr_in *)
				&state->sin6)->sin_addr), state->hop);
#endif

			if (icmp->icmp_type == ICMP_TIME_EXCEEDED)
			{
				if (!late)
					state->not_done= 1;
			}
			else if (icmp->icmp_type == ICMP_DEST_UNREACH)
			{
				if (!late)
					state->done= 1;
				switch(icmp->icmp_code)
				{
				case ICMP_UNREACH_NET:
					add_str(state,
						", " DBQ(err) ":" DBQ(N));
					break;
				case ICMP_UNREACH_HOST:
					add_str(state,
						", " DBQ(err) ":" DBQ(H));
					break;
				case ICMP_UNREACH_PROTOCOL:
					add_str(state,
						", " DBQ(err) ":" DBQ(P));
					break;
				case ICMP_UNREACH_PORT:
					break;
				case ICMP_UNREACH_NEEDFRAG:
					nextmtu= ntohs(icmp->icmp_nextmtu);
					snprintf(line, sizeof(line),
						", " DBQ(mtu) ":%d",
						nextmtu);
					add_str(state, line);
					if (!late && nextmtu >= sizeof(*ip)+
						sizeof(*etcp))
					{
						nextmtu -= sizeof(*ip)+
							sizeof(*etcp);
						if (nextmtu <
							state->curpacksize)
						{
							state->curpacksize=
								nextmtu;
						}
					}
					if (!late)
						state->not_done= 1;
					break;
				case ICMP_UNREACH_FILTER_PROHIB:
					add_str(state,
						", " DBQ(err) ":" DBQ(A));
					break;
				default:
					snprintf(line, sizeof(line),
						", " DBQ(err) ":%d",
						icmp->icmp_code);
					add_str(state, line);
					break;
				}
			}
		}
		else if (eip->ip_p == IPPROTO_UDP)
		{
			/* Now check if there is also a UDP header in the
			 * packet
			 */
			if (nrecv < hlen + ICMP_MINLEN + ehlen + sizeof(*eudp))
			{
				printf("ready_callback4: too short %d\n",
					(int)nrecv);
				return;
			}

			eudp= (struct udphdr *)((char *)eip+ehlen);

			/* We store the id in the source port.
			 */
			ind= ntohs(eudp->uh_sport) - SRC_BASE_PORT;

			if (ind != state->index)
				state= NULL;
			if (state && state->sin6.sin6_family != AF_INET)
				state= NULL;
			if (state && state->do_icmp)
				state= NULL;	

			if (!state)
			{
				/* Nothing here */
				// printf("ready_callback4: no state\n");
				return;
			}

#if 0
			printf("ready_callback4: from %s",
				inet_ntoa(remote.sin_addr));
			printf(" for %s hop %d\n",
				inet_ntoa(((struct sockaddr_in *)
				&state->sin6)->sin_addr), state->hop);
#endif

			if (!state->busy)
			{
#if 0
				printf(
			"ready_callback4: index (%d) is not busy\n",
					ind);
#endif
				return;
			}

			late= 0;
			isDup= 0;
			if (state->parismod)
			{
				/* Sequence number is in checksum field */
				seq= ntohs(eudp->uh_sum);

				/* Unfortunately, cheap home routers may 
				 * forget to restore the checksum field
				 * when they are doing NAT. Ignore the 
				 * sequence number if it seems wrong.
				 */
				if (seq > state->seq)
					seq= state->seq;
			}
			else
			{
				/* Sequence number is in destination field */
				seq= ntohs(eudp->uh_dport)-BASE_PORT;
			}

			if (state->open_result)
				add_str(state, " }, { ");

			if (seq != state->seq)
			{
				if (seq > state->seq)
				{
#if 0
					printf(
	"ready_callback4: mismatch for seq, got 0x%x, expected 0x%x (for %s)\n",
						seq, state->seq,
						state->hostname);
#endif
					return;
				}
				late= 1;

				snprintf(line, sizeof(line), DBQ(late) ":%d",
					state->seq-seq);
				add_str(state, line);
			}
			else if (state->gotresp)
			{
				isDup= 1;
				add_str(state, " " DBQ(dup) ":true");
			}

			if (!late && !isDup)
				state->last_response_hop= state->hop;

			ms= (now.tv_sec-state->xmit_time.tv_sec)*1000 +
				(now.tv_nsec-state->xmit_time.tv_nsec)/1e6;

			snprintf(line, sizeof(line),
				"%s" DBQ(from) ":" DBQ(%s),
				(late || isDup) ? ", " : "",
				inet_ntoa(remote.sin_addr));
			add_str(state, line);
			snprintf(line, sizeof(line),
				", " DBQ(ttl) ":%d, " DBQ(size) ":%d",
				ip->ip_ttl, (int)nrecv-IPHDR-ICMP_MINLEN);
			add_str(state, line);
			if (!late)
			{
				snprintf(line, sizeof(line),
					", " DBQ(rtt) ":%.3f", ms);
				add_str(state, line);
			}
			if (eip->ip_ttl != 1)
			{
				snprintf(line, sizeof(line),
					", " DBQ(ittl) ":%d", eip->ip_ttl);
				add_str(state, line);
			}
			if (eip->ip_tos != 0 || state->tos != 0)
			{
				snprintf(line, sizeof(line),
					", " DBQ(itos) ":%d", eip->ip_tos);
				add_str(state, line);
			}

			if (memcmp(&eip->ip_src,
				&((struct sockaddr_in *)&state->loc_sin6)->
				sin_addr, sizeof(eip->ip_src)) != 0)
			{
				printf("ready_callback4: changed source %s\n",
					inet_ntoa(eip->ip_src));
			}
			if (memcmp(&eip->ip_dst,
				&((struct sockaddr_in *)&state->sin6)->
				sin_addr, sizeof(eip->ip_dst)) != 0)
			{
				snprintf(line, sizeof(line),
					", " DBQ(edst) ":" DBQ(%s),
					inet_ntoa(eip->ip_dst));
				add_str(state, line);
			}
			if (memcmp(&ip->ip_dst,
				&((struct sockaddr_in *)&state->loc_sin6)->
				sin_addr, sizeof(eip->ip_src)) != 0)
			{
				printf("ready_callback4: weird destination %s\n",
					inet_ntoa(ip->ip_dst));
			}

#if 0
			printf("ready_callback4: from %s, ttl %d",
				inet_ntoa(remote.sin_addr), ip->ip_ttl);
			printf(" for %s hop %d\n",
				inet_ntoa(((struct sockaddr_in *)
				&state->sin6)->sin_addr), state->hop);
#endif

			if (icmp->icmp_type == ICMP_TIME_EXCEEDED)
			{
				if (!late)
					state->not_done= 1;
			}
			else if (icmp->icmp_type == ICMP_DEST_UNREACH)
			{
				if (!late)
					state->done= 1;
				switch(icmp->icmp_code)
				{
				case ICMP_UNREACH_NET:
					add_str(state,
						", " DBQ(err) ":" DBQ(N));
					break;
				case ICMP_UNREACH_HOST:
					add_str(state,
						", " DBQ(err) ":" DBQ(H));
					break;
				case ICMP_UNREACH_PROTOCOL:
					add_str(state,
						", " DBQ(err) ":" DBQ(P));
					break;
				case ICMP_UNREACH_PORT:
					break;
				case ICMP_UNREACH_NEEDFRAG:
					nextmtu= ntohs(icmp->icmp_nextmtu);
					snprintf(line, sizeof(line),
						", " DBQ(mtu) ":%d", nextmtu);
					add_str(state, line);
					if (!late && nextmtu >= sizeof(*ip)+
						sizeof(*eudp))
					{
						nextmtu -= sizeof(*ip)+
							sizeof(*eudp);
						if (nextmtu <
							state->curpacksize)
						{
							state->curpacksize=
								nextmtu;
						}
					}
					if (!late)
						state->not_done= 1;
					break;
				case ICMP_UNREACH_FILTER_PROHIB:
					add_str(state,
						", " DBQ(err) ":" DBQ(A));
					break;
				default:
					snprintf(line, sizeof(line),
						", " DBQ(err) ":%d",
						icmp->icmp_code);
					add_str(state, line);
					break;
				}
			}
		}
		else if (eip->ip_p == IPPROTO_ICMP)
		{
			/* Now check if there is also an ICMP header in the
			 * packet
			 */
			if (nrecv < hlen + ICMP_MINLEN + ehlen +
				offsetof(struct icmp, icmp_data[0]))
			{
				printf("ready_callback4: too short %d\n",
					(int)nrecv);
				return;
			}

			eicmp= (struct icmp *)((char *)eip+ehlen);

			if (eicmp->icmp_type != ICMP_ECHO ||
				eicmp->icmp_code != 0)
			{
				printf("ready_callback4: not ECHO\n");
				return;
			}

			ind= ntohs(eicmp->icmp_id);
			if ((ind >> TRT_ICMP4_INSTANCE_ID_SHIFT) != instance_id)
			{
				// printf("wrong instance id\n");
				return;
			}
			ind &= ~TRT_ICMP4_INSTANCE_ID_MASK;

			if (ind >= base->tabsiz)
			{
				/* Out of range */
#if 0
				printf(
				"ready_callback4: index out of range (%d)\n",
					ind);
#endif
				return;
			}

			if (ind != state->index)
			{
				/* Nothing here */
#if 0
				printf(
				"ready_callback4: nothing at index (%d)\n",
					ind);
#endif
				return;
			}

			if (state->sin6.sin6_family != AF_INET)
			{
				// printf("ready_callback4: bad family\n");
				return;
			}

			if (!state->do_icmp)
			{
				printf(
			"ready_callback4: index (%d) is not doing ICMP\n",
					ind);
				return;
			}
			if (!state->busy)
			{
				printf(
			"ready_callback4: index (%d) is not busy\n",
					ind);
				return;
			}

			if (state->parismod &&
				ntohs(eicmp->icmp_cksum) != state->paris)
			{
				printf(
	"ready_callback4: mismatch for paris, got 0x%x, expected 0x%x (%s)\n",
					ntohs(eicmp->icmp_cksum),
					state->paris, state->hostname);
			}

			if (state->open_result)
				add_str(state, " }, { ");

			late= 0;
			isDup= 0;
			seq= ntohs(eicmp->icmp_seq);
			if (seq != state->seq)
			{
				if (seq > state->seq)
				{
#if 0
					printf(
	"ready_callback4: mismatch for seq, got 0x%x, expected 0x%x (for %s)\n",
						seq, state->seq,
						state->hostname);
#endif
					return;
				}
				late= 1;

				snprintf(line, sizeof(line), DBQ(late) ":%d",
					state->seq-seq);
				add_str(state, line);
			}
			else if (state->gotresp)
			{
				isDup= 1;
				add_str(state, DBQ(dup) ":true");
			}

			if (!late && !isDup)
				state->last_response_hop= state->hop;

			ms= (now.tv_sec-state->xmit_time.tv_sec)*1000 +
				(now.tv_nsec-state->xmit_time.tv_nsec)/1e6;

			snprintf(line, sizeof(line), "%s" DBQ(from) ":" DBQ(%s),
				(late || isDup) ? ", " : "",
				inet_ntoa(remote.sin_addr));
			add_str(state, line);
			snprintf(line, sizeof(line),
				", " DBQ(ttl) ":%d, " DBQ(size) ":%d",
				ip->ip_ttl, (int)nrecv-IPHDR-ICMP_MINLEN);
			add_str(state, line);
			if (!late)
			{
				snprintf(line, sizeof(line),
					", " DBQ(rtt) ":%.3f", ms);
				add_str(state, line);
			}

			if (eip->ip_ttl != 1)
			{
				snprintf(line, sizeof(line),
					", " DBQ(ittl) ":%d", eip->ip_ttl);
				add_str(state, line);
			}
			if (eip->ip_tos != 0 || state->tos != 0)
			{
				snprintf(line, sizeof(line),
					", " DBQ(itos) ":%d", eip->ip_tos);
				add_str(state, line);
			}

			if (memcmp(&eip->ip_src,
				&((struct sockaddr_in *)&state->loc_sin6)->
				sin_addr, sizeof(eip->ip_src)) != 0)
			{
				printf("ready_callback4: changed source %s\n",
					inet_ntoa(eip->ip_src));
				printf("ready_callback4: expected %s\n",
					inet_ntoa(((struct sockaddr_in *)&state->loc_sin6)->sin_addr));
			}
			if (memcmp(&eip->ip_dst,
				&((struct sockaddr_in *)&state->sin6)->
				sin_addr, sizeof(eip->ip_dst)) != 0)
			{
				snprintf(line, sizeof(line),
					", " DBQ(edst) ":" DBQ(%s),
					inet_ntoa(eip->ip_dst));
				add_str(state, line);
			}
			if (memcmp(&ip->ip_dst,
				&((struct sockaddr_in *)&state->loc_sin6)->
				sin_addr, sizeof(eip->ip_src)) != 0)
			{
				printf("ready_callback4: weird destination %s\n",
					inet_ntoa(ip->ip_dst));
			}

#if 0
			printf("ready_callback4: from %s, ttl %d",
				inet_ntoa(remote.sin_addr), ip->ip_ttl);
			printf(" for %s hop %d\n",
				inet_ntoa(((struct sockaddr_in *)
				&state->sin6)->sin_addr), state->hop);
#endif

			if (icmp->icmp_type == ICMP_TIME_EXCEEDED)
			{
				if (!late && !isDup)
					state->not_done= 1;
			}
			else if (icmp->icmp_type == ICMP_DEST_UNREACH)
			{
				if (!late)
					state->done= 1;
				switch(icmp->icmp_code)
				{
				case ICMP_UNREACH_NET:
					add_str(state,
						", " DBQ(err) ":" DBQ(N));
					break;
				case ICMP_UNREACH_HOST:
					add_str(state,
						", " DBQ(err) ":" DBQ(H));
					break;
				case ICMP_UNREACH_PROTOCOL:
					add_str(state,
						", " DBQ(err) ":" DBQ(P));
					break;
				case ICMP_UNREACH_PORT:
					add_str(state,
						", " DBQ(err) ":" DBQ(p));
					break;
				case ICMP_UNREACH_NEEDFRAG:
					nextmtu= ntohs(icmp->icmp_nextmtu);
					snprintf(line, sizeof(line),
						", " DBQ(mtu) ":%d",
						nextmtu);
					add_str(state, line);
					if (!late && nextmtu >= sizeof(*ip) +
						ICMP_MINLEN)
					{
						nextmtu -= sizeof(*ip) +
							ICMP_MINLEN;
						if (nextmtu <
							state->curpacksize)
						{
							state->curpacksize=
								nextmtu;
						}
					}
					if (!late)
						state->not_done= 1;
					break;
				case ICMP_UNREACH_FILTER_PROHIB:
					add_str(state,
						", " DBQ(err) ":" DBQ(A));
					break;
				default:
					snprintf(line, sizeof(line),
						", " DBQ(err) ":%d",
						icmp->icmp_code);
					add_str(state, line);
					break;
				}
			}
			else
			{
				printf("imcp type %d\n", icmp->icmp_type);
			}
		}
		else
		{
			printf("ready_callback4: not TCP, UDP or ICMP (%d\n",
				eip->ip_p);
			return;
		}

		/* RFC-4884, Multi-Part ICMP messages */
		icmp_prefixlen= (ntohs(icmp->icmp_pmvoid) & 0xff) * 4;
		if (icmp_prefixlen != 0)
		{
			
#if 0
			printf("icmp_pmvoid: 0x%x for %s\n", icmp->icmp_pmvoid, state->hostname);
			printf("icmp_prefixlen: 0x%x for %s\n", icmp_prefixlen, inet_ntoa(remote.sin_addr));
#endif
			offset= hlen + ICMP_MINLEN + icmp_prefixlen;
			if (nrecv > offset)
			{
				do_icmp_multi(state, base->packet+offset,
					nrecv-offset, 0 /*!pre_rfc4884*/);
			}
			else
			{
#if 0
				printf(
			"ready_callback4: too short %d (Multi-Part ICMP)\n",
					(int)nrecv);
#endif
			}
		}
		else if (nrecv > hlen + ICMP_MINLEN + 128)
		{
			/* Try old style extensions */
			icmp_prefixlen= 128;
			offset= hlen + ICMP_MINLEN + icmp_prefixlen;
			if (nrecv > offset)
			{
				do_icmp_multi(state, base->packet+offset,
					nrecv-offset, 1 /*pre_rfc4884*/);
			}
			else
			{
				printf(
			"ready_callback4: too short %d (Multi-Part ICMP)\n",
					(int)nrecv);
			}
		}

		state->open_result= 1;

		if (!late && !isDup)
		{
			if (state->duptimeout)
			{
				state->gotresp= 1;
				interval.tv_sec= state->duptimeout/1000000;
				interval.tv_usec= state->duptimeout % 1000000;
				evtimer_add(&state->timer, &interval);
			}
			else
			{
				send_pkt(state);
			}
		}
	}
	else if (icmp->icmp_type == ICMP_ECHOREPLY)
	{
		if (icmp->icmp_code != 0)
		{
			printf("ready_callback4: not proper ECHO REPLY\n");
			return;
		}

		ind= ntohs(icmp->icmp_id);
		if ((ind >> TRT_ICMP4_INSTANCE_ID_SHIFT) != instance_id)
		{
			// printf("wrong instance id\n");
			return;
		}
		ind &= ~TRT_ICMP4_INSTANCE_ID_MASK;

		if (ind >= base->tabsiz)
		{
			/* Out of range */
#if 0
			printf(
			"ready_callback4: index out of range (%d)\n",
				ind);
#endif
			return;
		}

		if (ind != state->index)
		{
			/* Nothing here */
#if 0
			printf(
			"ready_callback4: nothing at index (%d)\n",
				ind);
#endif
			return;
		}

		if (state->sin6.sin6_family != AF_INET)
		{
			// printf("ready_callback4: bad family\n");
			return;
		}

		if (!state->busy)
		{
			printf(
		"ready_callback4: index (%d) is not busy\n",
				ind);
			return;
		}

		if (state->open_result)
			add_str(state, " }, { ");

		late= 0;
		isDup= 0;
		seq= ntohs(icmp->icmp_seq);
		if (seq != state->seq)
		{
			if (seq > state->seq)
			{
#if 0
				printf(
"ready_callback4: mismatch for seq, got 0x%x, expected 0x%x, for %s\n",
					seq, state->seq, state->hostname);
#endif
				return;
			}
			late= 1;

			snprintf(line, sizeof(line), DBQ(late) ":%d",
				state->seq-seq);
			add_str(state, line);
		}
		else if (state->gotresp)
		{
			isDup= 1;
			add_str(state, DBQ(dup) ":true");
		}

		if (memcmp(&ip->ip_dst,
			&((struct sockaddr_in *)&state->loc_sin6)->
			sin_addr, sizeof(eip->ip_src)) != 0)
		{
			printf("ready_callback4: weird destination %s\n",
				inet_ntoa(ip->ip_dst));
		}

		ms= (now.tv_sec-state->xmit_time.tv_sec)*1000 +
			(now.tv_nsec-state->xmit_time.tv_nsec)/1e6;

		snprintf(line, sizeof(line), "%s" DBQ(from) ":" DBQ(%s),
			(late || isDup) ? ", " : "",
			inet_ntoa(remote.sin_addr));
		add_str(state, line);
		snprintf(line, sizeof(line),
			", " DBQ(ttl) ":%d, " DBQ(size) ":%d",
			ip->ip_ttl, (int)nrecv - IPHDR - ICMP_MINLEN);
		add_str(state, line);
		if (ip->ip_tos != 0 || state->tos != 0)
		{
			snprintf(line, sizeof(line), ", " DBQ(tos) ":%d",
				ip->ip_tos);
			add_str(state, line);
		}
		if (!late)
		{
			snprintf(line, sizeof(line), ", " DBQ(rtt) ":%.3f", ms);
			add_str(state, line);
		}

#if 0
		printf("ready_callback4: from %s, ttl %d",
			inet_ntoa(remote.sin_addr), ip->ip_ttl);
		printf(" for %s hop %d\n",
			inet_ntoa(((struct sockaddr_in *)
			&state->sin6)->sin_addr), state->hop);
#endif

		/* Done */
		state->done= 1;

		state->open_result= 1;

		if (!late && !isDup)
		{
			if (state->duptimeout)
			{
				state->gotresp= 1;
				interval.tv_sec= state->duptimeout/1000000;
				interval.tv_usec= state->duptimeout % 1000000;
				evtimer_add(&state->timer, &interval);
			}
			else
			{
				send_pkt(state);
			}
		}

		return;
	}
	else if (icmp->icmp_type == ICMP_ECHO ||
		icmp->icmp_type == ICMP_ROUTERADVERT)
	{
		/* No need to do anything */
	}
	else
	{
		printf("ready_callback4: got type %d\n", icmp->icmp_type);
		return;
	}
}

static void report_hdropts(struct trtstate *state, unsigned char *s, 
	unsigned char *e)
{
	int o, len, mss;
	unsigned char *orig_s;
	char line[80];

	add_str(state, ", " DBQ(hdropts) ": [ ");
	orig_s= s;
	while (s<e)
	{
		o= *s;
		switch(o)
		{
		case 2:
			len= s[1];
			if (len < 4 || s+len > e)
			{
				printf("report_hdropts: bad option\n");
				break;
			}
			mss= (s[2] << 8) | s[3];
			snprintf(line, sizeof(line),
				"%s{ " DBQ(mss) ":%d }",
				s != orig_s ? ", " : "", mss);
			add_str(state, line);
			s += len;
			continue;
		default:
			snprintf(line, sizeof(line),
				"%s{ " DBQ(unknown-opt) ":%d }",
				s != orig_s ? ", " : "", o);
			add_str(state, line);
			break;
		}
		break;
	}
	add_str(state, " ]");
}

static void ready_tcp4(int __attribute((unused)) unused,
	const short __attribute((unused)) event, void *s)
{
	uint16_t myport;
	socklen_t slen;
	int hlen, late, isDup, tcp_hlen;
	unsigned ind, seq;
	ssize_t nrecv;
	struct trtbase *base;
	struct trtstate *state;
	struct ip *ip;
	double ms;
	struct tcphdr *tcphdr;
	unsigned char *e, *p;
	struct sockaddr_in remote;
	struct timespec now;
	struct timeval interval;
	char line[80];

	gettime_mono(&now);

	state= s;
	base= state->base;

	slen= sizeof(remote);

	if (state->response_in)
	{
		size_t len;

		/* Proto is eaten by ready_callback4 */
		len= sizeof(base->packet);
		read_response(state->socket_icmp, RESP_PACKET,
			&len, base->packet);
		nrecv= len;

		len= sizeof(remote);
		read_response(state->socket_icmp, RESP_PEERNAME,
			&len, &remote);
		if (len != sizeof(remote))
		{
			crondlog(DIE9
			"ready_tcp4: error reading remote from '%s'",
				state->response_in);
		}
	}
	else
	{
		nrecv= recvfrom(state->socket_tcp, base->packet,
			sizeof(base->packet), MSG_DONTWAIT,
			(struct sockaddr *)&remote, &slen);
	}
	if (nrecv == -1)
	{
		/* Strange, read error */
		printf("ready_tcp4: read error '%s'\n", strerror(errno));
		return;
	}

	if (state->resp_file_out)
	{
		uint8_t proto= 6;

		write_response(state->resp_file_out, RESP_PROTO,
			sizeof(proto), &proto);
		write_response(state->resp_file_out, RESP_PACKET,
			nrecv, base->packet);
		write_response(state->resp_file_out, RESP_PEERNAME,
			sizeof(remote), &remote);
	}

	ip= (struct ip *)base->packet;
	hlen= ip->ip_hl*4;

	if (nrecv < hlen + sizeof(*tcphdr) || ip->ip_hl < 5)
	{
		/* Short packet */
		printf("ready_tcp4: too short %d\n", (int)nrecv);
		return;
	}

	tcphdr= (struct tcphdr *)(base->packet+hlen);

	tcp_hlen= tcphdr->doff * 4;
	if (nrecv < hlen + tcp_hlen || tcphdr->doff < 5)
	{
		/* Short packet */
		printf("ready_tcp4: too short %d\n", (int)nrecv);
		return;
	}

	/* Quick check if the port is in range */
	myport= ntohs(tcphdr->th_dport);
	if (myport < SRC_BASE_PORT || myport >= SRC_BASE_PORT+base->tabsiz)
	{
		return;	/* Not for us */
	}

	/* We store the id in high order 16 bits of the sequence number */
	ind= ntohl(tcphdr->th_ack) >> 16;

	if (ind != state->index)
		state= NULL;
	if (state && state->sin6.sin6_family != AF_INET)
		state= NULL;
	if (state && !state->do_tcp)
		state= NULL;	

	if (!state)
	{
		/* Nothing here */
		printf("ready_tcp4: no state for index %d\n", ind);
		return;
	}

	if (!state->busy)
	{
		printf(
	"ready_callback4: index (%d) is not busy\n",
			ind);
		return;
	}

	late= 0;
	isDup= 0;

	if (state->open_result)
		add_str(state, " }, { ");

	/* Only check if the ack is without 64k of what we expect */
	seq= ntohl(tcphdr->th_ack) & 0xffff;
	if (seq-state->seq > 0x2000)
	{
		if (seq > state->seq)
		{
#if 0
			printf(
"ready_callback4: mismatch for seq, got 0x%x, expected 0x%x, for %s\n",
				seq, state->seq, state->hostname);
#endif
			return;
		}
		late= 1;

		snprintf(line, sizeof(line), DBQ(late) ":%d",
			state->seq-seq);
		add_str(state, line);
	}
	else if (state->gotresp)
	{
		isDup= 1;
		add_str(state, DBQ(dup) ":true");
	}

	ms= (now.tv_sec-state->xmit_time.tv_sec)*1000 +
		(now.tv_nsec-state->xmit_time.tv_nsec)/1e6;

	snprintf(line, sizeof(line), "%s" DBQ(from) ":" DBQ(%s),
		(late || isDup) ? ", " : "",
		inet_ntoa(remote.sin_addr));
	add_str(state, line);
	snprintf(line, sizeof(line), ", " DBQ(ttl) ":%d, " DBQ(size) ":%d",
		ip->ip_ttl, (int)(nrecv - IPHDR - sizeof(*tcphdr)));
	add_str(state, line);
	if (ip->ip_tos != 0 || state->tos != 0)
	{
		snprintf(line, sizeof(line), ", " DBQ(tos) ":%d", ip->ip_tos);
		add_str(state, line);
	}
	snprintf(line, sizeof(line), ", " DBQ(flags) ":" DBQ(%s%s%s%s%s%s),
		((tcphdr->th_flags & TCP_FIN_FLAG) ? "F" : ""),
		((tcphdr->th_flags & TCP_SYN_FLAG) ? "S" : ""),
		((tcphdr->th_flags & TCP_RST_FLAG) ? "R" : ""),
		((tcphdr->th_flags & TCP_PSH_FLAG) ? "P" : ""),
		((tcphdr->th_flags & TCP_ACK_FLAG) ? "A" : ""),
		((tcphdr->th_flags & TCP_URG_FLAG) ? "U" : ""));
	add_str(state, line);

	if (tcp_hlen > sizeof(*tcphdr))
	{
		p= (unsigned char *)&tcphdr[1];
		e= ((unsigned char *)tcphdr) + tcp_hlen;
		report_hdropts(state, p, e);
	}

	if (!late)
	{
		snprintf(line, sizeof(line), ", " DBQ(rtt) ":%.3f", ms);
		add_str(state, line);
	}

#if 0
	printf("ready_callback4: from %s, ttl %d",
		inet_ntoa(remote.sin_addr), ip->ip_ttl);
	printf(" for %s hop %d\n",
		inet_ntoa(((struct sockaddr_in *)
		&state->sin6)->sin_addr), state->hop);
#endif

	/* Done */
	state->done= 1;

	state->open_result= 1;

	if (!late && !isDup)
	{
		if (state->duptimeout)
		{
			state->gotresp= 1;
			interval.tv_sec= state->duptimeout/1000000;
			interval.tv_usec= state->duptimeout % 1000000;
			evtimer_add(&state->timer, &interval);
		}
		else
		{
			send_pkt(state);
		}
	}

	return;
}

static void ready_tcp6(int __attribute((unused)) unused,
	const short __attribute((unused)) event, void *s)
{
	uint16_t myport;
	int late, isDup, rcvdttl, rcvdtclass, tcp_hlen;
	unsigned ind, seq;
	ssize_t nrecv;
	struct trtbase *base;
	struct trtstate *state;
	double ms;
	unsigned char *e, *p;
	struct tcphdr *tcphdr;
	struct cmsghdr *cmsgptr;
	struct msghdr msg;
	struct iovec iov[1];
	struct sockaddr_in6 remote;
	struct in6_addr dstaddr;
	struct timespec now;
	struct timeval interval;
	char buf[INET6_ADDRSTRLEN];
	char line[80];
	char cmsgbuf[256];

	gettime_mono(&now);

	state= s;
	base= state->base;

	iov[0].iov_base= base->packet;
	iov[0].iov_len= sizeof(base->packet);
	msg.msg_name= &remote;
	msg.msg_namelen= sizeof(remote);
	msg.msg_iov= iov;
	msg.msg_iovlen= 1;
	msg.msg_control= cmsgbuf;
	msg.msg_controllen= sizeof(cmsgbuf);
	msg.msg_flags= 0;			/* Not really needed */

	if (state->response_in)
	{
		size_t len;

		/* Proto is eaten by ready_callback6 */
		len= sizeof(base->packet);
		read_response(state->socket_icmp, RESP_PACKET,
			&len, base->packet);
		nrecv= len;

		len= sizeof(remote);
		read_response(state->socket_icmp, RESP_PEERNAME,
			&len, &remote);
		if (len != sizeof(remote))
		{
			crondlog(DIE9
			"ready_tcp6: error reading remote from '%s'",
				state->response_in);
		}
	}
	else
		nrecv= recvmsg(state->socket_tcp, &msg, MSG_DONTWAIT);
	if (nrecv == -1)
	{
		/* Strange, read error */
		printf("ready_tcp6: read error '%s'\n", strerror(errno));
		return;
	}

	if (state->resp_file_out)
	{
		uint8_t proto= 6;

		write_response(state->resp_file_out, RESP_PROTO,
			sizeof(proto), &proto);
		write_response(state->resp_file_out, RESP_PACKET,
			nrecv, base->packet);
		write_response(state->resp_file_out, RESP_PEERNAME,
			sizeof(remote), &remote);
	}

	rcvdttl= -42;	/* To spot problems */
	rcvdtclass= -42;	/* To spot problems */
	memset(&dstaddr, '\0', sizeof(dstaddr));
	for (cmsgptr= CMSG_FIRSTHDR(&msg); cmsgptr; 
		cmsgptr= CMSG_NXTHDR(&msg, cmsgptr))
	{
		if (cmsgptr->cmsg_len == 0)
			break;	/* Can this happen? */
		if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
			cmsgptr->cmsg_type == IPV6_HOPLIMIT)
		{
			rcvdttl= *(int *)CMSG_DATA(cmsgptr);
		}
		if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
			cmsgptr->cmsg_type == IPV6_PKTINFO)
		{
			dstaddr= ((struct in6_pktinfo *)
				CMSG_DATA(cmsgptr))->ipi6_addr;
		}
		if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
			cmsgptr->cmsg_type == IPV6_TCLASS)
		{
			rcvdtclass= *(int *)CMSG_DATA(cmsgptr);
		}
	}

	if (state->response_in)
	{
		size_t len;

		len= sizeof(rcvdttl);
		read_response(state->socket_icmp, RESP_RCVDTTL,
			&len, &rcvdttl);
		if (len != sizeof(rcvdttl))
		{
			crondlog(DIE9
			"ready_tcp6: error reading ttl from '%s'",
				state->response_in);
		}
		len= sizeof(rcvdtclass);
		read_response(state->socket_icmp, RESP_RCVDTCLASS,
			&len, &rcvdtclass);
		if (len != sizeof(rcvdtclass))
		{
			crondlog(DIE9
		"ready_tcp6: error reading traffic class from '%s'",
				state->response_in);
		}
	}
	if (state->response_out)
	{
		write_response(state->resp_file_out, RESP_RCVDTTL,
			sizeof(rcvdttl), &rcvdttl);
		write_response(state->resp_file_out, RESP_RCVDTCLASS,
			sizeof(rcvdtclass), &rcvdtclass);
	}

	tcphdr= (struct tcphdr *)(base->packet);

	tcp_hlen= tcphdr->doff * 4;
	if (nrecv < tcp_hlen || tcphdr->doff < 5)
	{
		/* Short packet */
		printf("ready_tcp6: too short %d\n", (int)nrecv);
		return;
	}

	/* Quick check if the port is in range */
	myport= ntohs(tcphdr->th_dport);
	if (myport < SRC_BASE_PORT || myport >= SRC_BASE_PORT+base->tabsiz)
	{
		return;	/* Not for us */
	}

	/* We store the id in high order 16 bits of the sequence number */
	ind= ntohl(tcphdr->th_ack) >> 16;

	if (ind != state->index)
		state= NULL;
	if (state && state->sin6.sin6_family != AF_INET6)
		state= NULL;
	if (state && !state->do_tcp)
		state= NULL;	

	if (!state)
	{
		/* Nothing here */
		printf("ready_tcp6: no state for index %d\n", ind);
		return;
	}

	if (!state->busy)
	{
		printf("ready_tcp6: index (%d) is not busy\n", ind);
		return;
	}

	late= 0;
	isDup= 0;

	if (state->open_result)
		add_str(state, " }, { ");

	/* Only check if the ack is within 64k of what we expect */
	seq= ntohl(tcphdr->th_ack) & 0xffff;
	if (seq-state->seq > 0x2000)
	{
		if (seq > state->seq)
		{
#if 0
			printf(
"ready_tcp6: mismatch for seq, got 0x%x, expected 0x%x, for %s\n",
				seq, state->seq, state->hostname);
#endif
			return;
		}
		late= 1;

		snprintf(line, sizeof(line), DBQ(late) ":%d",
			state->seq-seq);
		add_str(state, line);
	}
	else if (state->gotresp)
	{
		isDup= 1;
		add_str(state, DBQ(dup) ":true");
	}

	ms= (now.tv_sec-state->xmit_time.tv_sec)*1000 +
		(now.tv_nsec-state->xmit_time.tv_nsec)/1e6;

	snprintf(line, sizeof(line), "%s" DBQ(from) ":" DBQ(%s),
		(late || isDup) ? ", " : "",
		inet_ntop(AF_INET6, &remote.sin6_addr, buf, sizeof(buf)));
	add_str(state, line);
	snprintf(line, sizeof(line), ", " DBQ(ttl) ":%d, " DBQ(size) ":%d",
		rcvdttl, (int)(nrecv - sizeof(*tcphdr)));
	add_str(state, line);
	if (rcvdtclass != 0 || state->tos != 0)
	{
		snprintf(line, sizeof(line), ", " DBQ(tos) ":%d",
			rcvdtclass);
		add_str(state, line);
	}
	snprintf(line, sizeof(line), ", " DBQ(flags) ":" DBQ(%s%s%s%s%s%s),
		((tcphdr->th_flags & TCP_FIN_FLAG) ? "F" : ""),
		((tcphdr->th_flags & TCP_SYN_FLAG) ? "S" : ""),
		((tcphdr->th_flags & TCP_RST_FLAG) ? "R" : ""),
		((tcphdr->th_flags & TCP_PSH_FLAG) ? "P" : ""),
		((tcphdr->th_flags & TCP_ACK_FLAG) ? "A" : ""),
		((tcphdr->th_flags & TCP_URG_FLAG) ? "U" : ""));
	add_str(state, line);

	if (tcp_hlen > sizeof(*tcphdr))
	{
		p= (unsigned char *)&tcphdr[1];
		e= ((unsigned char *)tcphdr) + tcp_hlen;
		report_hdropts(state, p, e);
	}

	if (!late)
	{
		snprintf(line, sizeof(line), ", " DBQ(rtt) ":%.3f", ms);
		add_str(state, line);
	}

#if 0
	printf("ready_tcp6: from %s, ttl %d",
		inet_ntoa(remote.sin_addr), ip->ip_ttl);
	printf(" for %s hop %d\n",
		inet_ntoa(((struct sockaddr_in *)
		&state->sin6)->sin_addr), state->hop);
#endif

	/* Done */
	state->done= 1;

	state->open_result= 1;

	if (!late && !isDup)
	{
		if (state->duptimeout)
		{
			state->gotresp= 1;
			interval.tv_sec= state->duptimeout/1000000;
			interval.tv_usec= state->duptimeout % 1000000;
			evtimer_add(&state->timer, &interval);
		}
		else
		{
			send_pkt(state);
		}
	}

	return;
}

static void ready_callback6(int __attribute((unused)) unused,
	const short __attribute((unused)) event, void *s)
{
	ssize_t nrecv;
	int ind, rcvdttl, late, isDup, nxt, icmp_prefixlen, offset, rcvdtclass;
	unsigned nextmtu, seq, optlen, hbhoptsize, dstoptsize;
	size_t v6info_siz, siz;
	struct trtbase *base;
	struct trtstate *state;
	struct ip6_hdr *eip;
	struct ip6_frag *frag;
	struct ip6_ext *opthdr;
	struct icmp6_hdr *icmp, *eicmp;
	struct tcphdr *etcp;
	struct udphdr *eudp;
	struct v6info *v6info;
	struct cmsghdr *cmsgptr;
	void *ptr;
	double ms= -42;	/* lint, to spot problems */
	struct timespec now;
	struct sockaddr_in6 remote;
	struct in6_addr dstaddr;
	struct msghdr msg;
	struct iovec iov[1];
	struct timeval interval;
	char buf[INET6_ADDRSTRLEN];
	char line[80];
	char cmsgbuf[256];

	state= s;
	base= state->base;

	if (state->response_in)
	{
		int type;
		uint8_t proto;
		size_t len;

		peek_response(state->socket_icmp, &type);
		if (type == RESP_SENDTO)
		{
			send_pkt(s);
			return;
		}

		/* Get proto before we get the time because at response_out
		 * we don't get here when a TCP packet arrives.
		 */
		len= sizeof(proto);
		read_response(state->socket_icmp, RESP_PROTO,
			&len, &proto);
		if (len != sizeof(proto))
		{
			crondlog(DIE9
			"ready_callback6: error reading proto from '%s'",
				state->response_in);
		}

		if (proto == 0)
		{
			noreply_callback(0, 0, state);
			return;	/* Timeout */
		}
		if (proto == 6)
		{
			ready_tcp6(0, 0, s);
			return;
		}
		if (proto != 1)
		{
			fprintf(stderr, "ready_callback6: proto != 1\n");
			return;
		}
	}

	gettime_mono(&now);

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
	if (state->response_in)
	{
		size_t len;

		len= sizeof(base->packet);
		read_response(state->socket_icmp, RESP_PACKET,
			&len, base->packet);
		nrecv= len;

		len= sizeof(remote);
		read_response(state->socket_icmp, RESP_PEERNAME,
			&len, &remote);
		if (len != sizeof(remote))
		{
			crondlog(DIE9
			"ready_callback6: error reading remote from '%s'",
				state->response_in);
		}


		/* Do not try to fuzz the cmsgbuf. We assume stuff returned by
		 * the kernel can be trusted.
		 */
		memset(cmsgbuf, '\0', sizeof(cmsgbuf));
	}
	else
		nrecv= recvmsg(state->socket_icmp, &msg, MSG_DONTWAIT);
	if (nrecv == -1)
	{
		/* Strange, read error */
		fprintf(stderr, "ready_callback6: read error '%s'\n",
			strerror(errno));
		return;
	}

	if (state->response_out)
	{
		uint8_t proto= 1;

		write_response(state->resp_file_out, RESP_PROTO,
			sizeof(proto), &proto);
		write_response(state->resp_file_out, RESP_PACKET,
			nrecv, base->packet);
		write_response(state->resp_file_out, RESP_PEERNAME,
			sizeof(remote), &remote);
	}

	rcvdttl= -42;		/* To spot problems */
	rcvdtclass= -42;	/* To spot problems */
	memset(&dstaddr, '\0', sizeof(dstaddr));
	for (cmsgptr= CMSG_FIRSTHDR(&msg); cmsgptr; 
		cmsgptr= CMSG_NXTHDR(&msg, cmsgptr))
	{
		if (cmsgptr->cmsg_len == 0)
			break;	/* Can this happen? */
		if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
			cmsgptr->cmsg_type == IPV6_HOPLIMIT)
		{
			rcvdttl= *(int *)CMSG_DATA(cmsgptr);
		}
		if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
			cmsgptr->cmsg_type == IPV6_PKTINFO)
		{
			dstaddr= ((struct in6_pktinfo *)
				CMSG_DATA(cmsgptr))->ipi6_addr;
		}
		if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
			cmsgptr->cmsg_type == IPV6_TCLASS)
		{
			rcvdtclass= *(int *)CMSG_DATA(cmsgptr);
		}
	}

	if (state->response_in)
	{
		size_t len;

		len= sizeof(rcvdttl);
		read_response(state->socket_icmp, RESP_RCVDTTL,
			&len, &rcvdttl);
		if (len != sizeof(rcvdttl))
		{
			crondlog(DIE9
			"ready_callback6: error reading ttl from '%s'",
				state->response_in);
		}
		len= sizeof(rcvdtclass);
		read_response(state->socket_icmp, RESP_RCVDTCLASS,
			&len, &rcvdtclass);
		if (len != sizeof(rcvdtclass))
		{
			crondlog(DIE9
		"ready_callback6: error reading traffic class from '%s'",
				state->response_in);
		}
	}
	if (state->response_out)
	{
		write_response(state->resp_file_out, RESP_RCVDTTL,
			sizeof(rcvdttl), &rcvdttl);
		write_response(state->resp_file_out, RESP_RCVDTCLASS,
			sizeof(rcvdtclass), &rcvdtclass);
	}

	if (nrecv < sizeof(*icmp))
	{
		/* Short packet */
#if 0
		fprintf(stderr, "ready_callback6: too short %d (icmp)\n",
			(int)nrecv);
#endif
		return;
	}

	icmp= (struct icmp6_hdr *)&base->packet;

	hbhoptsize= 0;
	dstoptsize= 0;
	if (icmp->icmp6_type == ICMP6_DST_UNREACH ||
		icmp->icmp6_type == ICMP6_PACKET_TOO_BIG ||
		icmp->icmp6_type == ICMP6_TIME_EXCEEDED)
	{
		eip= (struct ip6_hdr *)&icmp[1];

		/* Make sure the packet we have is big enough */
		if (nrecv < sizeof(*icmp) + sizeof(*eip))
		{
#if 0
			fprintf(stderr,
				"ready_callback6: too short %d (icmp_ip)\n",
				(int)nrecv);
#endif
			return;
		}

		/* Make sure we have TCP, UDP, ICMP, a fragment header or
		 * an options header */
		if (eip->ip6_nxt == IPPROTO_FRAGMENT ||
			eip->ip6_nxt == IPPROTO_HOPOPTS ||
			eip->ip6_nxt == IPPROTO_DSTOPTS ||
			eip->ip6_nxt == IPPROTO_TCP ||
			eip->ip6_nxt == IPPROTO_UDP ||
			eip->ip6_nxt == IPPROTO_ICMPV6)
		{
			frag= NULL;
			nxt= eip->ip6_nxt;
			ptr= &eip[1];
			if (nxt == IPPROTO_HOPOPTS)
			{
				/* Make sure the options header is completely
				 * there.
				 */
				offset= (u_char *)ptr - base->packet;
				if (offset + sizeof(*opthdr) > nrecv)
				{
#if 0
					fprintf(stderr,
			"ready_callback6: too short %d (HOPOPTS)\n",
						(int)nrecv);
#endif
					return;
				}
				opthdr= (struct ip6_ext *)ptr;
				hbhoptsize= 8*opthdr->ip6e_len;
				optlen= hbhoptsize+8;
				if (offset + optlen > nrecv)
				{
					/* Does not contain the full header */
					return;
				}
				nxt= opthdr->ip6e_nxt;
				ptr= ((char *)opthdr)+optlen;
			}
			if (nxt == IPPROTO_FRAGMENT)
			{
				/* Make sure the fragment header is completely
				 * there.
				 */
				offset= (u_char *)ptr - base->packet;
				if (offset + sizeof(*frag) > nrecv)
				{
#if 0
					fprintf(stderr,
			"ready_callback6: too short %d (FRAGMENT)\n",
						(int)nrecv);
#endif
					return;
				}
				frag= (struct ip6_frag *)ptr;
				if ((ntohs(frag->ip6f_offlg) & ~3) != 0)
				{
					/* Not first fragment, just ignore
					 * it.
					 */
					if (state->response_in)
					{
						/* Try again for the next
						 * packet
						 */
						ready_callback6(0, 0, state);
					}
					return;
				}
				nxt= frag->ip6f_nxt;
				ptr= &frag[1];
			}
			if (nxt == IPPROTO_DSTOPTS)
			{
				/* Make sure the options header is completely
				 * there.
				 */
				offset= (u_char *)ptr - base->packet;
				if (offset + sizeof(*opthdr) > nrecv)
				{
#if 0
					printf(
			"ready_callback6: too short %d (DSTOPTS)\n",
						(int)nrecv);
#endif
					return;
				}
				opthdr= (struct ip6_ext *)ptr;
				dstoptsize= 8*opthdr->ip6e_len;
				optlen= dstoptsize+8;
				if (offset + optlen > nrecv)
				{
					/* Does not contain the full header */
#if 0
					printf(
			"ready_callback6: too short %d (full DSTOPTS)\n",
						(int)nrecv);
#endif
					return;
				}
				nxt= opthdr->ip6e_nxt;
				ptr= ((char *)opthdr)+optlen;
			}

			v6info_siz= sizeof(*v6info);
			if (nxt == IPPROTO_TCP)
			{
				siz= sizeof(*etcp);
				v6info_siz= 0;
			}
			else if (nxt == IPPROTO_UDP)
				siz= sizeof(*eudp);
			else
				siz= sizeof(*eicmp);

			/* Now check if there is also a header in the
			 * packet.
			 */
			offset= (u_char *)ptr - base->packet;
			if (offset + siz + v6info_siz > nrecv)
			{
#if 0
				printf(
			"ready_callback6: too short %d (all) from %s\n",
					(int)nrecv, inet_ntop(AF_INET6,
					&remote.sin6_addr, buf, sizeof(buf)));
#endif
				return;
			}

			etcp= NULL;
			eudp= NULL;
			eicmp= NULL;
			v6info= NULL;
			if (nxt == IPPROTO_TCP)
			{
				etcp= (struct tcphdr *)ptr;
			}
			else if (nxt == IPPROTO_UDP)
			{
				eudp= (struct udphdr *)ptr;
				v6info= (struct v6info *)&eudp[1];
			}
			else
			{
				eicmp= (struct icmp6_hdr *)ptr;
				v6info= (struct v6info *)&eicmp[1];
			}

#if 0
			if (v6info)
			{
				printf(
"ready_callback6: pid = htonl(%d), id = htonl(%d), seq = htonl(%d)\n",
					ntohl(v6info->pid),
					ntohl(v6info->id),
					ntohl(v6info->seq));
			}
#endif

			if (etcp)
			{
				/* We store the id in high order 16 bits of the
				 * sequence number
				 */
				ind= ntohl(etcp->seq) >> 16;
			}
			else
			{
				if (ntohl(v6info->pid) != base->my_pid)
				{
					/* From a different process */
					return;
				}

				ind= ntohl(v6info->id);
			}

			if (ind != state->index)
				state= NULL;

			if (state && state->sin6.sin6_family != AF_INET6)
				state= NULL;

			if (state)
			{
				if ((etcp && !state->do_tcp) ||
					(eudp && !state->do_udp) ||
					(eicmp && !state->do_icmp))
				{
					state= NULL;	
				}
			}

			if (!state)
			{
				/* Nothing here */
				return;
			}

#if 0
			printf("ready_callback6: from %s",
				inet_ntop(AF_INET6, &remote.sin6_addr,
				buf, sizeof(buf)));
			printf(" for %s hop %d\n",
				inet_ntop(AF_INET6, &state->sin6.sin6_addr,
					buf, sizeof(buf)), state->hop);
#endif

			if (!state->busy)
			{
				printf(
			"ready_callback6: index (%d) is not busy\n",
					ind);
				return;
			}

			late= 0;
			isDup= 0;
			if (etcp)
			{
				/* Sequence number is in seq field */
				seq= ntohl(etcp->seq) & 0xffff;
			}
			else
				seq= ntohl(v6info->seq);

			if (state->open_result)
				add_str(state, " }, { ");

			if (seq != state->seq)
			{
				if (seq > state->seq)
				{
#if 0
					printf(
	"ready_callback6: mismatch for seq, got 0x%x, expected 0x%x\n",
						seq,
						state->seq);
#endif
					return;
				}
				late= 1;

				snprintf(line, sizeof(line), DBQ(late) ":%d",
					state->seq-seq);
				add_str(state, line);
			} else if (state->gotresp)
			{
				isDup= 1;
				add_str(state, DBQ(dup) ":true");
			}

			if (!late && !isDup)
				state->last_response_hop= state->hop;

			if (memcmp(&eip->ip6_src,
				&state->loc_sin6.sin6_addr,
				sizeof(eip->ip6_src)) != 0)
			{
				printf("ready_callback6: changed source %s\n",
					inet_ntop(AF_INET6, &eip->ip6_src,
					buf, sizeof(buf)));
			}
			if (memcmp(&eip->ip6_dst,
				&state->sin6.sin6_addr,
				sizeof(eip->ip6_dst)) != 0)
			{
				printf(
			"ready_callback6: changed destination %s for %s\n",
					inet_ntop(AF_INET6, &eip->ip6_dst,
					buf, sizeof(buf)),
					state->hostname);
			}
			if (memcmp(&dstaddr,
				&state->loc_sin6.sin6_addr,
				sizeof(dstaddr)) != 0)
			{
#if 0
			printf("ready_callback6: weird destination %s\n",
					inet_ntop(AF_INET6, &dstaddr,
					buf, sizeof(buf)));
#endif
			}

			if (eicmp && state->parismod &&
				ntohs(eicmp->icmp6_cksum) !=
				state->paris + 1)
			{
				fprintf(stderr,
			"ready_callback6: got checksum 0x%x, expected 0x%x\n",
					ntohs(eicmp->icmp6_cksum),
					state->paris + 1);
			}

			if (!late)
			{
				ms= (now.tv_sec-state->xmit_time.tv_sec)*1000 +
					(now.tv_nsec-state->xmit_time.tv_nsec)/
					1e6;
			}
			else if (v6info)
			{
				ms= (now.tv_sec-v6info->tv.tv_sec)*1000 +
					(now.tv_nsec-v6info->tv.tv_nsec)/1e6;
			}

			snprintf(line, sizeof(line), "%s" DBQ(from) ":" DBQ(%s),
				(late || isDup) ? ", " : "",
				inet_ntop(AF_INET6, &remote.sin6_addr,
				buf, sizeof(buf)));
			add_str(state, line);
			snprintf(line, sizeof(line),
				", " DBQ(ttl)":%d, " DBQ(rtt) ":%.3f, "
				DBQ(size) ":%d",
				rcvdttl, ms, (int)(nrecv-ICMP6_HDR));
			add_str(state, line);
			if (eip->ip6_hops != 1)
			{
				snprintf(line, sizeof(line),
					", " DBQ(ittl) ":%d", eip->ip6_hops);
				add_str(state, line);
			}
			if (IP6_TOS(eip) != 0 || state->tos != 0)
			{
				snprintf(line, sizeof(line),
					", " DBQ(itos) ":%d", IP6_TOS(eip));
				add_str(state, line);
			}

			if (hbhoptsize)
			{
				snprintf(line, sizeof(line),
					", " DBQ(hbhoptsize) ":%d",
					hbhoptsize);
				add_str(state, line);
			}
			if (dstoptsize)
			{
				snprintf(line, sizeof(line),
					", " DBQ(dstoptsize) ":%d",
					dstoptsize);
				add_str(state, line);
			}

#if 0
			printf("ready_callback6: from %s, ttl %d",
				inet_ntop(AF_INET6, &remote.sin6_addr, buf,
				sizeof(buf)), rcvdttl);
			printf(" for %s hop %d\n",
				inet_ntop(AF_INET6, &state->sin6.sin6_addr, buf,
				sizeof(buf)), state->hop);
#endif

			if (icmp->icmp6_type == ICMP6_TIME_EXCEEDED)
			{
				if (!late && !isDup)
					state->not_done= 1;
			}
			else if (icmp->icmp6_type == ICMP6_PACKET_TOO_BIG)
			{
				nextmtu= ntohl(icmp->icmp6_mtu);
				snprintf(line, sizeof(line),
					", " DBQ(mtu) ":%d", nextmtu);
				add_str(state, line);
				siz= sizeof(*eip);
				if (eudp)
					siz += sizeof(*eudp);
				else if (eicmp)
					siz += sizeof(*eicmp);
				else if (etcp)
					siz += sizeof(*etcp);
				if (nextmtu < 1200)
				{
					/* This is IPv6, no need to go 
					 * below 1280. Use 1200 to deal with
					 * off by one error or weird tunnels.
					 */
					nextmtu= 1200;
				}
				if (!late && nextmtu >= siz)
				{
					nextmtu -= siz;
					if (nextmtu < state->curpacksize)
						state->curpacksize= nextmtu;
				}
				if (!late)
					state->not_done= 1;
			}
			else if (icmp->icmp6_type == ICMP6_DST_UNREACH)
			{
				if (!late)
					state->done= 1;
				switch(icmp->icmp6_code)
				{
				case ICMP6_DST_UNREACH_NOROUTE:	/* 0 */
					add_str(state,
						", " DBQ(err) ":" DBQ(N));
					break;
				case ICMP6_DST_UNREACH_ADMIN:	/* 1 */
					add_str(state,
						", " DBQ(err) ":" DBQ(A));
					break;
				case ICMP6_DST_UNREACH_BEYONDSCOPE: /* 2 */
					add_str(state,
						", " DBQ(err) ":" DBQ(h));
					break;
				case ICMP6_DST_UNREACH_ADDR:	/* 3 */
					add_str(state,
						", " DBQ(err) ":" DBQ(H));
					break;
				case ICMP6_DST_UNREACH_NOPORT:	/* 4 */
					break;
				default:
					snprintf(line, sizeof(line),
						", " DBQ(err) ":%d",
						icmp->icmp6_code);
					add_str(state, line);
					break;
				}
			}
		}
		else
		{
			fprintf(stderr,
			"ready_callback6: not UDP or ICMP (ip6_nxt = %d)\n",
				eip->ip6_nxt);
			return;
		}

		/* RFC-4884, Multi-Part ICMP messages */
		icmp_prefixlen= icmp->icmp6_data8[0] * 8;
		if (icmp_prefixlen != 0)
		{
			
			printf("icmp6_data8[0]: 0x%x for %s\n", icmp->icmp6_data8[0], state->hostname);
			printf("icmp_prefixlen: 0x%x for %s\n", icmp_prefixlen, inet_ntop(AF_INET6, &state->sin6.sin6_addr, buf, sizeof(buf)));
			offset= sizeof(*icmp) + icmp_prefixlen;
			if (nrecv > offset)
			{
				do_icmp_multi(state, base->packet+offset,
					nrecv-offset, 0 /*!pre_rfc4884*/);
			}
			else
			{
#if 0
				printf(
			"ready_callback6: too short %d (Multi-Part ICMP)\n",
					(int)nrecv);
#endif
			}
		}
		else if (nrecv > 128)
		{
			/* Try old style extensions */
			icmp_prefixlen= 128;
			offset= sizeof(*icmp) + icmp_prefixlen;
			if (nrecv > offset)
			{
				do_icmp_multi(state, base->packet+offset,
					nrecv-offset, 1 /*pre_rfc4884*/);
			}
			else
			{
				printf(
			"ready_callback6: too short %d (Multi-Part ICMP)\n",
					(int)nrecv);
			}
		}

		state->open_result= 1;

		if (!late && !isDup)
		{
			if (state->duptimeout)
			{
				state->gotresp= 1;
				interval.tv_sec= state->duptimeout/1000000;
				interval.tv_usec= state->duptimeout % 1000000;
				evtimer_add(&state->timer, &interval);
			}
			else
			{
				send_pkt(state);
			}
		}
	}
	else if (icmp->icmp6_type == ICMP6_ECHO_REPLY)
	{
		eip= NULL;

		/* Now check if there is also a header in the packet */
		if (nrecv < sizeof(*icmp) + sizeof(*v6info))
		{
#if 0
			printf("ready_callback6: too short %d (echo reply)\n",
				(int)nrecv);
#endif
			return;
		}

		eudp= NULL;
		eicmp= NULL;

		v6info= (struct v6info *)&icmp[1];

		if (ntohl(v6info->pid) != base->my_pid)
		{
			/* From a different process */
			return;
		}

		ind= ntohl(v6info->id);

		if (ind != state->index)
			state= NULL;
		if (state && state->sin6.sin6_family != AF_INET6)
			state= NULL;

		if (state && !state->do_icmp)
		{
			state= NULL;	
		}

		if (!state)
		{
			/* Nothing here */
			return;
		}

#if 0
		printf("ready_callback6: from %s",
			inet_ntop(AF_INET6, &remote.sin6_addr,
			buf, sizeof(buf)));
		printf(" for %s hop %d\n",
			inet_ntop(AF_INET6, &state->sin6.sin6_addr,
				buf, sizeof(buf)), state->hop);
#endif

		if (!state->busy)
		{
			printf(
		"ready_callback6: index (%d) is not busy\n",
				ind);
			return;
		}

		if (state->open_result)
			add_str(state, " }, { ");

		late= 0;
		isDup= 0;
		seq= ntohl(v6info->seq);
		if (seq != state->seq)
		{
			if (seq > state->seq)
			{
				printf(
"ready_callback6: mismatch for seq, got 0x%x, expected 0x%x\n",
					ntohl(v6info->seq),
					state->seq);
				return;
			}
			late= 1;

			snprintf(line, sizeof(line), DBQ(late) ":%d",
				state->seq-seq);
			add_str(state, line);
		}
		else if (state->gotresp)
		{
			isDup= 1;
			add_str(state, DBQ(dup) ":true");
		}

		if (!late && !isDup)
		{
			state->last_response_hop= state->hop;
			state->done= 1;
		}

		if (memcmp(&dstaddr, &state->loc_sin6.sin6_addr,
			sizeof(dstaddr)) != 0)
		{
#if 0
			printf("ready_callback6: weird destination %s\n",
				inet_ntop(AF_INET6, &dstaddr,
				buf, sizeof(buf)));
#endif
		}

		if (!late)
		{
			ms= (now.tv_sec-state->xmit_time.tv_sec)*1000 +
				(now.tv_nsec-state->xmit_time.tv_nsec)/1e6;
		}
		else
		{
			ms= (now.tv_sec-v6info->tv.tv_sec)*1000 +
				(now.tv_nsec-v6info->tv.tv_nsec)/1e6;
		}

		snprintf(line, sizeof(line), "%s" DBQ(from) ":" DBQ(%s),
			(late || isDup) ? ", " : "",
			inet_ntop(AF_INET6, &remote.sin6_addr,
			buf, sizeof(buf)));
		add_str(state, line);
		snprintf(line, sizeof(line),
		", " DBQ(ttl) ":%d, " DBQ(rtt) ":%.3f, " DBQ(size) ":%d",
			rcvdttl, ms, (int)(nrecv - ICMP6_HDR));
		add_str(state, line);
		if (rcvdtclass != 0 || state->tos != 0)
		{
			snprintf(line, sizeof(line), ", " DBQ(itos) ":%d",
				rcvdtclass);
			add_str(state, line);
		}

#if 0
		printf("ready_callback6: from %s, ttl %d",
			inet_ntop(AF_INET6, &remote.sin6_addr, buf,
			sizeof(buf)), rcvdttl);
		printf(" for %s hop %d\n",
			inet_ntop(AF_INET6, &state->sin6.sin6_addr, buf,
			sizeof(buf)), state->hop);
#endif

		state->open_result= 1;

		if (!late && !isDup)
		{
			if (state->duptimeout)
			{
				state->gotresp= 1;
				interval.tv_sec= state->duptimeout/1000000;
				interval.tv_usec= state->duptimeout % 1000000;
				evtimer_add(&state->timer, &interval);
			}
			else
			{
				send_pkt(state);
			}
		}
	}
	else if (icmp->icmp6_type == ICMP6_ECHO_REQUEST /* 128 */ ||
		icmp->icmp6_type == MLD_LISTENER_QUERY /* 130 */ ||
		icmp->icmp6_type == MLD_LISTENER_REPORT /* 131 */ ||
		icmp->icmp6_type == ND_ROUTER_ADVERT /* 134 */ ||
		icmp->icmp6_type == ND_NEIGHBOR_SOLICIT /* 135 */ ||
		icmp->icmp6_type == ND_NEIGHBOR_ADVERT /* 136 */ ||
		icmp->icmp6_type == ND_REDIRECT /* 137 */)
	{
		if (state->response_in)
		{
			/* Try again for the next packet */
			ready_callback6(0, 0, state);
		}

		/* No need to do anything */
	}
	else
	{
		printf("ready_callback6: got type %d\n", icmp->icmp6_type);
		return;
	}
}

static struct trtbase *traceroute_base_new(struct event_base
	*event_base)
{
	struct trtbase *base;

	base= xzalloc(sizeof(*base));

	base->event_base= event_base;

	base->tabsiz= 10;
	base->table= xzalloc(base->tabsiz * sizeof(*base->table));

	base->my_pid= getpid();

	return base;
}

static void noreply_callback(int __attribute((unused)) unused,
	const short __attribute((unused)) event, void *s)
{
	struct trtstate *state;

	state= s;

	if (!state->gotresp)
	{
		if (state->open_result)
			add_str(state, " }, { ");
		add_str(state, DBQ(x) ":" DBQ(*));
		state->open_result= 1;

		if (state->resp_file_out)
		{
			/* Use a zero proto to signal a timeout */
			uint8_t proto= 0;

			write_response(state->resp_file_out, RESP_PROTO,
				sizeof(proto), &proto);
		}
	}

	if (state->response_in)
	{
		if (state->sin6.sin6_family == AF_INET6)
			ready_callback6(0, 0, state);
		else
			ready_callback4(0, 0, state);
	}
	else
	{
		send_pkt(state);
	}
}

static void *traceroute_init(int __attribute((unused)) argc, char *argv[],
	void (*done)(void *state, int error))
{
	uint16_t destport;
	uint32_t opt;
	int i, do_icmp, do_v6, dont_fragment, delay_name_res, do_tcp, do_udp;
	int tos;
	unsigned count, duptimeout, firsthop, gaplimit, maxhops, maxpacksize,
		hbhoptsize, destoptsize, parismod, parisbase, timeout;
		/* must be int-sized */
	size_t newsiz;
	char *str_Atlas;
	char *str_bundle;
	const char *hostname;
	char *out_filename;
	const char *destportstr;
	char *response_in, *response_out;
	char *interface;
	char *check;
	char *validated_response_in= NULL;
	char *validated_response_out= NULL;
	char *validated_out_filename= NULL;
	struct trtstate *state;
	sa_family_t af;
	len_and_sockaddr *lsa;
	FILE *fh;

	if (!trt_base)
	{
		trt_base= traceroute_base_new(EventBase);
		if (!trt_base)
			crondlog(DIE9 "traceroute_base_new failed");
	}

	/* Parse arguments */
	count= 3;
	firsthop= 1;
	gaplimit= 5;
	interface= NULL;
	maxhops= 32;
	maxpacksize= 40;
	destportstr= "80";
	duptimeout= 10;
	timeout= 1000;
	parismod= 16;
	parisbase= 0;
	hbhoptsize= 0;
	destoptsize= 0;
	tos= 0;
	str_Atlas= NULL;
	str_bundle= NULL;
	out_filename= NULL;
	response_in= NULL;
	response_out= NULL;
	opt_complementary = "=1:4--6:i--u:a+:b+:c+:f+:g+:m+:t+:w+:z+:S+:H+:D+";

	opt = getopt32(argv, TRACEROUTE_OPT_STRING, &parismod, &parisbase,
		&count,
		&firsthop, &gaplimit, &interface, &maxhops, &destportstr,
		&tos, &timeout, &duptimeout,
		&str_Atlas, &str_bundle, &out_filename, &maxpacksize,
		&hbhoptsize, &destoptsize, &response_in, &response_out);
	hostname = argv[optind];

	if (opt == 0xffffffff)
	{
		crondlog(LVL8 "bad options");
		return NULL;
	}

	do_icmp= !!(opt & OPT_I);
	do_v6= !!(opt & OPT_6);
	dont_fragment= !!(opt & OPT_F);
	delay_name_res= !!(opt & OPT_r);
	delay_name_res= 1;	/* Always enabled, leave the old code in
				 * place for now.
				 */
	do_tcp= !!(opt & OPT_T);
	do_udp= !(do_icmp || do_tcp);
	if (maxpacksize > MAX_DATA_SIZE)
	{
		crondlog(LVL8 "max. packet size too big");
		return NULL;
	}

	if (response_in)
	{
		validated_response_in= rebased_validated_filename(ATLAS_SPOOLDIR,
			response_in, ATLAS_FUZZING_REL);
		if (!validated_response_in)
		{
			crondlog(LVL8 "insecure fuzzing file '%s'",
				response_in);
			goto err;
		}
	}
	if (response_out)
	{
		validated_response_out= rebased_validated_filename(ATLAS_SPOOLDIR,
			response_out, ATLAS_FUZZING_REL);
		if (!validated_response_out)
		{
			crondlog(LVL8 "insecure fuzzing file '%s'",
				response_out);
			goto err;
		}
	}

	if (out_filename)
	{
		validated_out_filename= rebased_validated_filename(ATLAS_SPOOLDIR,
			out_filename, SAFE_PREFIX_REL);
		if (!validated_out_filename)
		{
			crondlog(LVL8 "insecure file '%s'", out_filename);
			goto err;
		}
		fh= fopen(validated_out_filename, "a");
		if (!fh)
		{
			crondlog(LVL8 "traceroute: unable to append to '%s'",
				validated_out_filename);
			goto err;
		}
		fclose(fh);
	}

	if (str_Atlas)
	{
		if (!validate_atlas_id(str_Atlas))
		{
			crondlog(LVL8 "bad atlas ID '%s'", str_Atlas);
			goto err;
		}
	}
	if (str_bundle)
	{
		if (!validate_atlas_id(str_bundle))
		{
			crondlog(LVL8 "bad bundle ID '%s'", str_bundle);
			goto err;
		}
	}

	if (!delay_name_res)
	{
		/* Attempt to resolve 'name' */
		af= do_v6 ? AF_INET6 : AF_INET;
		destport= strtoul(destportstr, &check, 0);
		if (check[0] != '\0' || destport == 0)
			goto err;
		lsa= host_and_af2sockaddr(hostname, destport, af);
		if (!lsa)
			goto err;

		if (lsa->len > sizeof(state->sin6))
		{
			free(lsa);
			goto err;
		}

		if (atlas_check_addr(&lsa->u.sa, lsa->len) == -1)
		{
			free(lsa);
			goto err;
		}
	}
	else
	{
		/* lint */
		lsa= NULL;
		af= -1;
	}

	state= xzalloc(sizeof(*state));
	state->parismod= parismod;
	state->parisbase= parisbase;
	state->trtcount= count;
	state->firsthop= firsthop;
	state->maxpacksize= maxpacksize;
	state->maxhops= maxhops;
	state->gaplimit= gaplimit;
	state->interface= interface ? strdup(interface) : NULL;
	state->destportstr= strdup(destportstr);
	state->duptimeout= duptimeout*1000;
	state->timeout= timeout*1000;
	state->tos= tos;
	state->atlas= str_Atlas ? strdup(str_Atlas) : NULL;
	state->bundle_id= str_bundle ? strdup(str_bundle) : NULL;
	state->hostname= strdup(hostname);
	state->do_icmp= do_icmp;
	state->do_tcp= do_tcp;
	state->do_udp= do_udp;
	state->do_v6= do_v6;
	state->dont_fragment= dont_fragment;
	state->delay_name_res= delay_name_res;
	state->hbhoptsize= hbhoptsize;
	state->destoptsize= destoptsize;
	state->out_filename= validated_out_filename;
		validated_out_filename= NULL;
	state->response_in= validated_response_in;
		validated_response_in= NULL;
	state->response_out= validated_response_out;
		validated_response_out= NULL;
	state->base= trt_base;
	state->paris= state->parisbase;
	state->busy= 0;
	state->result= NULL;
	state->reslen= 0;
	state->resmax= 0;
	state->socket_icmp= -1;
	state->socket_tcp= -1;

	if (response_in || response_out)
		trt_base->my_pid= 42;

	for (i= 0; i<trt_base->tabsiz; i++)
	{
		if (trt_base->table[i] == NULL)
			break;
	}
	if (i >= trt_base->tabsiz)
	{
		newsiz= 2*trt_base->tabsiz;
		trt_base->table= xrealloc(trt_base->table,
			newsiz*sizeof(*trt_base->table));
		for (i= trt_base->tabsiz; i<newsiz; i++)
			trt_base->table[i]= NULL;
		i= trt_base->tabsiz;
		trt_base->tabsiz= newsiz;
	}
	state->index= i;
	trt_base->table[i]= state;
	trt_base->done= done;

	memset(&state->loc_sin6, '\0', sizeof(state->loc_sin6));
	state->loc_socklen= 0;

	if (!delay_name_res)
	{
		memcpy(&state->sin6, &lsa->u.sa, lsa->len);
		state->socklen= lsa->len;
		free(lsa); lsa= NULL;
		if (af == AF_INET6)
		{
			char buf[INET6_ADDRSTRLEN];
			printf("traceroute_init: %s, len %d for %s\n",
				inet_ntop(AF_INET6, &state->sin6.sin6_addr,
				buf, sizeof(buf)), state->socklen,
				state->hostname);
		}
	}

	evtimer_assign(&state->timer, state->base->event_base,
		noreply_callback, state);

	return state;

err:
	if (validated_response_in) free(validated_response_in);
	if (validated_response_out) free(validated_response_out);
	if (validated_out_filename) free(validated_out_filename);
	return NULL;
}

static void traceroute_start2(void *state)
{
	struct trtstate *trtstate;
	char line[80];

	trtstate= state;

	if (!trtstate->busy)
	{
		printf("traceroute_start: not busy, can't continue\n");
		return;
	}
	trtstate->busy= 1;

	trtstate->min= ULONG_MAX;
	trtstate->max= 0;
	trtstate->sum= 0;
	trtstate->sentpkts= 0;
	trtstate->rcvdpkts= 0;
	trtstate->duppkts= 0;

	trtstate->hop= trtstate->firsthop;
	trtstate->sent= 0;
	trtstate->seq= 0;
	if (trtstate->parismod)
	{
		trtstate->paris= (trtstate->paris-trtstate->parisbase+1+
			trtstate->parismod) % trtstate->parismod +
			trtstate->parisbase;
	}
	trtstate->last_response_hop=
		(trtstate->firsthop > 1 ? trtstate->firsthop-1 : 0);
	trtstate->done= 0;
	trtstate->not_done= 0;
	trtstate->lastditch= 0;
	trtstate->curpacksize= trtstate->maxpacksize;

	if (trtstate->result) free(trtstate->result);
	trtstate->resmax= 80;
	trtstate->result= xmalloc(trtstate->resmax);
	trtstate->reslen= 0;
	trtstate->open_result= 0;
	trtstate->starttime= atlas_time();

	trtstate->socket_tcp= -1;

	snprintf(line, sizeof(line), "{ " DBQ(hop) ":%d", trtstate->hop);
	add_str(trtstate, line);

	if (trtstate->do_icmp)
	{
		if (create_socket(trtstate, 0 /*do_tcp*/) == -1)
			return;
	}
	else if (trtstate->do_udp)
	{
		if (create_socket(trtstate, 0 /*do_tcp*/) == -1)
			return;
		if (trtstate->do_v6)
		{
			trtstate->loc_sin6.sin6_port= htons(SRC_BASE_PORT +
                                trtstate->index);
		}
		else
		{
			((struct sockaddr_in *)(&trtstate->loc_sin6))->
				sin_port= htons(SRC_BASE_PORT +
                                trtstate->index);
		}
	}
	else if (trtstate->do_tcp)
	{
		if (create_socket(trtstate, 1 /*do_tcp*/) == -1)
			return;

		if (trtstate->do_v6)
		{
			trtstate->loc_sin6.sin6_port= htons(SRC_BASE_PORT +
                                trtstate->index);
		}
		else
		{
			((struct sockaddr_in *)(&trtstate->loc_sin6))->
				sin_port= htons(SRC_BASE_PORT +
                                trtstate->index);
		}
	}

	add_str(trtstate, ", " DBQ(result) ": [ ");

	send_pkt(trtstate);

	if (trtstate->response_in)
	{
		for (;;)
		{
			if (trtstate->sin6.sin6_family == AF_INET6)
				ready_callback6(0, 0, state);
			else
				ready_callback4(0, 0, state);
		}
	}
}

static int create_socket(struct trtstate *state, int do_tcp)
{
	int af, type, protocol;
	int r, on, serrno;
	char line[80];

	af= (state->do_v6 ? AF_INET6 : AF_INET);
	type= SOCK_RAW;
	protocol= (af == AF_INET6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP);

	if (!state->response_in)
		state->socket_icmp= xsocket(af, type, protocol);
	if (state->socket_icmp == -1)
	{
		serrno= errno;

		snprintf(line, sizeof(line),
	", " DBQ(error) ":" DBQ(socket failed: %s) " }",
			strerror(serrno));
		add_str(state, line);
		report(state);
		return -1;
	} 

	if (state->interface)
	{
		if (bind_interface(state->socket_icmp,
			af, state->interface) == -1)
		{
			crondlog(LVL7 "binding to interface '%s' failed with '%s'", state->interface, strerror(errno));

			snprintf(line, sizeof(line),
	", " DBQ(error) ":" DBQ(bind_interface failed) " }");
			add_str(state, line);
			report(state);
			return -1;
		}
	}

	if (state->response_in)
		r= 0;	/* Don't try to connect when reading from a file */
	else
	{
		r= connect(state->socket_icmp,
			(struct sockaddr *)&state->sin6,
			state->socklen);
	}
#if 0
 { errno= ENOSYS; r= -1; }
#endif
	if (r == -1)
	{
		serrno= errno;

		snprintf(line, sizeof(line),
	", " DBQ(error) ":" DBQ(connect failed: %s) " }",
			strerror(serrno));
		add_str(state, line);
		report(state);
		return -1;
	}
	if (state->response_in)
	{
		size_t len;

		len= sizeof(state->loc_sin6);
		read_response(state->socket_icmp, RESP_SOCKNAME,
			&len, &state->loc_sin6);
		state->loc_socklen= len;
	}
	else
	{
		state->loc_socklen= sizeof(state->loc_sin6);
		if (!state->response_in && getsockname(state->socket_icmp,
			(struct sockaddr *)&state->loc_sin6,
			&state->loc_socklen) == -1)
		{
			crondlog(DIE9 "getsockname failed");
		}
	}
	if (state->resp_file_out)
	{
		write_response(state->resp_file_out, RESP_SOCKNAME,
			state->loc_socklen, &state->loc_sin6);
	}

	if (!state->response_in)
	{
		close(state->socket_icmp);
		state->socket_icmp= xsocket(af, type,
			protocol);
	}
	if (state->socket_icmp == -1)
	{
		serrno= errno;

		snprintf(line, sizeof(line),
	", " DBQ(error) ":" DBQ(socket failed: %s) " }",
			strerror(serrno));
		add_str(state, line);
		report(state);
		return -1;
	} 

	if (af == AF_INET6)
	{
		on = 1;
		setsockopt(state->socket_icmp, IPPROTO_IPV6,
			IPV6_RECVPKTINFO, &on, sizeof(on));

		on = 1;
		setsockopt(state->socket_icmp, IPPROTO_IPV6,
			IPV6_RECVHOPLIMIT, &on, sizeof(on));

		on = 1;
		setsockopt(state->socket_icmp, IPPROTO_IPV6,
			IPV6_RECVTCLASS, &on, sizeof(on));
	}

	if (state->interface)
	{
		if (bind_interface(state->socket_icmp,
			af, state->interface) == -1)
		{
			snprintf(line, sizeof(line),
	", " DBQ(error) ":" DBQ(bind_interface failed) " }");
			add_str(state, line);
			report(state);
			return -1;
		}
	}

	if (set_tos(state, state->socket_icmp, af, 0 /*!inner*/) == -1)
		return -1;

	event_assign(&state->event_icmp, state->base->event_base,
		state->socket_icmp,
		EV_READ | EV_PERSIST,
		(af == AF_INET6 ? ready_callback6 : ready_callback4),
		state);
	if (!state->response_in)
		event_add(&state->event_icmp, NULL);

	if (do_tcp)
	{
		if (state->response_in)
			state->socket_tcp= open("/dev/null", O_RDWR);
		else
			state->socket_tcp= xsocket(af, SOCK_RAW, IPPROTO_TCP);
		if (state->socket_tcp == -1)
		{
			serrno= errno;

			snprintf(line, sizeof(line),
		", " DBQ(error) ":" DBQ(socket failed: %s) " }",
				strerror(serrno));
			add_str(state, line);
			report(state);
			return -1;
		} 

		if (af == AF_INET6)
		{
			on = 1;
			setsockopt(state->socket_tcp, IPPROTO_IPV6,
				IPV6_RECVHOPLIMIT, &on, sizeof(on));
			on = 1;
			setsockopt(state->socket_tcp, IPPROTO_IPV6,
				IPV6_RECVTCLASS, &on, sizeof(on));
		}

		if (state->interface)
		{
			if (bind_interface(state->socket_tcp,
				af, state->interface) == -1)
			{
				snprintf(line, sizeof(line),
		", " DBQ(error) ":" DBQ(bind_interface failed) " }");
				add_str(state, line);
				report(state);
				return -1;
			}
		}

		if (state->response_in)
			r= 0;	/* No need to connect */
		else
		{
			r= connect(state->socket_tcp,
				(struct sockaddr *)&state->sin6,
				state->socklen);
		}
#if 0
 { errno= ENOSYS; r= -1; }
#endif
		if (r == -1)
		{
			serrno= errno;

			snprintf(line, sizeof(line),
		", " DBQ(error) ":" DBQ(connect failed: %s) " }",
				strerror(serrno));
			add_str(state, line);
			report(state);
			return -1;
		}

		event_assign(&state->event_tcp, state->base->event_base,
			state->socket_tcp,
			EV_READ | EV_PERSIST,
			(af == AF_INET6 ? ready_tcp6 : ready_tcp4),
			state);
		if (!state->response_in)
			event_add(&state->event_tcp, NULL);
	}

	return 0;
}

static void dns_cb(int result, struct evutil_addrinfo *res, void *ctx)
{
	int r;
	size_t tmp_len;
	struct trtstate *env;
	double nsecs;
	struct timespec now, elapsed;
	char line[160];
	struct addrinfo tmp_res;
	struct sockaddr_storage tmp_sockaddr;

	env= ctx;

	if (!env->dnsip)
	{
		crondlog(LVL7
			"dns_cb: in dns_cb but not doing dns at this time");
		if (res)
			evutil_freeaddrinfo(res);
		return;
	}

	gettime_mono(&now);
	elapsed.tv_sec= now.tv_sec - env->start_time.tv_sec;
	if (now.tv_nsec < env->start_time.tv_sec)
	{
		elapsed.tv_sec--;
		now.tv_nsec += 1000000000;
	}
	elapsed.tv_nsec= now.tv_nsec - env->start_time.tv_nsec;
	nsecs= (elapsed.tv_sec * 1e9 + elapsed.tv_nsec);
	env->ttr= nsecs/1e6;

	if (result != 0)
	{
		/* Hmm, great. Where do we put this init code */
		if (env->result) free(env->result);
		env->resmax= 80;
		env->result= xmalloc(env->resmax);
		env->reslen= 0;

		env->starttime= time(NULL);
		snprintf(line, sizeof(line),
		"{ " DBQ(error) ":" DBQ(name resolution failed: %s) " }",
			evutil_gai_strerror(result));
		add_str(env, line);
		report(env);
		return;
	}

	env->dnsip= 0;
	env->no_src= 0;

	env->dns_res= res;
	env->dns_curr= res;

	if (env->response_in)
	{
		env->socket_icmp= open(env->response_in, O_RDONLY);
		if (env->socket_icmp == -1)
		{
			crondlog(DIE9 "unable to open '%s'",
				env->response_in);
		}
	
		tmp_len= sizeof(tmp_res);
		read_response(env->socket_icmp, RESP_ADDRINFO,
			&tmp_len, &tmp_res);
		assert(tmp_len == sizeof(tmp_res));
		tmp_len= sizeof(tmp_sockaddr);
		read_response(env->socket_icmp, RESP_ADDRINFO_SA,
			&tmp_len, &tmp_sockaddr);
		assert(tmp_len == tmp_res.ai_addrlen);
		tmp_res.ai_addr= (struct sockaddr *)&tmp_sockaddr;
		env->dns_curr= &tmp_res;
	}


	while (env->dns_curr)
	{
		if (env->response_out)
		{
			write_response(env->resp_file_out, RESP_ADDRINFO,
				sizeof(*env->dns_curr), env->dns_curr);
			write_response(env->resp_file_out, RESP_ADDRINFO_SA,
				env->dns_curr->ai_addrlen,
				env->dns_curr->ai_addr);
		}

		env->socklen= env->dns_curr->ai_addrlen;
		if (env->socklen > sizeof(env->sin6))
			break;	/* Weird */
		memcpy(&env->sin6, env->dns_curr->ai_addr,
			env->socklen);

		r= atlas_check_addr((struct sockaddr *)&env->sin6,
			env->socklen);
		if (r == -1)
		{
			if (env->result) free(env->result);
			env->resmax= 80;
			env->result= xmalloc(env->resmax);
			env->reslen= 0;

			env->starttime= time(NULL);
			snprintf(line, sizeof(line),
			"{ " DBQ(error) ":" DBQ(address not allowed) " }");
			add_str(env, line);
			env->no_src= 1;
			report(env);
			return;
		}

		traceroute_start2(env);

		if (!env->response_in)
			evutil_freeaddrinfo(env->dns_res);

		env->dns_res= NULL;
		env->dns_curr= NULL;
		
		return;
	}

	/* Something went wrong */
	if (!env->response_in)
		evutil_freeaddrinfo(env->dns_res);
	env->dns_res= NULL;
	env->dns_curr= NULL;
	snprintf(line, sizeof(line),
"%s{ " DBQ(error) ":" DBQ(name resolution failed: out of addresses) " } ] }",
		env->sent ? " }, " : "");
	add_str(env, line);
	report(env);
}

static void traceroute_start(void *state)
{
	struct trtstate *trtstate;
	struct evutil_addrinfo hints;

	trtstate= state;

	if (trtstate->busy)
	{
		printf("traceroute_start: busy, can't start\n");
		return;
	}
	trtstate->busy= 1;
	trtstate->socket_icmp= -1;

	if (trtstate->response_out)
	{
		trtstate->resp_file_out= fopen(trtstate->response_out, "w");
		if (!trtstate->resp_file_out)
		{
			crondlog(DIE9 "unable to write to '%s'",
				trtstate->response_out);
		}
	}


	if (!trtstate->delay_name_res)
	{
		traceroute_start2(state);
		return;
	}

	gettime_mono(&trtstate->start_time);
	trtstate->dnsip= 1;
	if (trtstate->response_in)
	{
		dns_cb(0, 0, trtstate);
	}
	else
	{
		memset(&hints, '\0', sizeof(hints));
		hints.ai_socktype= SOCK_DGRAM;
		hints.ai_family= trtstate->do_v6 ? AF_INET6 : AF_INET;
		(void) evdns_getaddrinfo(DnsBase, trtstate->hostname,
			trtstate->destportstr, &hints, dns_cb, trtstate);
	}
}

static int traceroute_delete(void *state)
{
	int ind;
	struct trtstate *trtstate;
	struct trtbase *base;

	trtstate= state;

	printf("traceroute_delete: state %p, index %d, busy %d\n",
		state, trtstate->index, trtstate->busy);

	if (trtstate->busy)
		return 0;

	base= trtstate->base;
	ind= trtstate->index;

	if (base->table[ind] != trtstate)
		crondlog(DIE9 "strange, state not in table");
	base->table[ind]= NULL;

	event_del(&trtstate->timer);

	free(trtstate->atlas);
	trtstate->atlas= NULL;
	free(trtstate->interface);
	trtstate->interface= NULL;
	free(trtstate->bundle_id);
	trtstate->bundle_id= NULL;
	free(trtstate->hostname);
	trtstate->hostname= NULL;
	free(trtstate->destportstr);
	trtstate->destportstr= NULL;
	free(trtstate->out_filename);
	trtstate->out_filename= NULL;

	free(trtstate);

	return 1;
}

struct testops traceroute_ops = { traceroute_init, traceroute_start,
	traceroute_delete };

