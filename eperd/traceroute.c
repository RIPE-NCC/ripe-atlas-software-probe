/*
 * Copyright (c) 2013-2014 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * traceroute.c
 */

#include "libbb.h"
#include <event2/dns.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "eperd.h"

#define SAFE_PREFIX ATLAS_DATA_NEW

#define DBQ(str) "\"" #str "\""

#ifndef STANDALONE_BUSYBOX
#define uh_sport source
#define uh_dport dest
#define uh_ulen len
#define uh_sum check
#endif

#define TRACEROUTE_OPT_STRING ("!46IUFrTa:b:c:f:g:i:m:p:w:z:A:O:S:H:D:")

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
	void (*done)(void *state);

	u_char packet[MAX_DATA_SIZE];
};

struct trtstate
{
	/* Parameters */
	char *atlas;
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
	struct evutil_addrinfo *dns_res;
	struct evutil_addrinfo *dns_curr;

	time_t starttime;
	struct timeval xmit_time;

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
	struct timeval tv;
};

static int create_socket(struct trtstate *state, int do_tcp);

#define OPT_PAD1 0
#define OPT_PADN 1
static void do_hbh_dest_opt(struct trtbase *base, int sock, int hbh_dest,
	unsigned size)
{
	int i;
	size_t totsize, ehlen, padlen;

	if (size == 0)
	{
		setsockopt(sock, IPPROTO_IPV6,
			hbh_dest ? IPV6_DSTOPTS : IPV6_HOPOPTS, NULL, 0);
		return;
	}

	/* Compute the totsize we need */
	totsize = 2 + size;
	if (totsize % 8)
		totsize += 8 - (totsize % 8);

	/* Consistency check */
	if (totsize > sizeof(base->packet))
		return;

	ehlen= totsize/8 - 1;
	if (ehlen > 255)
		return;

	memset(base->packet, '\0', totsize);
	base->packet[1]= ehlen;
	for (i= 2; i<totsize;)
	{
		padlen= totsize-i;
		if (padlen == 1)
		{
			base->packet[i]= OPT_PAD1;
			i++;
			continue;
		}
		padlen -= 2;
		if (padlen > 255)
			padlen= 255;
		base->packet[i]= OPT_PADN;
		base->packet[i+1]= padlen;
		i += 2+padlen;
	}
	if (hbh_dest)
	{
		setsockopt(sock, IPPROTO_IPV6, IPV6_DSTOPTS, base->packet,
			totsize);
	}
	else
	{
		setsockopt(sock, IPPROTO_IPV6, IPV6_HOPOPTS, base->packet,
			totsize);
	}
}

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
	FILE *fh;
	const char *proto;
	char namebuf[NI_MAXHOST];

	event_del(&state->timer);

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
			", " DBQ(time) ":%ld"
			", " DBQ(endtime) ":%ld, ",
			state->atlas, get_atlas_fw_version(),
			get_timesync(),
			state->starttime,
			(long)time(NULL));
	}

	fprintf(fh, DBQ(dst_name) ":" DBQ(%s),
		state->hostname);

	if (!state->dnsip)
	{
		getnameinfo((struct sockaddr *)&state->sin6, state->socklen,
			namebuf, sizeof(namebuf), NULL, 0, NI_NUMERICHOST);

		fprintf(fh, ", " DBQ(dst_addr) ":" DBQ(%s), namebuf);

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

	fprintf(fh, ", \"size\":%d", state->maxpacksize);
	if (state->parismod)
	{
		fprintf(fh, ", \"paris_id\":%d", state->paris);
	}
	fprintf(fh, ", \"result\": [ %s ] }\n", state->result);

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
		state->base->done(state);
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

	state->gotresp= 0;

	base= state->base;

	if (state->sent >= state->trtcount)
	{
		add_str(state, " } ] }");
		if (state->hop >= state->maxhops ||
			(state->done && !state->not_done))
		{
			/* We are done */
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

	gettimeofday(&state->xmit_time, NULL);

	if (state->sin6.sin6_family == AF_INET6)
	{
		hop= state->hop;

		if (state->do_tcp)
		{
			sock= socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
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
				do_hbh_dest_opt(base, sock, 0 /* hbh */,
					 state->hbhoptsize);
			}
			if (state->destoptsize != 0)
			{
				do_hbh_dest_opt(base, sock, 1 /* dest */,
					 state->destoptsize);
			}
#endif

			/* Bind to source addr/port */
			r= bind(sock,
				(struct sockaddr *)&state->loc_sin6,
				state->loc_socklen);
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

			tcphdr->seq= htonl((state->index) << 16 | state->seq);
			tcphdr->doff= len / 4;
			tcphdr->syn= 1;

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
			tcphdr->source= state->loc_sin6.sin6_port;
			tcphdr->dest= state->sin6.sin6_port;
			tcphdr->uh_sum= 0;

			sum= in_cksum_icmp6(&v6_ph, 
				(unsigned short *)base->packet, len);
			
			tcphdr->check= sum;

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
			r= sendto(sock, base->packet, len, 0,
				(struct sockaddr *)&sin6copy,
				state->socklen);

#if 0
 { static int doit=1; if (doit && r != -1)
 	{ errno= ENOSYS; r= -1; } doit= !doit; }
#endif
			serrno= errno;
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

			do_hbh_dest_opt(base, state->socket_icmp, 0 /* hbh */,
					 state->hbhoptsize);
			do_hbh_dest_opt(base, state->socket_icmp, 1 /* dest */,
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
			r= sendto(state->socket_icmp, base->packet, len, 0,
				(struct sockaddr *)&sin6copy,
				sizeof(sin6copy));

#if 0
 { static int doit=1; if (doit && r != -1)
 	{ errno= ENOSYS; r= -1; } doit= !doit; }
#endif

			if (r == -1)
			{
				if (errno != EMSGSIZE)
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
		else if (state->do_udp)
		{
			sock= socket(AF_INET6, SOCK_DGRAM, 0);
			if (sock == -1)
			{
				crondlog(DIE9 "socket failed");
			}

			on= 1;
			setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on,
				sizeof(on));

			if (state->hbhoptsize != 0)
			{
				do_hbh_dest_opt(base, sock, 0 /* hbh */,
					 state->hbhoptsize);
			}
			if (state->destoptsize != 0)
			{
				do_hbh_dest_opt(base, sock, 1 /* dest */,
					 state->destoptsize);
			}

			/* Bind to source addr/port */
			r= bind(sock,
				(struct sockaddr *)&state->loc_sin6,
				state->loc_socklen);
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

			r= sendto(sock, base->packet, len, 0,
				(struct sockaddr *)&state->sin6,
				state->socklen);

#if 0
 { static int doit=1; if (doit && r != -1)
 	{ errno= ENOSYS; r= -1; } doit= !doit; }
#endif
			serrno= errno;
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
			sock= socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
			if (sock == -1)
			{
				crondlog(DIE9 "socket failed");
			}

			on= 1;
			setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on,
				sizeof(on));

			/* Bind to source addr/port */
			r= bind(sock,
				(struct sockaddr *)&state->loc_sin6,
				state->loc_socklen);
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

			tcphdr->seq= htonl((state->index) << 16 | state->seq);
			tcphdr->doff= len / 4;
			tcphdr->syn= 1;

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
			tcphdr->source=
				((struct sockaddr_in *)&state->loc_sin6)->
				sin_port;
			tcphdr->dest= ((struct sockaddr_in *)&state->sin6)->
				sin_port;
			tcphdr->uh_sum= 0;

			sum= in_cksum_udp(&v4_ph, NULL,
				(unsigned short *)base->packet, len);
			
			tcphdr->check= sum;

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

			r= sendto(sock, base->packet, len, 0,
				(struct sockaddr *)&state->sin6,
				state->socklen);

#if 0
 { static int doit=0; if (doit && r != -1)
 	{ errno= ENOSYS; r= -1; } doit= !doit; }
#endif

			serrno= errno;
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

			if (state->curpacksize+ICMP_MINLEN < len)
				state->curpacksize= len-ICMP_MINLEN;
			if (state->curpacksize+ICMP_MINLEN > len)
			{
				memset(&base->packet[len], '\0',
					state->curpacksize-ICMP_MINLEN-len);
				strcpy((char *)&base->packet[len], id);
				len= state->curpacksize+ICMP_MINLEN;
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

			r= sendto(state->socket_icmp, base->packet, len, 0,
				(struct sockaddr *)&state->sin6,
				state->socklen);

#if 0
 { static int doit=1; if (doit && r != -1)
 	{ errno= ENOSYS; r= -1; } doit= !doit; }
#endif

			if (r == -1)
			{
				if (errno != EMSGSIZE)
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

			/* Bind to source addr/port */
			r= bind(sock,
				(struct sockaddr *)&state->loc_sin6,
				state->loc_socklen);
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

			r= sendto(sock, base->packet, len, 0,
				(struct sockaddr *)&state->sin6,
				state->socklen);

#if 0
 { static int doit=0; if (doit && r != -1)
 	{ errno= ENOSYS; r= -1; } doit= !doit; }
#endif

			serrno= errno;
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
	struct timeval now, interval;
	struct sockaddr_in remote;
	char line[80];

	gettimeofday(&now, NULL);

	state= s;
	base= state->base;

	slen= sizeof(remote);
	nrecv= recvfrom(state->socket_icmp, base->packet, sizeof(base->packet),
		MSG_DONTWAIT, (struct sockaddr *)&remote, &slen);
	if (nrecv == -1)
	{
		/* Strange, read error */
		printf("ready_callback4: read error '%s'\n", strerror(errno));
		return;
	}
	// printf("ready_callback4: got packet\n");

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
			srcport= ntohs(etcp->source);
			if (srcport < SRC_BASE_PORT ||
				srcport > SRC_BASE_PORT+256)
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
				(now.tv_usec-state->xmit_time.tv_usec)/1e3;

			snprintf(line, sizeof(line), "%s\"from\":\"%s\"",
				(late || isDup) ? ", " : "",
				inet_ntoa(remote.sin_addr));
			add_str(state, line);
			snprintf(line, sizeof(line),
				", \"ttl\":%d, \"size\":%d",
				ip->ip_ttl, (int)nrecv - IPHDR - ICMP_MINLEN);
			add_str(state, line);
			if (!late)
			{
				snprintf(line, sizeof(line), ", \"rtt\":%.3f",
					ms);
				add_str(state, line);
			}

			if (eip->ip_ttl != 1)
			{
				snprintf(line, sizeof(line), ", \"ittl\":%d",
					eip->ip_ttl);
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
					", \"edst\":\"%s\"",
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
					add_str(state, ", \"err\":\"N\"");
					break;
				case ICMP_UNREACH_HOST:
					add_str(state, ", \"err\":\"H\"");
					break;
				case ICMP_UNREACH_PROTOCOL:
					add_str(state, ", \"err\":\"P\"");
					break;
				case ICMP_UNREACH_PORT:
					break;
				case ICMP_UNREACH_NEEDFRAG:
					nextmtu= ntohs(icmp->icmp_nextmtu);
					snprintf(line, sizeof(line),
						", \"mtu\":%d",
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
printf("curpacksize: %d\n", state->curpacksize);
					if (!late)
						state->not_done= 1;
					break;
				case ICMP_UNREACH_FILTER_PROHIB:
					add_str(state, ", \"err\":\"A\"");
					break;
				default:
					snprintf(line, sizeof(line),
						", \"err\":%d",
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
				(now.tv_usec-state->xmit_time.tv_usec)/1e3;

			snprintf(line, sizeof(line), "%s\"from\":\"%s\"",
				(late || isDup) ? ", " : "",
				inet_ntoa(remote.sin_addr));
			add_str(state, line);
			snprintf(line, sizeof(line),
				", \"ttl\":%d, \"size\":%d",
				ip->ip_ttl, (int)nrecv-IPHDR-ICMP_MINLEN);
			add_str(state, line);
			if (!late)
			{
				snprintf(line, sizeof(line), ", \"rtt\":%.3f",
					ms);
				add_str(state, line);
			}
			if (eip->ip_ttl != 1)
			{
				snprintf(line, sizeof(line), ", \"ittl\":%d",
					eip->ip_ttl);
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
					", \"edst\":\"%s\"",
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
					add_str(state, ", \"err\":\"N\"");
					break;
				case ICMP_UNREACH_HOST:
					add_str(state, ", \"err\":\"H\"");
					break;
				case ICMP_UNREACH_PROTOCOL:
					add_str(state, ", \"err\":\"P\"");
					break;
				case ICMP_UNREACH_PORT:
					break;
				case ICMP_UNREACH_NEEDFRAG:
					nextmtu= ntohs(icmp->icmp_nextmtu);
					snprintf(line, sizeof(line),
						", \"mtu\":%d",
						nextmtu);
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
printf("curpacksize: %d\n", state->curpacksize);
					if (!late)
						state->not_done= 1;
					break;
				case ICMP_UNREACH_FILTER_PROHIB:
					add_str(state, ", \"err\":\"A\"");
					break;
				default:
					snprintf(line, sizeof(line),
						", \"err\":%d",
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
				printf("wrong instance id\n");
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
printf("%s, %d: sin6_family = %d\n", __FILE__, __LINE__, state->sin6.sin6_family);
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
				(now.tv_usec-state->xmit_time.tv_usec)/1e3;

			snprintf(line, sizeof(line), "%s\"from\":\"%s\"",
				(late || isDup) ? ", " : "",
				inet_ntoa(remote.sin_addr));
			add_str(state, line);
			snprintf(line, sizeof(line),
				", \"ttl\":%d, \"size\":%d",
				ip->ip_ttl, (int)nrecv-IPHDR-ICMP_MINLEN);
			add_str(state, line);
			if (!late)
			{
				snprintf(line, sizeof(line), ", \"rtt\":%.3f",
					ms);
				add_str(state, line);
			}

			if (eip->ip_ttl != 1)
			{
				snprintf(line, sizeof(line), ", \"ittl\":%d",
					eip->ip_ttl);
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
					", \"edst\":\"%s\"",
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
					add_str(state, ", \"err\":\"N\"");
					break;
				case ICMP_UNREACH_HOST:
					add_str(state, ", \"err\":\"H\"");
					break;
				case ICMP_UNREACH_PROTOCOL:
					add_str(state, ", \"err\":\"P\"");
					break;
				case ICMP_UNREACH_PORT:
					add_str(state, ", \"err\":\"p\"");
					break;
				case ICMP_UNREACH_NEEDFRAG:
					nextmtu= ntohs(icmp->icmp_nextmtu);
					snprintf(line, sizeof(line),
						", \"mtu\":%d",
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
					add_str(state, ", \"err\":\"A\"");
					break;
				default:
					snprintf(line, sizeof(line),
						", \"err\":%d",
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
				send_pkt(state);
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
			printf("wrong instance id\n");
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
printf("%s, %d: sin6_family = %d\n", __FILE__, __LINE__, state->sin6.sin6_family);
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
			(now.tv_usec-state->xmit_time.tv_usec)/1e3;

		snprintf(line, sizeof(line), "%s\"from\":\"%s\"",
			(late || isDup) ? ", " : "",
			inet_ntoa(remote.sin_addr));
		add_str(state, line);
		snprintf(line, sizeof(line), ", \"ttl\":%d, \"size\":%d",
			ip->ip_ttl, (int)nrecv - IPHDR - ICMP_MINLEN);
		add_str(state, line);
		if (!late)
		{
			snprintf(line, sizeof(line), ", \"rtt\":%.3f", ms);
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
				send_pkt(state);
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

static void ready_tcp4(int __attribute((unused)) unused,
	const short __attribute((unused)) event, void *s)
{
	uint16_t myport;
	socklen_t slen;
	int hlen, late, isDup;
	unsigned ind, seq;
	ssize_t nrecv;
	struct trtbase *base;
	struct trtstate *state;
	struct ip *ip;
	double ms;
	struct tcphdr *tcphdr;
	struct sockaddr_in remote;
	struct timeval now;
	struct timeval interval;
	char line[80];

	gettimeofday(&now, NULL);

	state= s;
	base= state->base;

	slen= sizeof(remote);
	nrecv= recvfrom(state->socket_tcp, base->packet, sizeof(base->packet),
		MSG_DONTWAIT, (struct sockaddr *)&remote, &slen);
	if (nrecv == -1)
	{
		/* Strange, read error */
		printf("ready_tcp4: read error '%s'\n", strerror(errno));
		return;
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

	/* Quick check if the port is in range */
	myport= ntohs(tcphdr->dest);
	if (myport < SRC_BASE_PORT || myport > SRC_BASE_PORT+256)
	{
		return;	/* Not for us */
	}

	/* We store the id in high order 16 bits of the sequence number */
	ind= ntohl(tcphdr->ack_seq) >> 16;

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
printf("%s, %d: sin6_family = %d\n", __FILE__, __LINE__, state->sin6.sin6_family);
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
	seq= ntohl(tcphdr->ack_seq) & 0xffff;
	if (seq-state->seq > 0x2000)
	{
printf("got seq %d, expected %d\n", seq, state->seq);
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
		(now.tv_usec-state->xmit_time.tv_usec)/1e3;

	snprintf(line, sizeof(line), "%s\"from\":\"%s\"",
		(late || isDup) ? ", " : "",
		inet_ntoa(remote.sin_addr));
	add_str(state, line);
	snprintf(line, sizeof(line), ", \"ttl\":%d, \"size\":%d",
		ip->ip_ttl, (int)(nrecv - IPHDR - sizeof(*tcphdr)));
	add_str(state, line);
	snprintf(line, sizeof(line), ", \"flags\":\"%s%s%s%s%s%s\"",
		(tcphdr->fin ? "F" : ""),
		(tcphdr->syn ? "S" : ""),
		(tcphdr->rst ? "R" : ""),
		(tcphdr->psh ? "P" : ""),
		(tcphdr->ack ? "A" : ""),
		(tcphdr->urg ? "U" : ""));
	add_str(state, line);

	if (!late)
	{
		snprintf(line, sizeof(line), ", \"rtt\":%.3f", ms);
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
			send_pkt(state);
	}

	return;
}

static void ready_tcp6(int __attribute((unused)) unused,
	const short __attribute((unused)) event, void *s)
{
	uint16_t myport;
	int late, isDup, rcvdttl;
	unsigned ind, seq;
	ssize_t nrecv;
	struct trtbase *base;
	struct trtstate *state;
	double ms;
	struct tcphdr *tcphdr;
	struct cmsghdr *cmsgptr;
	struct msghdr msg;
	struct iovec iov[1];
	struct sockaddr_in6 remote;
	struct in6_addr dstaddr;
	struct timeval now;
	struct timeval interval;
	char buf[INET6_ADDRSTRLEN];
	char line[80];
	char cmsgbuf[256];

	gettimeofday(&now, NULL);

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

	nrecv= recvmsg(state->socket_tcp, &msg, MSG_DONTWAIT);
	if (nrecv == -1)
	{
		/* Strange, read error */
		printf("ready_tcp6: read error '%s'\n", strerror(errno));
		return;
	}

	rcvdttl= -42;	/* To spot problems */
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
	}

	tcphdr= (struct tcphdr *)(base->packet);

	/* Quick check if the port is in range */
	myport= ntohs(tcphdr->dest);
	if (myport < SRC_BASE_PORT || myport > SRC_BASE_PORT+256)
	{
		return;	/* Not for us */
	}

	/* We store the id in high order 16 bits of the sequence number */
	ind= ntohl(tcphdr->ack_seq) >> 16;

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
printf("%s, %d: sin6_family = %d\n", __FILE__, __LINE__, state->sin6.sin6_family);
		printf("ready_tcp6: index (%d) is not busy\n", ind);
		return;
	}

	late= 0;
	isDup= 0;

	if (state->open_result)
		add_str(state, " }, { ");

	/* Only check if the ack is within 64k of what we expect */
	seq= ntohl(tcphdr->ack_seq) & 0xffff;
	if (seq-state->seq > 0x2000)
	{
printf("got seq %d, expected %d\n", seq, state->seq);
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
		(now.tv_usec-state->xmit_time.tv_usec)/1e3;

	snprintf(line, sizeof(line), "%s\"from\":\"%s\"",
		(late || isDup) ? ", " : "",
		inet_ntop(AF_INET6, &remote.sin6_addr, buf, sizeof(buf)));
	add_str(state, line);
	snprintf(line, sizeof(line), ", \"ttl\":%d, \"size\":%d",
		rcvdttl, (int)(nrecv - sizeof(*tcphdr)));
	add_str(state, line);
	snprintf(line, sizeof(line), ", \"flags\":\"%s%s%s%s%s%s\"",
		(tcphdr->fin ? "F" : ""),
		(tcphdr->syn ? "S" : ""),
		(tcphdr->rst ? "R" : ""),
		(tcphdr->psh ? "P" : ""),
		(tcphdr->ack ? "A" : ""),
		(tcphdr->urg ? "U" : ""));
	add_str(state, line);
	if (!late)
	{
		snprintf(line, sizeof(line), ", \"rtt\":%.3f", ms);
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
			send_pkt(state);
	}

	return;
}

static void ready_callback6(int __attribute((unused)) unused,
	const short __attribute((unused)) event, void *s)
{
	ssize_t nrecv;
	int ind, rcvdttl, late, isDup, nxt, icmp_prefixlen, offset;
	unsigned nextmtu, seq, optlen, hbhoptsize, dstoptsize;
	size_t ehdrsiz, v6info_siz, siz;
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
	double ms;
	struct timeval now;
	struct sockaddr_in6 remote;
	struct in6_addr dstaddr;
	struct msghdr msg;
	struct iovec iov[1];
	struct timeval interval;
	char buf[INET6_ADDRSTRLEN];
	char line[80];
	char cmsgbuf[256];

	gettimeofday(&now, NULL);

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

	nrecv= recvmsg(state->socket_icmp, &msg, MSG_DONTWAIT);
	if (nrecv == -1)
	{
		/* Strange, read error */
		printf("ready_callback6: read error '%s'\n", strerror(errno));
		return;
	}

	rcvdttl= -42;	/* To spot problems */
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
	}

	if (nrecv < sizeof(*icmp))
	{
		/* Short packet */
#if 0
		printf("ready_callback6: too short %d (icmp)\n", (int)nrecv);
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
			printf("ready_callback6: too short %d (icmp_ip)\n",
				(int)nrecv);
#endif
			return;
		}

		/* Make sure we have TCP, UDP, ICMP or a fragment header */
		if (eip->ip6_nxt == IPPROTO_FRAGMENT ||
			eip->ip6_nxt == IPPROTO_HOPOPTS ||
			eip->ip6_nxt == IPPROTO_DSTOPTS ||
			eip->ip6_nxt == IPPROTO_TCP ||
			eip->ip6_nxt == IPPROTO_UDP ||
			eip->ip6_nxt == IPPROTO_ICMPV6)
		{
			ehdrsiz= 0;
			frag= NULL;
			nxt= eip->ip6_nxt;
			ptr= &eip[1];
			if (nxt == IPPROTO_HOPOPTS)
			{
				/* Make sure the options header is completely
				 * there.
				 */
				if (nrecv < sizeof(*icmp) + sizeof(*eip)
					+ sizeof(*opthdr))
				{
#if 0
					printf(
			"ready_callback6: too short %d (icmp+ip+opt)\n",
						(int)nrecv);
#endif
					return;
				}
				opthdr= (struct ip6_ext *)ptr;
				hbhoptsize= 8*opthdr->ip6e_len;
				optlen= hbhoptsize+8;
				if (nrecv < sizeof(*icmp) + sizeof(*eip) +
					optlen)
				{
					/* Does not contain the full header */
					return;
				}
				ehdrsiz += optlen;
				nxt= opthdr->ip6e_nxt;
				ptr= ((char *)opthdr)+optlen;
			}
			if (nxt == IPPROTO_FRAGMENT)
			{
				/* Make sure the fragment header is completely
				 * there.
				 */
				if (nrecv < sizeof(*icmp) + sizeof(*eip)
					+ sizeof(*frag))
				{
#if 0
					printf(
			"ready_callback6: too short %d (icmp+ip+frag)\n",
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
					return;
				}
				ehdrsiz += sizeof(*frag);
				nxt= frag->ip6f_nxt;
				ptr= &frag[1];
			}
			if (nxt == IPPROTO_DSTOPTS)
			{
				/* Make sure the options header is completely
				 * there.
				 */
				if (nrecv < sizeof(*icmp) + sizeof(*eip)
					+ sizeof(*opthdr))
				{
#if 0
					printf(
			"ready_callback6: too short %d (icmp+ip+opt)\n",
						(int)nrecv);
#endif
					return;
				}
				opthdr= (struct ip6_ext *)ptr;
				dstoptsize= 8*opthdr->ip6e_len;
				optlen= dstoptsize+8;
				if (nrecv < sizeof(*icmp) + sizeof(*eip) +
					optlen)
				{
					/* Does not contain the full header */
					return;
				}
				ehdrsiz += optlen;
				nxt= opthdr->ip6e_nxt;
				ptr= ((char *)opthdr)+optlen;
			}

			v6info_siz= sizeof(*v6info);
			if (nxt == IPPROTO_TCP)
			{
				ehdrsiz += sizeof(*etcp);
				v6info_siz= 0;
			}
			else if (nxt == IPPROTO_UDP)
				ehdrsiz += sizeof(*eudp);
			else
				ehdrsiz += sizeof(*eicmp);

			/* Now check if there is also a header in the
			 * packet.
			 */
			if (nrecv < sizeof(*icmp) + sizeof(*eip)
				+ ehdrsiz + v6info_siz)
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
printf("%s, %d: sin6_family = %d\n", __FILE__, __LINE__, state->sin6.sin6_family);
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
						ntohl(v6info->seq),
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
			printf("ready_callback6: weird destination %s\n",
					inet_ntop(AF_INET6, &dstaddr,
					buf, sizeof(buf)));
			}

			if (eicmp && state->parismod &&
				ntohs(eicmp->icmp6_cksum) !=
				state->paris + 1)
			{
				printf(
			"ready_callback6: got checksum 0x%x, expected 0x%x\n",
					ntohs(eicmp->icmp6_cksum),
					state->paris + 1);
			}

			if (!late)
			{
				ms= (now.tv_sec-state->xmit_time.tv_sec)*1000 +
					(now.tv_usec-state->xmit_time.tv_usec)/
					1e3;
			}
			else if (v6info)
			{
				ms= (now.tv_sec-v6info->tv.tv_sec)*1000 +
					(now.tv_usec-v6info->tv.tv_usec)/
					1e3;
			}

			snprintf(line, sizeof(line), "%s\"from\":\"%s\"",
				(late || isDup) ? ", " : "",
				inet_ntop(AF_INET6, &remote.sin6_addr,
				buf, sizeof(buf)));
			add_str(state, line);
			snprintf(line, sizeof(line),
				", \"ttl\":%d, \"rtt\":%.3f, \"size\":%d",
				rcvdttl, ms, (int)(nrecv-ICMP6_HDR));
			add_str(state, line);
			if (eip->ip6_hops != 1)
			{
				snprintf(line, sizeof(line), ", \"ittl\":%d",
					eip->ip6_hops);
				add_str(state, line);
			}
			if (hbhoptsize)
			{
				snprintf(line, sizeof(line),
					", \"hbhoptsize\":%d", hbhoptsize);
				add_str(state, line);
			}
			if (dstoptsize)
			{
				snprintf(line, sizeof(line),
					", \"dstoptsize\":%d", dstoptsize);
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
				snprintf(line, sizeof(line), ", \"mtu\":%d",
					nextmtu);
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
					add_str(state, ", \"err\":\"N\"");
					break;
				case ICMP6_DST_UNREACH_ADMIN:	/* 1 */
					add_str(state, ", \"err\":\"A\"");
					break;
				case ICMP6_DST_UNREACH_BEYONDSCOPE: /* 2 */
					add_str(state, ", \"err\":\"h\"");
					break;
				case ICMP6_DST_UNREACH_ADDR:	/* 3 */
					add_str(state, ", \"err\":\"H\"");
					break;
				case ICMP6_DST_UNREACH_NOPORT:	/* 4 */
					break;
				default:
					snprintf(line, sizeof(line),
						", \"err\":%d",
						icmp->icmp6_code);
					add_str(state, line);
					break;
				}
			}
		}
		else
		{
			printf(
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
				send_pkt(state);
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
printf("%s, %d: sin6_family = %d\n", __FILE__, __LINE__, state->sin6.sin6_family);
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
			printf("ready_callback6: weird destination %s\n",
				inet_ntop(AF_INET6, &dstaddr,
				buf, sizeof(buf)));
		}

		if (!late)
		{
			ms= (now.tv_sec-state->xmit_time.tv_sec)*1000 +
				(now.tv_usec-state->xmit_time.tv_usec)/
				1e3;
		}
		else
		{
			ms= (now.tv_sec-v6info->tv.tv_sec)*1000 +
				(now.tv_usec-v6info->tv.tv_usec)/
				1e3;
		}

		snprintf(line, sizeof(line), "%s\"from\":\"%s\"",
			(late || isDup) ? ", " : "",
			inet_ntop(AF_INET6, &remote.sin6_addr,
			buf, sizeof(buf)));
		add_str(state, line);
		snprintf(line, sizeof(line),
			", \"ttl\":%d, \"rtt\":%.3f, \"size\":%d",
			rcvdttl, ms, (int)(nrecv - ICMP6_HDR));
		add_str(state, line);

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
				send_pkt(state);
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

#if 0
	printf("noreply_callback: gotresp = %d\n",
		state->gotresp);
#endif

	if (!state->gotresp)
	{
		if (state->open_result)
			add_str(state, " }, { ");
		add_str(state, DBQ(x) ":" DBQ(*));
		state->open_result= 1;
	}

	send_pkt(state);
}

static void *traceroute_init(int __attribute((unused)) argc, char *argv[],
	void (*done)(void *state))
{
	uint16_t destport;
	uint32_t opt;
	int i, do_icmp, do_v6, dont_fragment, delay_name_res, do_tcp, do_udp;
	unsigned count, duptimeout, firsthop, gaplimit, maxhops, maxpacksize,
		hbhoptsize, destoptsize, parismod, parisbase, timeout;
		/* must be int-sized */
	size_t newsiz;
	char *str_Atlas;
	const char *hostname;
	char *out_filename;
	const char *destportstr;
	char *interface;
	char *check;
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
	str_Atlas= NULL;
	out_filename= NULL;
	opt_complementary = "=1:4--6:i--u:a+:b+:c+:f+:g+:m+:w+:z+:S+:H+:D+";

for (i= 0; argv[i] != NULL; i++)
	printf("argv[%d] = '%s'\n", i, argv[i]);

	opt = getopt32(argv, TRACEROUTE_OPT_STRING, &parismod, &parisbase,
		&count,
		&firsthop, &gaplimit, &interface, &maxhops, &destportstr,
		&timeout,
		&duptimeout, &str_Atlas, &out_filename, &maxpacksize,
		&hbhoptsize, &destoptsize);
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
	do_tcp= !!(opt & OPT_T);
	do_udp= !(do_icmp || do_tcp);
	if (maxpacksize > sizeof(trt_base->packet))
		maxpacksize= sizeof(trt_base->packet);

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

	if (!delay_name_res)
	{
		/* Attempt to resolve 'name' */
		af= do_v6 ? AF_INET6 : AF_INET;
		destport= strtoul(destportstr, &check, 0);
		if (check[0] != '\0' || destport == 0)
			return NULL;
		lsa= host_and_af2sockaddr(hostname, destport, af);
		if (!lsa)
			return NULL;

		if (lsa->len > sizeof(state->sin6))
		{
			free(lsa);
			return NULL;
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
	state->interface= interface;
	state->destportstr= strdup(destportstr);
	state->duptimeout= duptimeout*1000;
	state->timeout= timeout*1000;
	state->atlas= str_Atlas ? strdup(str_Atlas) : NULL;
	state->hostname= strdup(hostname);
	state->do_icmp= do_icmp;
	state->do_tcp= do_tcp;
	state->do_udp= do_udp;
	state->do_v6= do_v6;
	state->dont_fragment= dont_fragment;
	state->delay_name_res= delay_name_res;
	state->hbhoptsize= hbhoptsize;
	state->destoptsize= destoptsize;
	state->out_filename= out_filename ? strdup(out_filename) : NULL;
	state->base= trt_base;
	state->paris= 0;
	state->busy= 0;
	state->result= NULL;
	state->reslen= 0;
	state->resmax= 0;

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
}

static void traceroute_start2(void *state)
{
	struct trtstate *trtstate;
	char line[80];

	trtstate= state;

	if (trtstate->busy)
	{
		printf("traceroute_start: busy, can't start\n");
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
		trtstate->paris= (trtstate->paris-trtstate->parisbase+1) %
			trtstate->parismod + trtstate->parisbase;
	}
	trtstate->last_response_hop= 0;	/* Should be starting hop */
	trtstate->done= 0;
	trtstate->not_done= 0;
	trtstate->lastditch= 0;
	trtstate->curpacksize= trtstate->maxpacksize;

	if (trtstate->result) free(trtstate->result);
	trtstate->resmax= 80;
	trtstate->result= xmalloc(trtstate->resmax);
	trtstate->reslen= 0;
	trtstate->open_result= 0;
	trtstate->starttime= time(NULL);

	trtstate->socket_icmp= -1;
	trtstate->socket_tcp= -1;

	snprintf(line, sizeof(line), "{ \"hop\":%d", trtstate->hop);
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

	add_str(trtstate, ", \"result\": [ ");

	send_pkt(trtstate);
}

static int create_socket(struct trtstate *state, int do_tcp)
{
	int af, type, protocol;
	int r, on, serrno;
	char line[80];

	af= (state->do_v6 ? AF_INET6 : AF_INET);
	type= SOCK_RAW;
	protocol= (af == AF_INET6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP);

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
			snprintf(line, sizeof(line),
	", " DBQ(error) ":" DBQ(bind_interface failed) " }");
			add_str(state, line);
			report(state);
			return -1;
		}
	}

	r= connect(state->socket_icmp,
		(struct sockaddr *)&state->sin6,
		state->socklen);
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
	state->loc_socklen= sizeof(state->loc_sin6);
	if (getsockname(state->socket_icmp,
		&state->loc_sin6,
		&state->loc_socklen) == -1)
	{
		crondlog(DIE9 "getsockname failed");
	}
#if 0
	printf("Got localname: %s\n",
		inet_ntop(AF_INET6,
		&state->loc_sin6.sin6_addr,
		buf, sizeof(buf)));
#endif

	close(state->socket_icmp);
	state->socket_icmp= xsocket(af, type,
		protocol);
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

	event_assign(&state->event_icmp, state->base->event_base,
		state->socket_icmp,
		EV_READ | EV_PERSIST,
		(af == AF_INET6 ? ready_callback6 : ready_callback4),
		state);
	event_add(&state->event_icmp, NULL);

	if (do_tcp)
	{
		state->socket_tcp= xsocket(af, SOCK_RAW,
			IPPROTO_TCP);
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

		r= connect(state->socket_tcp,
			(struct sockaddr *)&state->sin6,
			state->socklen);
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
		event_add(&state->event_tcp, NULL);
	}

	return 0;
}

static void dns_cb(int result, struct evutil_addrinfo *res, void *ctx)
{
	int count;
	struct trtstate *env;
	struct evutil_addrinfo *cur;
	char line[160];

	env= ctx;

	if (!env->dnsip)
	{
		crondlog(LVL7
			"dns_cb: in dns_cb but not doing dns at this time");
		if (res)
			evutil_freeaddrinfo(res);
		return;
	}

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

		traceroute_start2(env);

		evutil_freeaddrinfo(env->dns_res);
		env->dns_res= NULL;
		env->dns_curr= NULL;
		return;
	}

	/* Something went wrong */
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

	if (!trtstate->delay_name_res)
	{
		traceroute_start2(state);
		return;
	}

	memset(&hints, '\0', sizeof(hints));
	hints.ai_socktype= SOCK_DGRAM;
	hints.ai_family= trtstate->do_v6 ? AF_INET6 : AF_INET;
	trtstate->dnsip= 1;
	(void) evdns_getaddrinfo(DnsBase, trtstate->hostname,
		trtstate->destportstr, &hints, dns_cb, trtstate);
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

