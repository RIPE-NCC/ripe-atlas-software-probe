/*
traceroute.c
*/

#include "libbb.h"
#include <event2/event.h>
#include <event2/event_struct.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>

#include "eperd.h"
#include "evping.h"

#if !STANDALONE_BUSYBOX
#define uh_sport source
#define uh_dport dest
#define uh_ulen len
#define uh_sum check
#endif

#define TRACEROUTE_OPT_STRING ("46IUFa:c:f:g:m:w:z:A:O:S:")

#define OPT_4	(1 << 0)
#define OPT_6	(1 << 1)
#define OPT_I	(1 << 2)
#define OPT_U	(1 << 3)
#define OPT_F	(1 << 4)

#define BASE_PORT	(0x8000 + 666)
#define MAX_DATA_SIZE   (4096)

struct trtbase
{
	struct event_base *event_base;

	int v4icmp_rcv;
	int v6icmp_rcv;
	int v4icmp_snd;
	int v6icmp_snd;
	int v4udp_snd;
	int v6udp_snd;

	struct event event4;
	struct event event6;

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
	char *out_filename;
	char do_icmp;
	char do_v6;
	char dont_fragment;
	char trtcount;
	unsigned short maxpacksize;
	unsigned char firsthop;
	unsigned char maxhops;
	unsigned char gaplimit;
	unsigned char parismod;
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
};

static struct trtbase *trt_base;

struct udp_ph
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

static int in_cksum_udp(struct udp_ph *udp_ph, struct udphdr *udp, 
	unsigned short *buf, int sz)
{
	int nleft = sz;
	int sum = 0;
	unsigned short *w = buf;
	unsigned short ans = 0;

	nleft= sizeof(*udp_ph);
	w= (unsigned short *)udp_ph;
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	nleft= sizeof(*udp);
	w= (unsigned short *)udp;
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

	fprintf(fh, "{ ");
	if (state->atlas)
	{
		fprintf(fh, "\"id\":\"%s\", \"time\":%ld, ",
			state->atlas, (long)time(NULL));
	}

	getnameinfo((struct sockaddr *)&state->sin6, state->socklen,
		namebuf, sizeof(namebuf), NULL, 0, NI_NUMERICHOST);

	fprintf(fh, "\"name\":\"%s\", \"addr\":\"%s\"",
		state->hostname, namebuf);

	getnameinfo((struct sockaddr *)&state->loc_sin6, state->loc_socklen,
		namebuf, sizeof(namebuf), NULL, 0, NI_NUMERICHOST);

	fprintf(fh, ", \"srcaddr\":\"%s\"", namebuf);

	fprintf(fh, ", \"mode\":\"%s%c\"", state->do_icmp ? "ICMP" : "UDP",
		state->sin6.sin6_family == AF_INET6 ? '6' : '4');

	fprintf(fh, ", \"size\":%d", state->maxpacksize);
	if (state->parismod)
	{
		fprintf(fh, ", \"paris-id\":%d",
			state->paris % state->parismod);
	}
	fprintf(fh, ", \"result\": [ %s ] }\n", state->result);
	free(state->result);
	state->result= NULL;
	state->busy= 0;

	if (state->out_filename)
		fclose(fh);

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
	struct udp_ph udp_ph;
	struct v6_ph v6_ph;
	struct udphdr udp;
	struct timeval interval;
	char line[80];
	char id[]= "http://atlas.ripe.net Randy Bush, Atlas says Hi!";

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
			", { \"hop\":%d, \"result\": [ ", state->hop);
		add_str(state, line);
	}
	state->seq++;

	gettimeofday(&state->xmit_time, NULL);

	if (state->sin6.sin6_family == AF_INET6)
	{
		hop= state->hop;

		if (state->do_icmp)
		{
			/* Set hop count */
			setsockopt(base->v6icmp_snd, SOL_IPV6,
				IPV6_UNICAST_HOPS, &hop, sizeof(hop));

			/* Set/clear don't fragment */
			on= (state->dont_fragment ? IPV6_PMTUDISC_DO :
				IPV6_PMTUDISC_DONT);
			setsockopt(base->v6icmp_snd, IPPROTO_IPV6,
					IPV6_MTU_DISCOVER, &on, sizeof(on));

			icmp6_hdr= (struct icmp6_hdr *)base->packet;
			icmp6_hdr->icmp6_type= ICMP6_ECHO_REQUEST;
			icmp6_hdr->icmp6_code= 0;
			icmp6_hdr->icmp6_cksum= 0;
			icmp6_hdr->icmp6_id= htons(getpid());
			icmp6_hdr->icmp6_seq= htons(state->seq);

			v6info= (struct v6info *)&icmp6_hdr[1];
			v6info->fuzz= 0;
			v6info->pid= htonl(getpid());
			v6info->id= htonl(state->index);
			v6info->seq= htonl(state->seq);
			v6info->tv= state->xmit_time;

			len= sizeof(*icmp6_hdr)+sizeof(*v6info);

			if (state->curpacksize < len)
				state->curpacksize= len;
			if (state->curpacksize > len)
			{
				memset(&base->packet[len], '\0',
					state->curpacksize-len);
				strcpy((char *)&base->packet[len], id);
				len= state->curpacksize;
			}

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
				val= state->paris % state->parismod + 1;

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

			r= sendto(base->v6icmp_snd, base->packet, len, 0,
				&state->sin6, state->socklen);
			if (r == -1)
			{
				if (errno != EMSGSIZE)
				{
					printf("send_pkt: sendto failed: %s\n",
						strerror(errno));
				}
			}
		}
		else
		{
			/* Set port */
			state->sin6.sin6_port= htons(BASE_PORT + 
				(state->parismod ? (state->paris % state->parismod) :
				0));

			/* Set hop count */
			setsockopt(base->v6udp_snd, SOL_IPV6, IPV6_UNICAST_HOPS,
				&hop, sizeof(hop));

			/* Set/clear don't fragment */
			on= (state->dont_fragment ? IPV6_PMTUDISC_DO :
				IPV6_PMTUDISC_DONT);
			setsockopt(base->v6udp_snd, IPPROTO_IPV6,
					IPV6_MTU_DISCOVER, &on, sizeof(on));

			v6info= (struct v6info *)base->packet;
			v6info->fuzz= 0;
			v6info->pid= htonl(getpid());
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

			r= sendto(base->v6udp_snd, base->packet, len, 0,
				&state->sin6, state->socklen);
			if (r == -1)
			{
				if (errno != EACCES &&
					errno != ECONNREFUSED)
				{
					printf("send_pkt: sendto failed: %s\n",
						strerror(errno));
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

		if (state->do_icmp)
		{
			hop= state->hop;

			icmp_hdr= (struct icmp *)base->packet;
			icmp_hdr->icmp_type= ICMP_ECHO;
			icmp_hdr->icmp_code= 0;
			icmp_hdr->icmp_cksum= 0;
			icmp_hdr->icmp_id= htons(state->index);
			icmp_hdr->icmp_seq= htons(state->seq);
			icmp_hdr->icmp_data[0]= '\0';
			icmp_hdr->icmp_data[1]= '\0';

			len= offsetof(struct icmp, icmp_data[2]);

			if (state->curpacksize < len)
				state->curpacksize= len;
			if (state->curpacksize > len)
			{
				memset(&base->packet[len], '\0',
					state->curpacksize-len);
				strcpy((char *)&base->packet[len], id);
				len= state->curpacksize;
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
			setsockopt(base->v4icmp_snd, IPPROTO_IP, IP_TTL,
				&hop, sizeof(hop));

			/* Set/clear don't fragment */
			on= (state->dont_fragment ? IP_PMTUDISC_DO :
				IP_PMTUDISC_DONT);
			setsockopt(base->v4icmp_snd, IPPROTO_IP,
				IP_MTU_DISCOVER, &on, sizeof(on));

			r= sendto(base->v4icmp_snd, base->packet, len, 0,
				&state->sin6, state->socklen);
			if (r == -1)
			{
				if (errno != EMSGSIZE)
				{
					printf("send_pkt: sendto failed: %s\n",
						strerror(errno));
				}
			}
		}
		else
		{
			if (state->parismod)
			{
				sock= socket(AF_INET, SOCK_DGRAM, 0);
				if (sock == -1)
				{
					crondlog(DIE9 "socket failed");
				}

				/* Bind to source addr/port */
				if (bind(sock,
					(struct sockaddr *)&state->loc_sin6,
					state->loc_socklen) == -1)
				{
					printf("bind failed\n");
					close(sock);
					return;
				}
			}
			else
			{
				sock= base->v4udp_snd;
			}

			hop= state->hop;

			/* Set port */
			if (!state->parismod)
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

			udp_ph.src= ((struct sockaddr_in *)&state->loc_sin6)->
				sin_addr;
			udp_ph.dst= ((struct sockaddr_in *)&state->sin6)->
				sin_addr;
			udp_ph.zero= 0;
			udp_ph.proto= IPPROTO_UDP;
			udp_ph.len= htons(sizeof(udp)+len);
			udp.uh_sport=
				((struct sockaddr_in *)&state->loc_sin6)->
				sin_port;
			udp.uh_dport= ((struct sockaddr_in *)&state->sin6)->
				sin_port;
			udp.uh_ulen= udp_ph.len;
			udp.uh_sum= 0;

			sum= in_cksum_udp(&udp_ph, &udp,
				(unsigned short *)base->packet, len);

			if (state->parismod)
			{
				/* Make sure that the sequence number ends
				 * up in the checksum field. We can't store
				 * 0.
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

			/* Set hop count */
			setsockopt(sock, IPPROTO_IP, IP_TTL,
				&hop, sizeof(hop));

			/* Set/clear don't fragment */
			on= (state->dont_fragment ? IP_PMTUDISC_DO :
				IP_PMTUDISC_DONT);
			setsockopt(sock, IPPROTO_IP,
				IP_MTU_DISCOVER, &on, sizeof(on));

			r= sendto(sock, base->packet, len, 0,
				&state->sin6, state->socklen);
			serrno= errno;
			if (state->parismod)
				close(sock);
			if (r == -1)
			{
				if (serrno != EMSGSIZE)
				{
					printf("send_pkt: sendto failed: %s\n",
						strerror(serrno));
				}
			}
		}
	}

	if (state->sent)
		add_str(state, " }, ");
	add_str(state, "{ ");

	/* Increment packets sent */
	state->sent++;

	/* Set timer */
	interval.tv_sec= state->timeout/1000000;
	interval.tv_usec= state->timeout % 1000000;
	evtimer_add(&state->timer, &interval);

}

static void ready_callback4(int __attribute((unused)) unused,
	const short __attribute((unused)) event, void *s)
{
	struct trtbase *base;
	struct trtstate *state;
	int hlen, ehlen, ind, nextmtu, late, isDup;
	unsigned seq;
	ssize_t nrecv;
	socklen_t slen;
	struct ip *ip, *eip;
	struct icmp *icmp, *eicmp;
	struct udphdr *eudp;
	double ms;
	struct timeval now, interval;
	struct sockaddr_in remote;
	char line[80];

	gettimeofday(&now, NULL);

	base= s;

	slen= sizeof(remote);
	nrecv= recvfrom(base->v4icmp_rcv, base->packet, sizeof(base->packet),
		MSG_DONTWAIT, (struct sockaddr *)&remote, &slen);
	if (nrecv == -1)
	{
		/* Strange, read error */
		printf("ready_callback4: read error '%s'\n", strerror(errno));
		return;
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

		if (eip->ip_p == IPPROTO_UDP)
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

			/* If we are doing paris, we store the id in the
			 * destination port.
			 */
			ind= ntohs(eudp->uh_dport) - BASE_PORT;

			state= NULL;
			if (ind >= 0 && ind < base->tabsiz)
				state= base->table[ind];
			if (state && state->sin6.sin6_family != AF_INET)
				state= NULL;
			if (state && state->do_icmp)
				state= NULL;	
			if (state && !state->parismod)
				state= NULL;	

			if (!state)
			{
				/* Try again for non-paris. Get the id from
				 * the checksum field.
				 */
				ind= ntohs(eudp->uh_sum)-1;
				state= NULL;
				if (ind >= 0 && ind < base->tabsiz)
					state= base->table[ind];
				if (state && state->sin6.sin6_family != AF_INET)
					state= NULL;
				if (state && state->do_icmp)
					state= NULL;	
				if (state && state->parismod)
					state= NULL;	
				if (!state)
				{
					/* Nothing here */
					return;
				}
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
printf("%s, %d: sin6_family = %d\n", __FILE__, __LINE__, state->sin6.sin6_family);
				printf(
			"ready_callback4: index (%d) is not busy\n",
					ind);
				return;
			}

			late= 0;
			isDup= 0;
			if (state->parismod)
			{
				/* Sequence number is in checksum field */
				seq= ntohs(eudp->uh_sum);
			}
			else
			{
				/* Sequence number is in destination field */
				seq= ntohs(eudp->uh_dport)-BASE_PORT;
			}

			if (seq != state->seq)
			{
				if (seq > state->seq)
				{
					printf(
	"ready_callback4: mismatch for seq, got 0x%x, expected 0x%x (for %s)\n",
						seq, state->seq,
						state->hostname);
					return;
				}
				late= 1;

				snprintf(line, sizeof(line), "\"late\":%d",
					state->seq-seq);
				add_str(state, line);
			}
			else if (state->gotresp)
			{
				isDup= 1;
				add_str(state, " }, { \"dup\":true");
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
				ip->ip_ttl, (int)nrecv);
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

			if (late)
				add_str(state, " }, { ");
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

			if (ind >= base->tabsiz)
			{
				/* Out of range */
				printf(
				"ready_callback4: index out of range (%d)\n",
					ind);
				return;
			}

			state= base->table[ind];
			if (!state)
			{
				/* Nothing here */
				printf(
				"ready_callback4: nothing at index (%d)\n",
					ind);
				return;
			}

			if (state->sin6.sin6_family != AF_INET)
			{
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
					ntohs(eicmp->icmp_cksum), state->paris,
					state->hostname);
			}

			late= 0;
			isDup= 0;
			seq= ntohs(eicmp->icmp_seq);
			if (seq != state->seq)
			{
				if (seq > state->seq)
				{
					printf(
	"ready_callback4: mismatch for seq, got 0x%x, expected 0x%x (for %s)\n",
						seq, state->seq,
						state->hostname);
					return;
				}
				late= 1;

				snprintf(line, sizeof(line), "\"late\":%d",
					state->seq-seq);
				add_str(state, line);
			}
			else if (state->gotresp)
			{
				isDup= 1;
				add_str(state, " }, { \"dup\":true");
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
				ip->ip_ttl, (int)nrecv);
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
					if (!late && nextmtu >= sizeof(*ip))
					{
						nextmtu -= sizeof(*ip);
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

			if (late)
				add_str(state, " }, { ");
		}
		else
		{
			printf("ready_callback4: not UDP or ICMP (%d\n",
				eip->ip_p);
			return;
		}

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

		if (ind >= base->tabsiz)
		{
			/* Out of range */
			printf(
			"ready_callback4: index out of range (%d)\n",
				ind);
			return;
		}

		state= base->table[ind];
		if (!state)
		{
			/* Nothing here */
			printf(
			"ready_callback4: nothing at index (%d)\n",
				ind);
			return;
		}

		if (state->sin6.sin6_family != AF_INET)
		{
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
		seq= ntohs(icmp->icmp_seq);
		if (seq != state->seq)
		{
			if (seq > state->seq)
			{
				printf(
"ready_callback4: mismatch for seq, got 0x%x, expected 0x%x, for %s\n",
					seq, state->seq, state->hostname);
				return;
			}
			late= 1;

			snprintf(line, sizeof(line), "\"late\":%d",
				state->seq-seq);
			add_str(state, line);
		}
		else if (state->gotresp)
		{
			isDup= 1;
			add_str(state, " }, { \"dup\":true");
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
		snprintf(line, sizeof(line), ", \"ttl\":%d",
			ip->ip_ttl);
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

		if (late)
			add_str(state, " }, { ");

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

static void ready_callback6(int __attribute((unused)) unused,
	const short __attribute((unused)) event, void *s)
{
	ssize_t nrecv;
	int ind, rcvdttl, late, isDup, nxt;
	unsigned nextmtu, seq;
	size_t ehdrsiz, siz;
	struct trtbase *base;
	struct trtstate *state;
	struct ip6_hdr *eip;
	struct ip6_frag *frag;
	struct icmp6_hdr *icmp, *eicmp;
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

	base= s;

	iov[0].iov_base= base->packet;
	iov[0].iov_len= sizeof(base->packet);
	msg.msg_name= &remote;
	msg.msg_namelen= sizeof(remote);
	msg.msg_iov= iov;
	msg.msg_iovlen= 1;
	msg.msg_control= cmsgbuf;
	msg.msg_controllen= sizeof(cmsgbuf);
	msg.msg_flags= 0;			/* Not really needed */

	nrecv= recvmsg(base->v6icmp_rcv, &msg, MSG_DONTWAIT);
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
		printf("ready_callback6: too short %d (icmp)\n", (int)nrecv);
		return;
	}

	icmp= (struct icmp6_hdr *)&base->packet;

	if (icmp->icmp6_type == ICMP6_DST_UNREACH ||
		icmp->icmp6_type == ICMP6_PACKET_TOO_BIG ||
		icmp->icmp6_type == ICMP6_TIME_EXCEEDED)
	{
		eip= (struct ip6_hdr *)&icmp[1];

		/* Make sure the packet we have is big enough */
		if (nrecv < sizeof(*icmp) + sizeof(*eip))
		{
			printf("ready_callback6: too short %d (icmp_ip)\n",
				(int)nrecv);
			return;
		}

		/* Make sure we have UDP or ICMP or a fragment header */
		if (eip->ip6_nxt == IPPROTO_FRAGMENT ||
			eip->ip6_nxt == IPPROTO_UDP ||
			eip->ip6_nxt == IPPROTO_ICMPV6)
		{
			ehdrsiz= 0;
			frag= NULL;
			nxt= eip->ip6_nxt;
			if (nxt == IPPROTO_FRAGMENT)
			{
				/* Make sure the fragment header is completely
				 * there.
				 */
				if (nrecv < sizeof(*icmp) + sizeof(*eip)
					+ sizeof(*frag))
				{
					printf(
			"ready_callback6: too short %d (icmp+ip+frag)\n",
						(int)nrecv);
					return;
				}
				frag= (struct ip6_frag *)&eip[1];
				if ((ntohs(frag->ip6f_offlg) & ~3) != 0)
				{
					/* Not first fragment, just ignore
					 * it.
					 */
					return;
				}
				ehdrsiz= sizeof(*frag);
				nxt= frag->ip6f_nxt;
			}

			if (nxt == IPPROTO_UDP)
				ehdrsiz += sizeof(*eudp);
			else
				ehdrsiz += sizeof(*eicmp);

			/* Now check if there is also a header in the
			 * packet.
			 */
			if (nrecv < sizeof(*icmp) + sizeof(*eip)
				+ ehdrsiz + sizeof(*v6info))
			{
				printf(
			"ready_callback6: too short %d (all) from %s\n",
					(int)nrecv, inet_ntop(AF_INET6,
					&remote.sin6_addr, buf, sizeof(buf)));
				return;
			}

			eudp= NULL;
			eicmp= NULL;
			ptr= (frag ? (void *)&frag[1] : (void *)&eip[1]);
			if (nxt == IPPROTO_UDP)
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
			printf(
"ready_callback6: pid = htonl(%d), id = htonl(%d), seq = htonl(%d)\n",
				ntohl(v6info->pid),
				ntohl(v6info->id),
				ntohl(v6info->seq));
#endif

			ind= ntohl(v6info->id);

			state= NULL;
			if (ind >= 0 && ind < base->tabsiz)
				state= base->table[ind];

			if (state && state->sin6.sin6_family != AF_INET6)
				state= NULL;

			if (state)
			{
				if ((eudp && state->do_icmp) ||
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

				snprintf(line, sizeof(line), "\"late\":%d",
					state->seq-seq);
				add_str(state, line);
			} else if (state->gotresp)
			{
				isDup= 1;
				add_str(state, " }, { \"dup\":true");
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
				state->paris % state->parismod + 1)
			{
				printf(
			"ready_callback6: got checksum 0x%x, expected 0x%x\n",
					ntohs(eicmp->icmp6_cksum),
					state->paris % state->parismod + 1);
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
				rcvdttl, ms, (int)nrecv);
			add_str(state, line);
			if (eip->ip6_hops != 1)
			{
				snprintf(line, sizeof(line), ", \"ittl\":%d",
					eip->ip6_hops);
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
				case ICMP6_DST_UNREACH_NOROUTE:
					add_str(state, ", \"err\":\"N\"");
					break;
				case ICMP6_DST_UNREACH_ADDR:
					add_str(state, ", \"err\":\"H\"");
					break;
				case ICMP6_DST_UNREACH_NOPORT:
					break;
				case ICMP6_DST_UNREACH_ADMIN:
					add_str(state, ", \"err\":\"A\"");
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

		if (late)
			add_str(state, " }, { ");

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
			printf("ready_callback6: too short %d (echo reply)\n",
				(int)nrecv);
			return;
		}

		eudp= NULL;
		eicmp= NULL;

		v6info= (struct v6info *)&icmp[1];

		ind= ntohl(v6info->id);

		state= NULL;
		if (ind >= 0 && ind < base->tabsiz)
			state= base->table[ind];

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

			snprintf(line, sizeof(line), "\"late\":%d",
				state->seq-seq);
			add_str(state, line);
		}
		else if (state->gotresp)
		{
			isDup= 1;
			add_str(state, " }, { \"dup\":true");
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
			rcvdttl, ms, (int)nrecv);
		add_str(state, line);

#if 0
		printf("ready_callback6: from %s, ttl %d",
			inet_ntop(AF_INET6, &remote.sin6_addr, buf,
			sizeof(buf)), rcvdttl);
		printf(" for %s hop %d\n",
			inet_ntop(AF_INET6, &state->sin6.sin6_addr, buf,
			sizeof(buf)), state->hop);
#endif

		if (late)
			add_str(state, " }, { ");

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
	int on;
	struct trtbase *base;

	base= xzalloc(sizeof(*base));

	base->event_base= event_base;

	base->tabsiz= 10;
	base->table= xzalloc(base->tabsiz * sizeof(*base->table));

	base->v4icmp_rcv= xsocket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	base->v6icmp_rcv= xsocket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	base->v4icmp_snd= xsocket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	base->v6icmp_snd= xsocket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	base->v4udp_snd= xsocket(AF_INET, SOCK_DGRAM, 0);
	base->v6udp_snd= xsocket(AF_INET6, SOCK_DGRAM, 0);

	on = 1;
	setsockopt(base->v6icmp_rcv, IPPROTO_IPV6, IPV6_RECVPKTINFO,
		&on, sizeof(on));

	on = 1;
	setsockopt(base->v6icmp_rcv, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
		&on, sizeof(on));

	event_assign(&base->event4, base->event_base, base->v4icmp_rcv,
		EV_READ | EV_PERSIST, ready_callback4, base);
	event_assign(&base->event6, base->event_base, base->v6icmp_rcv,
		EV_READ | EV_PERSIST, ready_callback6, base);
	event_add(&base->event4, NULL);
	event_add(&base->event6, NULL);

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
		add_str(state, "\"x\":\"*\"");

	send_pkt(state);
}

static void *traceroute_init(int __attribute((unused)) argc, char *argv[],
	void (*done)(void *state))
{
	int i, opt, do_icmp, do_v6, dont_fragment;
	unsigned count, duptimeout, firsthop, gaplimit, maxhops, maxpacksize,
		parismod, timeout; /* must be int-sized */
	size_t newsiz;
	char *str_Atlas;
	const char *hostname;
	char *out_filename;
	struct trtstate *state;
	sa_family_t af;
	len_and_sockaddr *lsa;

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
	maxhops= 32;
	maxpacksize= 40;
	duptimeout= 10;
	timeout= 1000;
	parismod= 16;
	out_filename= NULL;
	opt_complementary = "=1:4--6:i--u:a+:c+:f+:g+:m+:w+:z+:S+";
	opt = getopt32(argv, TRACEROUTE_OPT_STRING, &parismod, &count,
		&firsthop, &gaplimit, &maxhops, &timeout, &duptimeout,
		&str_Atlas, &out_filename, &maxpacksize);
	hostname = argv[optind];

	do_icmp= !!(opt & OPT_I);
	do_v6= !!(opt & OPT_6);
	dont_fragment= !!(opt & OPT_F);
	if (maxpacksize > sizeof(trt_base->packet))
		maxpacksize= sizeof(trt_base->packet);

	/* Attempt to resolve 'name' */
	af= do_v6 ? AF_INET6 : AF_INET;
	lsa= host_and_af2sockaddr(hostname, 0, af);
	if (!lsa)
		return NULL;

	if (lsa->len > sizeof(state->sin6))
	{
		free(lsa);
		return NULL;
	}

	state= xzalloc(sizeof(*state));
	state->parismod= parismod;
	state->trtcount= count;
	state->firsthop= firsthop;
	state->maxpacksize= maxpacksize;
	state->maxhops= maxhops;
	state->gaplimit= gaplimit;
	state->duptimeout= duptimeout*1000;
	state->timeout= timeout*1000;
	state->atlas= str_Atlas ? strdup(str_Atlas) : NULL;
	state->hostname= strdup(hostname);
	state->do_icmp= do_icmp;
	state->do_v6= do_v6;
	state->dont_fragment= dont_fragment;
	state->out_filename= out_filename ? strdup(out_filename) : NULL;
	state->base= trt_base;
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

	printf("traceroute_init: state %p, index %d\n",
		state, state->index);

	memcpy(&state->sin6, &lsa->u.sa, lsa->len);
	state->socklen= lsa->len;
	free(lsa); lsa= NULL;

	if (af == AF_INET6)
	{
		char buf[INET6_ADDRSTRLEN];
		printf("traceroute_init: %s, len %d for %s\n",
			inet_ntop(AF_INET6, &state->sin6.sin6_addr,
			buf, sizeof(buf)), state->socklen, state->hostname);
	}

	evtimer_assign(&state->timer, state->base->event_base,
		noreply_callback, state);

	return state;
}

static void traceroute_start(void *state)
{
	int serrno;
	struct trtstate *trtstate;
	struct trtbase *trtbase;
	struct sockaddr_in loc_sa4;
	struct sockaddr_in6 loc_sa6;
	char line[80];

	trtstate= state;
	trtbase= trtstate->base;

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
	trtstate->paris++;
	trtstate->last_response_hop= 0;	/* Should be starting hop */
	trtstate->done= 0;
	trtstate->not_done= 0;
	trtstate->lastditch= 0;
	trtstate->curpacksize= trtstate->maxpacksize;

	if (trtstate->result) free(trtstate->result);
	trtstate->resmax= 80;
	trtstate->result= xmalloc(trtstate->resmax);
	trtstate->reslen= 0;

	snprintf(line, sizeof(line), "{ \"hop\":%d", trtstate->hop);
	add_str(trtstate, line);

	if (trtstate->do_icmp)
	{
		if (trtstate->do_v6)
		{
			memset(&loc_sa6, '\0', sizeof(loc_sa6));
			loc_sa6.sin6_family= AF_INET;

			if (connect(trtbase->v6icmp_snd,
				&trtstate->sin6, trtstate->socklen) == -1)
			{
				serrno= errno;

				snprintf(line, sizeof(line),
			", \"error\":\"connect failed: %s\" }",
					strerror(serrno));
				add_str(trtstate, line);
				report(trtstate);
				return;
			}
			trtstate->loc_socklen= sizeof(trtstate->loc_sin6);
			if (getsockname(trtbase->v6icmp_snd,
				&trtstate->loc_sin6,
				&trtstate->loc_socklen) == -1)
			{
				crondlog(DIE9 "getsockname failed");
			}
#if 0
			printf("Got localname: %s\n",
				inet_ntop(AF_INET6,
				&trtstate->loc_sin6.sin6_addr,
				buf, sizeof(buf)));
#endif
		}
		else
		{
			memset(&loc_sa4, '\0', sizeof(loc_sa4));
			loc_sa4.sin_family= AF_INET;
			((struct sockaddr_in *)&trtstate->sin6)->sin_port=
				htons(0x8000);

#if 0
			if (bind(trtbase->v4icmp_snd,
				&loc_sa4, sizeof(loc_sa4)) == -1)
			{
				crondlog(DIE9 "bind failed");
			}
#endif

			if (connect(trtbase->v4icmp_snd,
				&trtstate->sin6, trtstate->socklen) == -1)
			{
				crondlog(DIE9 "connect failed");
			}
			trtstate->loc_socklen= sizeof(trtstate->loc_sin6);
			if (getsockname(trtbase->v4icmp_snd,
				&trtstate->loc_sin6,
				&trtstate->loc_socklen) == -1)
			{
				crondlog(DIE9 "getsockname failed");
			}
#if 0
			printf("Got localname: %s\n",
				inet_ntoa(((struct sockaddr_in *)
				&trtstate->loc_sin6)->sin_addr));
#endif
		}
	}
	else
	{
		if (trtstate->do_v6)
		{
			int sock;

			memset(&loc_sa6, '\0', sizeof(loc_sa6));
			loc_sa6.sin6_family= AF_INET6;
			sock= trtbase->v6udp_snd;

			if (connect(sock,
				&trtstate->sin6, trtstate->socklen) == -1)
			{
				serrno= errno;

				snprintf(line, sizeof(line),
			", \"error\":\"connect failed: %s\" }",
					strerror(serrno));
				add_str(trtstate, line);
				report(trtstate);
				return;
			}
			trtstate->loc_socklen= sizeof(trtstate->loc_sin6);
			if (getsockname(sock,
				&trtstate->loc_sin6,
				&trtstate->loc_socklen) == -1)
			{
				crondlog(DIE9 "getsockname failed");
			}

#if 0
			printf("Got localname: %s:%d\n",
				inet_ntop(AF_INET6,
				&trtstate->loc_sin6.sin6_addr,
				buf, sizeof(buf)),
				ntohs(((struct sockaddr_in *)&trtstate->
					loc_sin6)->sin_port));
#endif
		}
		else
		{
			int sock;

			memset(&loc_sa4, '\0', sizeof(loc_sa4));
			loc_sa4.sin_family= AF_INET;
			if (trtstate->parismod)
			{
				loc_sa4.sin_port= htons(BASE_PORT +
					trtstate->paris % trtstate->parismod);

				/* Also set destination port */
				((struct sockaddr_in *)&trtstate->sin6)->
					sin_port= htons(BASE_PORT +
					trtstate->index);

				sock= socket(AF_INET, SOCK_DGRAM, 0);
				if (sock == -1)
				{
					crondlog(DIE9 "socket failed");
				}
				if (bind(sock, &loc_sa4, sizeof(loc_sa4)) == -1)
				{
					crondlog(DIE9 "bind failed");
				}
			}
			else
			{
				sock= trtbase->v4udp_snd;
			}


			if (connect(sock,
				&trtstate->sin6, trtstate->socklen) == -1)
			{
				crondlog(DIE9 "connect failed");
			}
			trtstate->loc_socklen= sizeof(trtstate->loc_sin6);
			if (getsockname(sock,
				&trtstate->loc_sin6,
				&trtstate->loc_socklen) == -1)
			{
				crondlog(DIE9 "getsockname failed");
			}
			if (trtstate->parismod)
				close(sock);
#if 0
			printf("Got localname: %s:%d\n",
				inet_ntoa(((struct sockaddr_in *)
				&trtstate->loc_sin6)->sin_addr),
				ntohs(((struct sockaddr_in *)&trtstate->
					loc_sin6)->sin_port));
#endif
		}
	}

	add_str(trtstate, ", \"result\": [ ");

	send_pkt(trtstate);
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
	free(trtstate->out_filename);
	trtstate->out_filename= NULL;

	free(trtstate);

	return 1;
}

struct testops traceroute_ops = { traceroute_init, traceroute_start,
	traceroute_delete };

