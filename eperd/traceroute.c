/*
traceroute.c
*/

#include "libbb.h"
#include <event2/event.h>
#include <event2/event_struct.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

#include "eperd.h"
#include "evping.h"

#define TRACEROUTE_OPT_STRING ("46iuFa:c:A:O:S:")

#define OPT_4	(1 << 0)
#define OPT_6	(1 << 1)
#define OPT_i	(1 << 2)
#define OPT_u	(1 << 3)
#define OPT_F	(1 << 4)

#define BASE_PORT	(0x8000 + 666)
#define MAX_DATA_SIZE   (4096)
#define TIMEOUT		(1)	/* In seconds */

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
	unsigned char maxhops;
	unsigned char gaplimit;
	unsigned char parismod;

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
	char namebuf[NI_MAXHOST];

	/* Should go to output file */

	event_del(&state->timer);

	if (state->atlas)
		printf("%s %ld ", state->atlas, (long)time(NULL));

	getnameinfo((struct sockaddr *)&state->sin6, state->socklen,
		namebuf, sizeof(namebuf), NULL, 0, NI_NUMERICHOST);

	printf("%s %s ", state->hostname, namebuf);
	printf("%c%c ", state->do_icmp ? 'I' : 'U',
		state->sin6.sin6_family == AF_INET6 ? '6' : '4');

	printf("size:%d ", state->maxpacksize);
	if (state->parismod)
	printf("paris-id:%d ", state->paris % state->parismod);
	printf("%s <EOL>\n", state->result);
	free(state->result);
	state->result= NULL;
	state->busy= 0;
}

static void send_pkt(struct trtstate *state)
{
	int r, hop, len, on;
	uint16_t sum;
	unsigned usum;
	struct trtbase *base;
	struct icmp *icmp_hdr;
	struct timeval interval = { TIMEOUT, 0 };
	char line[80];
	char id[]= "http://atlas.ripe.net Randy Bush, Atlas says Hi!";

	base= state->base;

	if (state->sent >= state->trtcount)
	{
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
			printf("gaplimit reached: %d > %d + %d\n",
				state->hop, state->last_response_hop,
				state->gaplimit);
			if (state->lastditch)
			{
				/* Also done with last-ditch probe. */
				report(state);
				return;
			}
			state->lastditch= 1;
			state->hop= 255;
		}

		snprintf(line, sizeof(line), "hop:%d ", state->hop);
		add_str(state, line);
	}
	state->seq++;

	gettimeofday(&state->xmit_time, NULL);

	if (state->sin6.sin6_family == AF_INET6)
	{
		printf("send_pkt: sending IPv6 packet\n");

		hop= state->hop;

		/* Set port */
		state->sin6.sin6_port= htons(BASE_PORT + hop);

		/* Set hop count */
#if 0
		setsockopt(base->v6udp, SOL_IPV6, IPV6_UNICAST_HOPS,
			&hop, sizeof(hop));
#endif

		len= 8;	/* Should figure out what to do with payload */

		r= sendto(base->v6udp_snd, base->packet, len, 0,
			&state->sin6, state->socklen);
		if (r == -1)
		{
			printf("send_pkt: sendto failed: %s\n",
				strerror(errno));
			return;
		}
	}
	else
	{
		printf("send_pkt: sending IPv4 packet\n");

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

			printf(
			"send_pkt: seq %d, paris %d, icmp_cksum= htons(%d)\n",
				state->seq, state->paris,
				ntohs(icmp_hdr->icmp_cksum));

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
				printf("send_pkt: sendto failed: %s\n",
					strerror(errno));
				state->sent++;
				return;
			}
		}
		else
		{
			hop= state->hop;

			/* Set port */
			((struct sockaddr_in *)&state->sin6)->sin_port=
				htons(BASE_PORT + hop);

			/* Set hop count */
			setsockopt(base->v4udp_snd, IPPROTO_IP, IP_TTL,
				&hop, sizeof(hop));

			len= 8;	/* Should figure out what to do with payload */

			r= sendto(base->v4udp_snd, base->packet, len, 0,
				&state->sin6, state->socklen);
			if (r == -1)
			{
				printf("send_pkt: sendto failed: %s\n",
					strerror(errno));
				return;
			}
		}
	}

	/* Increment packets sent */
	state->sent++;

	/* Set timer */
	evtimer_add(&state->timer, &interval);

}

static void ready_callback4(int __attribute((unused)) unused,
	const short __attribute((unused)) event, void *s)
{
	struct trtbase *base;
	struct trtstate *state;
	int hlen, ehlen, ind, nextmtu;
	ssize_t nrecv;
	socklen_t slen;
	struct ip *ip, *eip;
	struct icmp *icmp, *eicmp;
	struct udphdr *eudp;
	double ms;
	struct timeval now;
	struct sockaddr_in remote;
	char line[80];

	gettimeofday(&now, NULL);

	printf("in ready_callback4\n");

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

		/* Make sure we have UDP */
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

			ind= 0;	/* Should compute index */

			if (ind >= base->tabsiz)
			{
				/* Out of range */
				return;
			}

			state= base->table[ind];
			if (!state)
			{
				/* Nothing here */
				return;
			}

			printf("ready_callback4: from %s",
				inet_ntoa(remote.sin_addr));
			printf(" for %s hop %d\n",
				inet_ntoa(((struct sockaddr_in *)
				&state->sin6)->sin_addr), state->hop);

			if (icmp->icmp_type == ICMP_DEST_UNREACH)
			{
				/* Done? */
				event_del(&state->timer);

				return;
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

			if (ntohs(eicmp->icmp_cksum) != state->paris)
			{
				printf(
	"ready_callback4: mismatch for paris, got 0x%x, expected 0x%x\n",
					ntohs(eicmp->icmp_cksum), state->paris);
			}
			if (ntohs(eicmp->icmp_seq) != state->seq)
			{
				printf(
	"ready_callback4: mismatch for seq, got 0x%x, expected 0x%x\n",
					ntohs(eicmp->icmp_seq), state->seq);
			}

			state->last_response_hop= state->hop;

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
				printf(
				"ready_callback4: changed destination %s\n",
					inet_ntoa(eip->ip_dst));
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

			snprintf(line, sizeof(line), "from:%s ",
				inet_ntoa(remote.sin_addr));
			add_str(state, line);
			snprintf(line, sizeof(line), "ttl:%d rtt:%.3f size:%d ",
				ip->ip_ttl, ms, (int)nrecv);
			add_str(state, line);

			printf("ready_callback4: from %s, ttl %d",
				inet_ntoa(remote.sin_addr), ip->ip_ttl);
			printf(" for %s hop %d\n",
				inet_ntoa(((struct sockaddr_in *)
				&state->sin6)->sin_addr), state->hop);

			if (icmp->icmp_type == ICMP_TIME_EXCEEDED)
				state->not_done= 1;
			else if (icmp->icmp_type == ICMP_DEST_UNREACH)
			{
				state->done= 1;
				switch(icmp->icmp_code)
				{
				case ICMP_UNREACH_NET:
					add_str(state, "!N ");
					break;
				case ICMP_UNREACH_HOST:
					add_str(state, "!H ");
					break;
				case ICMP_UNREACH_PROTOCOL:
					add_str(state, "!P ");
					break;
				case ICMP_UNREACH_PORT:
					add_str(state, "!p ");
					break;
				case ICMP_UNREACH_NEEDFRAG:
					nextmtu= ntohs(icmp->icmp_nextmtu);
					snprintf(line, sizeof(line), "!F=%d ",
						nextmtu);
					add_str(state, line);
					if (nextmtu >= sizeof(*ip))
					{
						nextmtu -= sizeof(*ip);
						if (nextmtu <
							state->curpacksize)
						{
							state->curpacksize=
								nextmtu;
						}
					}
					state->not_done= 1;
					break;
				case ICMP_UNREACH_FILTER_PROHIB:
					add_str(state, "!A ");
					break;
				default:
					snprintf(line, sizeof(line), "!%d ",
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
			printf("ready_callback4: not UDP\n");
			return;
		}


		send_pkt(state);
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

		if (ntohs(icmp->icmp_seq) != state->seq)
		{
			printf(
"ready_callback4: mismatch for seq, got 0x%x, expected 0x%x\n",
				ntohs(icmp->icmp_seq), state->seq);
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

		snprintf(line, sizeof(line), "from:%s ",
			inet_ntoa(remote.sin_addr));
		add_str(state, line);
		snprintf(line, sizeof(line), "ttl:%d rtt:%.3f ms",
			ip->ip_ttl, ms);
		add_str(state, line);

		printf("ready_callback4: from %s, ttl %d",
			inet_ntoa(remote.sin_addr), ip->ip_ttl);
		printf(" for %s hop %d\n",
			inet_ntoa(((struct sockaddr_in *)
			&state->sin6)->sin_addr), state->hop);

		/* Done */
		state->done= 1;

		send_pkt(state);

		return;
	}
	else if (icmp->icmp_type == ICMP_ECHO)
	{
		/* No need to do anything */
	}
	else
	{
		printf("got type %d\n", icmp->icmp_type);
		abort();
	}
}

static void ready_callback6(int __attribute((unused)) unused,
	const short __attribute((unused)) event, void *s)
{
	printf("in ready_callback6\n");

	//abort();
}

static struct trtbase *traceroute_base_new(struct event_base
	*event_base)
{
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

	event_assign(&base->event4, base->event_base, base->v4icmp_rcv,
		EV_READ | EV_PERSIST, ready_callback4, base);
	event_assign(&base->event6, base->event_base, base->v4icmp_rcv,
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

	add_str(state, "* ");

	send_pkt(state);
}

static void *traceroute_init(int __attribute((unused)) argc, char *argv[])
{
	int i, opt, do_icmp, do_v6, dont_fragment;
	unsigned trtcount, maxpacksize, parismod; /* must be int-sized */
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
	parismod= 0;
	trtcount= 3;
	maxpacksize= 40;
	out_filename= NULL;
	opt_complementary = "=1:4--6:i--u:a+:c+:S+";
	opt = getopt32(argv, TRACEROUTE_OPT_STRING, &parismod, &trtcount,
		&str_Atlas, &out_filename, &maxpacksize);
	hostname = argv[optind];

	do_icmp= !!(opt & OPT_i);
	do_v6= !!(opt & OPT_6);
	dont_fragment= !!(opt & OPT_F);
	if (maxpacksize > sizeof(trt_base->packet))
		maxpacksize= sizeof(trt_base->packet);

	/* Attempt to resolve 'name' */
	af= AF_UNSPEC;
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
	state->trtcount= trtcount;
	state->maxpacksize= maxpacksize;
	state->maxhops= 32;
	state->gaplimit= 5;
	state->atlas= strdup(str_Atlas);
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
		crondlog(DIE9 "should resize tabel");
	}
	state->index= i;
	trt_base->table[i]= state;

	memcpy(&state->sin6, &lsa->u.sa, lsa->len);
	state->socklen= lsa->len;
	free(lsa); lsa= NULL;


	evtimer_assign(&state->timer, state->base->event_base,
		noreply_callback, state);

	return state;
}

static void traceroute_start(void *state)
{
	struct trtstate *trtstate;
	struct trtbase *trtbase;
	struct sockaddr_in loc_sa4;
	struct sockaddr_in6 loc_sa6;
	char line[80];

	printf("in traceroute_start\n");

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

	trtstate->hop= 1;
	trtstate->sent= 0;
	trtstate->seq++;
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

	snprintf(line, sizeof(line), "hop:%d ", trtstate->hop);
	add_str(trtstate, line);

	if (trtstate->do_icmp)
	{
		if (trtstate->do_v6)
		{
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
			printf("Got localname: %s\n",
				inet_ntoa(((struct sockaddr_in *)
				&trtstate->loc_sin6)->sin_addr));
		}
	}

	send_pkt(trtstate);
}

static int traceroute_delete(void *state)
{
	struct trtstate *trtstate;

	trtstate= state;

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

