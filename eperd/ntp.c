/*
 * Copyright (c) 2013-2014 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * traceroute.c
 */

#include "libbb.h"
#include <math.h>
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

#define NTP_PORT	123

#define NTP_OPT_STRING ("!46c:i:w:A:O:R:W:")

#define OPT_4	(1 << 0)
#define OPT_6	(1 << 1)

#define IPHDR              20

#define SRC_BASE_PORT	(20480)
#define MAX_DATA_SIZE   (4096)

#define DBQ(str) "\"" #str "\""

struct ntp_ts
{
	uint32_t ntp_seconds;
	uint32_t ntp_fraction;
};

struct ntpbase
{
	struct event_base *event_base;

	int my_pid;

	struct ntpstate **table;
	int tabsiz;

	/* For standalone traceroute. Called when a traceroute instance is
	 * done. Just one pointer for all instances. It is up to the caller
	 * to keep it consistent.
	 */
	void (*done)(void *state);

	u_char packet[MAX_DATA_SIZE];
};

struct ntpstate
{
	/* Parameters */
	char *atlas;
	char *hostname;
	char *destportstr;
	char *out_filename;
	char *interface;
	char do_v6;
	char count;
	unsigned timeout;
	char *response_in;	/* Fuzzing */
	char *response_out;

	/* Base and index in table */
	struct ntpbase *base;
	int index;

	struct sockaddr_in6 sin6;
	socklen_t socklen;
	struct sockaddr_in6 loc_sin6;
	socklen_t loc_socklen;

	int sent;
	uint16_t seq;
	int socket;			/* Socket for sending and receiving */
	struct event event_socket;	/* Event for this socket */
	unsigned first:1;		/* Waiting for first response */
	unsigned done:1;		/* We got something from the target
					 * host or a destination unreachable.
					 */
	unsigned not_done:1;		/* Not got something else */
	unsigned busy:1;		/* Busy, do not start another one */
	unsigned gotresp:1;		/* Got a response to the last packet
					 * we sent. For dup detection.
					 */
	unsigned dnsip:1;		/* Busy with dns name resolution */
	struct evutil_addrinfo *dns_res;
	struct evutil_addrinfo *dns_curr;

	time_t starttime;
	struct timeval xmit_time;

	uint8_t ntp_flags;
	uint8_t ntp_stratum;
	int8_t ntp_poll;
	int8_t ntp_precision;
	uint32_t ntp_root_delay;
	uint32_t ntp_root_dispersion;
	uint32_t ntp_reference_id;
	struct ntp_ts ntp_reference_ts;

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

static struct ntpbase *ntp_base;

struct ntphdr
{
	uint8_t ntp_flags;
	uint8_t ntp_stratum;
	int8_t ntp_poll;
	int8_t ntp_precision;
	uint32_t ntp_root_delay;
	uint32_t ntp_root_dispersion;
	uint32_t ntp_reference_id;
	struct ntp_ts ntp_reference_ts;
	struct ntp_ts ntp_origin_ts;
	struct ntp_ts ntp_receive_ts;
	struct ntp_ts ntp_transmit_ts;
};

#define NTP_LI_MASK		0xC0
#define NTP_LI_SHIFT		   6
#define 	LI_NO_WARNING	0
#define 	LI_61		1
#define 	LI_59		2
#define 	LI_UNKNOWN 	3
#define NTP_VERSION		   4
#define NTP_VERSION_MASK	0x38
#define NTP_VERSION_SHIFT	   3
#define NTP_MODE_CLIENT		   3
#define NTP_MODE_MASK		 0x7
#define		MODE_RESERVED	0
#define		MODE_SYM_ACT	1
#define		MODE_SYM_PASS	2
#define		MODE_CLIENT	3
#define		MODE_SERVER	4
#define		MODE_BROADCAST	5
#define		MODE_CONTROL	6
#define		MODE_PRIVATE	7

#define STRATUM_INVALID		 0
#define STRATUM_UNSYNCHRONIZED	16

#define NTP_1970	2208988800UL	/* 1970 - 1900 in seconds */

#define NTP_4G		4294967296.0


static void ready_callback(int __attribute((unused)) unused,
	const short __attribute((unused)) event, void *s);
static int create_socket(struct ntpstate *state);

static void add_str(struct ntpstate *state, const char *str)
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

static void format_li(char *line, size_t size, uint8_t flags)
{
	const char *str;

	switch((flags & NTP_LI_MASK) >> NTP_LI_SHIFT)
	{
	case LI_NO_WARNING:	str= "no"; break;
	case LI_61:		str= "61"; break;
	case LI_59:		str= "59"; break;
	case LI_UNKNOWN:	str= "unknown"; break;
	}
	snprintf(line, size, DBQ(li) ": " DBQ(%s), str);
}

static void format_mode(char *line, size_t size, uint8_t flags)
{
	const char *str;

	switch(flags & NTP_MODE_MASK)
	{
	case MODE_RESERVED:	str= "reserved"; break;
	case MODE_SYM_ACT:	str= "sym. active"; break;
	case MODE_SYM_PASS:	str= "sym. passive"; break;
	case MODE_CLIENT:	str= "client"; break;
	case MODE_SERVER:	str= "server"; break;
	case MODE_BROADCAST:	str= "broadcast"; break;
	case MODE_CONTROL:	str= "control"; break;
	case MODE_PRIVATE:	str= "private"; break;
	}
	snprintf(line, size, DBQ(mode) ": " DBQ(%s), str);
}

static void format_stratum(char *line, size_t size, uint8_t stratum)
{
	const char *str;

	str= NULL;
	switch(stratum)
	{
	case STRATUM_INVALID:		str= "invalid"; break;
	case STRATUM_UNSYNCHRONIZED:	str= "unsynchronized"; break;
	}
	if (str)
	{
		snprintf(line, size, DBQ(stratum) ": " DBQ(%s),
			str);
	}
	else if (stratum < STRATUM_UNSYNCHRONIZED)
	{
		snprintf(line, size, DBQ(stratum) ": %d",
			stratum);
	}
	else
	{
		snprintf(line, size, DBQ(stratum) ": " DBQ(reserved (%d)),
			stratum);
	}
}

static void format_8bit(char *line, size_t size, const char *label, 
	int8_t value)
{
	if (value >= 0 && value < 32)
	{
		snprintf(line, size, DBQ(%s) ": %u", label, 1U << value);
	}
	else
	{
		snprintf(line, size, DBQ(%s) ": %g", label, pow(2, value));
	}
}

static void format_short_ts(char *line, size_t size, const char *label,
	uint32_t value)
{
	snprintf(line, size, DBQ(%s) ": %g", label, value/65536.0);
}

static void format_ref_id(char *line, size_t size, uint32_t value,
	uint8_t stratum)
{
	int i;
	size_t offset;
	unsigned char *p;
	char line2[40];

	if (stratum == 0 || stratum == 1)
	{
		line2[0]= '\0';
		for (i= 0, p= (unsigned char *)&value;
			i<sizeof(value) && *p != '\0'; i++, p++)
		{
			offset= strlen(line2);
			if (*p < 32 || *p == '"' || *p == '\\' ||
				*p >= 127)
			{
				snprintf(line2+offset, sizeof(line2)-offset,
					"\\\\x%02x", *p);
			}
			else
			{
				snprintf(line2+offset, sizeof(line2)-offset,
					"%c", *p);
			}
				
		}
		snprintf(line, size, DBQ(ref-id) ": " DBQ(%s),
			line2);
	}
	else
	{
		snprintf(line, size, DBQ(ref-id) ": " DBQ(%08x),
				ntohl(value));
	}
}

static void format_ts(char *line, size_t size, const char *label,
	struct ntp_ts *ts)
{
	double d;

	d= ntohl(ts->ntp_seconds) + ntohl(ts->ntp_fraction)/NTP_4G;
	snprintf(line, size, DBQ(%s) ": %.9f", label, d);
}

static void report(struct ntpstate *state)
{
	FILE *fh;
	const char *proto;
	char namebuf[NI_MAXHOST];
	char line[80];

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
			", " DBQ(time) ":%ld, ",
			state->atlas, get_atlas_fw_version(),
			get_timesync(),
			state->starttime);
	}

	fprintf(fh, DBQ(dst_name) ":" DBQ(%s),
		state->hostname);

	if (!state->dnsip)
	{
		getnameinfo((struct sockaddr *)&state->sin6, state->socklen,
			namebuf, sizeof(namebuf), NULL, 0, NI_NUMERICHOST);

		fprintf(fh, ", " DBQ(dst_addr) ":" DBQ(%s), namebuf);

		if (state->loc_socklen != 0)
		{
			namebuf[0]= '\0';
			getnameinfo((struct sockaddr *)&state->loc_sin6,
				state->loc_socklen,
				namebuf, sizeof(namebuf), NULL, 0,
				NI_NUMERICHOST);

			fprintf(fh, ", " DBQ(src_addr) ":" DBQ(%s), namebuf);
		}
	}

	proto= "UDP";
	fprintf(fh, ", " DBQ(proto) ":" DBQ(%s) ", " DBQ(af) ": %d",
		proto,
		state->dnsip ? (state->do_v6 ? 6 : 4) :
		(state->sin6.sin6_family == AF_INET6 ? 6 : 4));

	if (!state->first && !state->dnsip)
	{
		format_li(line, sizeof(line), state->ntp_flags);
		fprintf(fh, ", %s", line);
		fprintf(fh, ", " DBQ(version) ": %d", 
			((state->ntp_flags & NTP_VERSION_MASK) >>
			NTP_VERSION_SHIFT));

		format_mode(line, sizeof(line), state->ntp_flags);
		fprintf(fh, ", %s", line);

		format_stratum(line, sizeof(line), state->ntp_stratum);
		fprintf(fh, ", %s", line);

		format_8bit(line, sizeof(line), "poll", state->ntp_poll);
		fprintf(fh, ", %s", line);

		format_8bit(line, sizeof(line), "precision",
			state->ntp_precision);
		fprintf(fh, ", %s", line);

		format_short_ts(line, sizeof(line), "root-delay",
			ntohl(state->ntp_root_delay));
		fprintf(fh, ", %s", line);

		format_short_ts(line, sizeof(line), "root-dispersion",
			ntohl(state->ntp_root_dispersion));
		fprintf(fh, ", %s", line);

		format_ref_id(line, sizeof(line), state->ntp_reference_id,
			state->ntp_stratum);
		fprintf(fh, ", %s", line);

		format_ts(line, sizeof(line), "ref-ts",
			&state->ntp_reference_ts);
		fprintf(fh, ", %s", line);
	}

	fprintf(fh, ", " DBQ(result) ": [ %s ] }\n", state->result);

	free(state->result);
	state->result= NULL;

	if (state->out_filename)
		fclose(fh);

	/* Kill the event and close socket */
	if (state->socket != -1)
	{
		event_del(&state->event_socket);
		close(state->socket);
		state->socket= -1;
	}

	state->busy= 0;

	if (state->base->done)
		state->base->done(state);
}

static void send_pkt(struct ntpstate *state)
{
	int r, len, serrno;
	struct ntpbase *base;
	struct ntphdr *ntphdr;
	double d;
	struct timeval interval;
	char line[80];

	state->gotresp= 0;

	base= state->base;

	if (state->sent >= state->count)
	{
		add_str(state, " }");

		/* We are done */
		report(state);
		return;
	}
	state->seq++;

	ntphdr= (struct ntphdr *)base->packet;
	len= sizeof(*ntphdr);

	memset(ntphdr, '\0', len);
	ntphdr->ntp_flags= (NTP_VERSION << NTP_VERSION_SHIFT) | NTP_MODE_CLIENT;

	gettimeofday(&state->xmit_time, NULL);

	ntphdr->ntp_transmit_ts.ntp_seconds=
		htonl(state->xmit_time.tv_sec + NTP_1970);
	d= state->xmit_time.tv_usec / 1e6;
	d *= NTP_4G;
	ntphdr->ntp_transmit_ts.ntp_fraction= htonl((uint32_t)d);

	if (state->sin6.sin6_family == AF_INET6)
	{
		/* Set port */
		state->sin6.sin6_port= htons(NTP_PORT);

		r= sendto(state->socket, base->packet, len, 0,
			(struct sockaddr *)&state->sin6,
			state->socklen);

#if 0
 { static int doit=1; if (doit && r != -1)
 { errno= ENOSYS; r= -1; } doit= !doit; }
#endif
		serrno= errno;

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
	else
	{
#if 0
		printf(
"send_pkt: sending IPv4 packet, do_icmp %d, parismod %d, index %d, state %p\n",
			state->do_icmp, state->parismod, state->index, state);
#endif

		/* Set port */
		((struct sockaddr_in *)&state->sin6)->sin_port=
			htons(NTP_PORT);

		if (state->response_in)
			r= 0;	/* No need to send */
		else
		{
			r= sendto(state->socket, base->packet, len, 0,
				(struct sockaddr *)&state->sin6,
				state->socklen);
		}

#if 0
{ static int doit=0; if (doit && r != -1)
{ errno= ENOSYS; r= -1; } doit= !doit; }
#endif

		serrno= errno;
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
			ready_callback(0, 0, state);
		else
			ready_callback(0, 0, state);
	}
}

static void ready_callback(int __attribute((unused)) unused,
	const short __attribute((unused)) event, void *s)
{
	struct ntpbase *base;
	struct ntpstate *state;
	int head;
	ssize_t nrecv;
	socklen_t slen;
	double d;
	struct ntphdr *ntphdr;
	struct timeval now;
	struct ntp_ts final_ts;
	struct sockaddr_in remote;
	char line[80];

	gettimeofday(&now, NULL);

	state= s;
	base= state->base;

	slen= sizeof(remote);
	if (state->response_in)
	{
		uint32_t len;
		if (read(state->socket, &len, sizeof(len)) != sizeof(len))
		{
			//printf("ready_callback4: error reading from '%s'\n",
			//	state->response_in);
			//abort();
			crondlog(DIE9 "ready_callback4: error reading from '%s'",
				state->response_in);
		}
		if (len > sizeof(base->packet))
		{
			//printf("ready_callback4: bad value for len: %u\n", len);
			//abort();
			crondlog(DIE9 "ready_callback4: bad value for len: %u",
				 len);
		}
		if (read(state->socket, base->packet, len) != len)
		{
			//printf("ready_callback4: error reading from '%s'\n",
			//	state->response_in);
			//abort();
			crondlog(DIE9 "ready_callback4: error reading from '%s'",
				state->response_in);
		}
		if (read(state->socket, &remote, sizeof(remote)) !=
			sizeof(remote))
		{
			//printf("ready_callback4: error reading from '%s'\n",
			//	state->response_in);
			//abort();
			crondlog(DIE9 "ready_callback4: error reading from '%s'",
				state->response_in);
		}
		nrecv= len;
	}
	else
	{
		nrecv= recvfrom(state->socket, base->packet,
			sizeof(base->packet),
			MSG_DONTWAIT, (struct sockaddr *)&remote, &slen);
	}
	if (nrecv == -1)
	{
		/* Strange, read error */
		printf("ready_callback: read error '%s'\n", strerror(errno));
		return;
	}
	// printf("ready_callback: got packet\n");

	if (state->resp_file_out)
	{
		uint32_t len= nrecv;

		fwrite(&len, sizeof(len), 1, state->resp_file_out);
		fwrite(base->packet, len, 1, state->resp_file_out);
		fwrite(&remote, sizeof(remote), 1, state->resp_file_out);
	}


	if (nrecv < sizeof(*ntphdr))
	{
		/* Short packet */
		printf("ready_callback: too short %d\n", (int)nrecv);
		return;
	}

	if (!state->busy)
	{
printf("%s, %d: sin6_family = %d\n", __FILE__, __LINE__, state->sin6.sin6_family);
		return;
	}

	if (state->open_result)
		add_str(state, " }, { ");

	head= 1;

	ntphdr= (struct ntphdr *)base->packet;

	if (state->first)
	{
		/* Copy mostly static fields */
		state->ntp_flags= ntphdr->ntp_flags;
		state->ntp_stratum= ntphdr->ntp_stratum;
		state->ntp_poll= ntphdr->ntp_poll;
		state->ntp_precision= ntphdr->ntp_precision;
		state->ntp_root_delay= ntphdr->ntp_root_delay;
		state->ntp_root_dispersion= ntphdr->ntp_root_dispersion;
		state->ntp_reference_id= ntphdr->ntp_reference_id;
		state->ntp_reference_ts= ntphdr->ntp_reference_ts;

		state->first= 0;
	}
	else
	{
		if ((ntphdr->ntp_flags & NTP_LI_MASK) !=
			(state->ntp_flags & NTP_LI_MASK))
		{
			format_li(line, sizeof(line), ntphdr->ntp_flags);
			add_str(state, line);
			head= 0;
		}

		if ((ntphdr->ntp_flags & NTP_VERSION_MASK) !=
			(state->ntp_flags & NTP_VERSION_MASK))
		{
			snprintf(line, sizeof(line), ", " DBQ(version) ": %d", 
				((ntphdr->ntp_flags & NTP_VERSION_MASK) >>
				NTP_VERSION_SHIFT));
			add_str(state, line);
			head= 0;
		}

		if ((ntphdr->ntp_flags & NTP_MODE_MASK) !=
			(state->ntp_flags & NTP_MODE_MASK))
		{
			if (!head)
				add_str(state, ", ");
			format_mode(line, sizeof(line), ntphdr->ntp_flags);
			add_str(state, line);
			head= 0;
		}

		if (ntphdr->ntp_stratum != state->ntp_stratum)
		{
			if (!head)
				add_str(state, ", ");
			format_stratum(line, sizeof(line), ntphdr->ntp_stratum);
			add_str(state, line);
			head= 0;
		}

		if (ntphdr->ntp_poll != state->ntp_poll)
		{
			if (!head)
				add_str(state, ", ");
			format_8bit(line, sizeof(line), "poll",
				ntphdr->ntp_poll);
			add_str(state, line);
			head= 0;
		}

		if (ntphdr->ntp_precision != state->ntp_precision)
		{
			if (!head)
				add_str(state, ", ");
			format_8bit(line, sizeof(line), "precision",
				ntphdr->ntp_precision);
			add_str(state, line);
			head= 0;
		}

		if (ntphdr->ntp_root_delay != state->ntp_root_delay)
		{
			if (!head)
				add_str(state, ", ");
			format_short_ts(line, sizeof(line), "root-delay",
				ntohl(ntphdr->ntp_root_delay));
			add_str(state, line);
			head= 0;
		}

		if (ntphdr->ntp_root_dispersion != state->ntp_root_dispersion)
		{
			if (!head)
				add_str(state, ", ");
			format_short_ts(line, sizeof(line), "root-dispersion",
				ntohl(ntphdr->ntp_root_dispersion));
			add_str(state, line);
			head= 0;
		}

		if (ntphdr->ntp_reference_id != state->ntp_reference_id)
		{
			if (!head)
				add_str(state, ", ");
			format_ref_id(line, sizeof(line),
				ntphdr->ntp_reference_id, ntphdr->ntp_stratum);
			add_str(state, line);
			head= 0;
		}

		if (memcmp(&ntphdr->ntp_reference_ts, &state->ntp_reference_ts,
			sizeof(ntphdr->ntp_reference_ts)) != 0)
		{
			if (!head)
				add_str(state, ", ");
			format_ts(line, sizeof(line), "ref-ts",
				&ntphdr->ntp_reference_ts);
			add_str(state, line);
			head= 0;
		}
	}

	d= ntohl(ntphdr->ntp_origin_ts.ntp_seconds) + 
		ntohl(ntphdr->ntp_origin_ts.ntp_fraction)/NTP_4G;
	snprintf(line, sizeof(line), "%s" DBQ(origin-ts) ": %.9f",
		head ? "" : ", ", d);
	head= 0;
	add_str(state, line);

	d= ntohl(ntphdr->ntp_receive_ts.ntp_seconds) + 
		ntohl(ntphdr->ntp_receive_ts.ntp_fraction)/NTP_4G;
	snprintf(line, sizeof(line), ", " DBQ(receive-ts) ": %.9f", d);
	add_str(state, line);

	d= ntohl(ntphdr->ntp_transmit_ts.ntp_seconds) + 
		ntohl(ntphdr->ntp_transmit_ts.ntp_fraction)/NTP_4G;
	snprintf(line, sizeof(line), ", " DBQ(transmit-ts) ": %.9f", d);
	add_str(state, line);

	final_ts.ntp_seconds= now.tv_sec + NTP_1970;
	d= now.tv_usec / 1e6;
	d *= 4294967296.0;
	final_ts.ntp_fraction= d;

	d= final_ts.ntp_seconds + final_ts.ntp_fraction/NTP_4G;
	snprintf(line, sizeof(line), ", " DBQ(final-ts) ": %.9f", d);
	add_str(state, line);

	/* Compute rtt */
	d= final_ts.ntp_seconds - ntohl(ntphdr->ntp_origin_ts.ntp_seconds) -
		(ntohl(ntphdr->ntp_transmit_ts.ntp_seconds) -
		ntohl(ntphdr->ntp_receive_ts.ntp_seconds)) +
		final_ts.ntp_fraction/NTP_4G -
		ntohl(ntphdr->ntp_origin_ts.ntp_fraction)/NTP_4G -
		(ntohl(ntphdr->ntp_transmit_ts.ntp_fraction)/NTP_4G -
		ntohl(ntphdr->ntp_receive_ts.ntp_fraction)/NTP_4G);
	snprintf(line, sizeof(line), ", " DBQ(rtt) ": %f", d);
	add_str(state, line);

	d= (ntohl(ntphdr->ntp_origin_ts.ntp_seconds) +
		final_ts.ntp_seconds)/2.0 -
		(ntohl(ntphdr->ntp_receive_ts.ntp_seconds) +
		ntohl(ntphdr->ntp_transmit_ts.ntp_seconds))/2.0 +
		(ntohl(ntphdr->ntp_origin_ts.ntp_fraction)/NTP_4G +
		final_ts.ntp_fraction/NTP_4G)/2.0 -
		(ntohl(ntphdr->ntp_receive_ts.ntp_fraction)/NTP_4G +
		ntohl(ntphdr->ntp_transmit_ts.ntp_fraction)/NTP_4G)/2.0;
	snprintf(line, sizeof(line), ", " DBQ(offset) ": %f", d);
	add_str(state, line);

	state->open_result= 1;
		
	send_pkt(state);
#if 0
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
#endif
}

#if 0
static void ready_callback6(int __attribute((unused)) unused,
	const short __attribute((unused)) event, void *s)
{
	crondlog(DIE9 "ready_callback6"); abort();
#if 0
	ssize_t nrecv;
	int ind, rcvdttl, nxt, icmp_prefixlen, offset;
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

		state->done= 1;

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

		send_pkt(state);
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
#endif
}
#endif

static struct ntpbase *ntp_base_new(struct event_base
	*event_base)
{
	struct ntpbase *base;

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
	struct ntpstate *state;

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

static void *ntp_init(int __attribute((unused)) argc, char *argv[],
	void (*done)(void *state))
{
	uint32_t opt;
	int i, do_v6;
	unsigned count, timeout;
		/* must be int-sized */
	size_t newsiz;
	char *str_Atlas;
	const char *hostname;
	char *out_filename;
	const char *destportstr;
	char *interface;
	char *response_in, *response_out;
	struct ntpstate *state;
	FILE *fh;

	if (!ntp_base)
	{
		ntp_base= ntp_base_new(EventBase);
		if (!ntp_base)
			crondlog(DIE9 "ntp_base_new failed");
	}

	/* Parse arguments */
	count= 3;
	interface= NULL;
	timeout= 1000;
	str_Atlas= NULL;
	out_filename= NULL;
	response_in= NULL;
	response_out= NULL;
	opt_complementary = "=1:4--6:i--u:c+:w+:";

	opt = getopt32(argv, NTP_OPT_STRING, &count,
		&interface, &timeout, &str_Atlas, &out_filename,
		&response_in, &response_out);
	hostname = argv[optind];

	if (opt == 0xffffffff)
	{
		crondlog(LVL8 "bad options");
		return NULL;
	}

	do_v6= !!(opt & OPT_6);

	if (response_in)
	{
		if (!validate_filename(response_in, ATLAS_FUZZING))
		{
			crondlog(LVL8 "insecure fuzzing file '%s'", response_in);
			return NULL;
		}
	}
	if (response_out)
	{
		if (!validate_filename(response_out, ATLAS_FUZZING))
		{
			crondlog(LVL8 "insecure fuzzing file '%s'", response_out);
			return NULL;
		}
	}

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

	destportstr= "123";

	state= xzalloc(sizeof(*state));
	state->count= count;
	state->interface= interface ? strdup(interface) : NULL;
	state->destportstr= strdup(destportstr);
	state->timeout= timeout*1000;
	state->atlas= str_Atlas ? strdup(str_Atlas) : NULL;
	state->hostname= strdup(hostname);
	state->do_v6= do_v6;
	state->out_filename= out_filename ? strdup(out_filename) : NULL;
	state->response_in= response_in ? strdup(response_in) : NULL;
	state->response_out= response_out ? strdup(response_out) : NULL;
	state->base= ntp_base;
	state->busy= 0;
	state->result= NULL;
	state->reslen= 0;
	state->resmax= 0;

	for (i= 0; i<ntp_base->tabsiz; i++)
	{
		if (ntp_base->table[i] == NULL)
			break;
	}
	if (i >= ntp_base->tabsiz)
	{
		newsiz= 2*ntp_base->tabsiz;
		ntp_base->table= xrealloc(ntp_base->table,
			newsiz*sizeof(*ntp_base->table));
		for (i= ntp_base->tabsiz; i<newsiz; i++)
			ntp_base->table[i]= NULL;
		i= ntp_base->tabsiz;
		ntp_base->tabsiz= newsiz;
	}
	state->index= i;
	ntp_base->table[i]= state;
	ntp_base->done= done;

	memset(&state->loc_sin6, '\0', sizeof(state->loc_sin6));
	state->loc_socklen= 0;

	evtimer_assign(&state->timer, state->base->event_base,
		noreply_callback, state);

	return state;
}

static void traceroute_start2(void *state)
{
	struct ntpstate *ntpstate;

	ntpstate= state;

	if (ntpstate->busy)
	{
		printf("ntp_start: busy, can't start\n");
		return;
	}
	ntpstate->busy= 1;

	ntpstate->min= ULONG_MAX;
	ntpstate->max= 0;
	ntpstate->sum= 0;
	ntpstate->sentpkts= 0;
	ntpstate->rcvdpkts= 0;
	ntpstate->duppkts= 0;

	ntpstate->sent= 0;
	ntpstate->seq= 0;
	ntpstate->first= 1;
	ntpstate->done= 0;
	ntpstate->not_done= 0;

	if (ntpstate->result) free(ntpstate->result);
	ntpstate->resmax= 80;
	ntpstate->result= xmalloc(ntpstate->resmax);
	ntpstate->reslen= 0;
	ntpstate->open_result= 0;
	ntpstate->starttime= time(NULL);

	ntpstate->socket= -1;

	if (create_socket(ntpstate) == -1)
		return;
	if (ntpstate->do_v6)
	{
		ntpstate->loc_sin6.sin6_port= htons(SRC_BASE_PORT +
			ntpstate->index);
	}
	else
	{
		((struct sockaddr_in *)(&ntpstate->loc_sin6))->
			sin_port= htons(SRC_BASE_PORT +
			ntpstate->index);
	}

	send_pkt(ntpstate);
}

static int create_socket(struct ntpstate *state)
{
	int af, type, protocol;
	int r, serrno;
	char line[80];

	af= (state->do_v6 ? AF_INET6 : AF_INET);
	type= SOCK_DGRAM;
	protocol= 0;

	if (state->response_in)
	{
		state->socket= open(state->response_in, O_RDONLY);
		if (state->socket == -1)
		{
			crondlog(DIE9 "unable to open '%s'",
				state->response_in);
		}
	}
	else
		state->socket= xsocket(af, type, protocol);
#if 0
 { errno= ENOSYS; state->socket= -1; }
#endif
	if (state->socket == -1)
	{
		serrno= errno;

		snprintf(line, sizeof(line),
	"{ " DBQ(error) ":" DBQ(socket failed: %s) " }",
			strerror(serrno));
		add_str(state, line);
		report(state);
		return -1;
	} 

	if (state->interface)
	{
		if (bind_interface(state->socket,
			af, state->interface) == -1)
		{
			snprintf(line, sizeof(line),
	"{ " DBQ(error) ":" DBQ(bind_interface failed) " }");
			add_str(state, line);
			report(state);
			return -1;
		}
	}

	if (state->response_in)
		r= 0;	/* No need to connect */
	else
	{
		r= connect(state->socket,
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
			"{ " DBQ(error) ":" DBQ(connect failed: %s) " }",
			strerror(serrno));
		add_str(state, line);
		report(state);
		return -1;
	}
	state->loc_socklen= sizeof(state->loc_sin6);
	if (!state->response_in && getsockname(state->socket,
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


	event_assign(&state->event_socket, state->base->event_base,
		state->socket,
		EV_READ | EV_PERSIST,
		(af == AF_INET6 ? ready_callback : ready_callback),
		state);
	event_add(&state->event_socket, NULL);

	return 0;
}

static void dns_cb(int result, struct evutil_addrinfo *res, void *ctx)
{
	int r, count;
	struct ntpstate *env;
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
			env->dnsip= 1;
			report(env);
			return;
		}

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

static void ntp_start(void *state)
{
	struct ntpstate *ntpstate;
	struct evutil_addrinfo hints;

	ntpstate= state;

	if (ntpstate->response_out)
	{
		ntpstate->resp_file_out= fopen(ntpstate->response_out, "w");
		if (!ntpstate->resp_file_out)
		{
			crondlog(DIE9 "unable to write to '%s'",
				ntpstate->response_out);
		}
	}


	memset(&hints, '\0', sizeof(hints));
	hints.ai_socktype= SOCK_DGRAM;
	hints.ai_family= ntpstate->do_v6 ? AF_INET6 : AF_INET;
	ntpstate->dnsip= 1;
	(void) evdns_getaddrinfo(DnsBase, ntpstate->hostname,
		ntpstate->destportstr, &hints, dns_cb, ntpstate);
}

static int ntp_delete(void *state)
{
	int ind;
	struct ntpstate *ntpstate;
	struct ntpbase *base;

	ntpstate= state;

	printf("ntp_delete: state %p, index %d, busy %d\n",
		state, ntpstate->index, ntpstate->busy);

	if (ntpstate->busy)
		return 0;

	base= ntpstate->base;
	ind= ntpstate->index;

	if (base->table[ind] != ntpstate)
		crondlog(DIE9 "strange, state not in table");
	base->table[ind]= NULL;

	event_del(&ntpstate->timer);

	free(ntpstate->atlas);
	ntpstate->atlas= NULL;
	free(ntpstate->hostname);
	ntpstate->hostname= NULL;
	free(ntpstate->destportstr);
	ntpstate->destportstr= NULL;
	free(ntpstate->out_filename);
	ntpstate->out_filename= NULL;
	free(ntpstate->interface);
	ntpstate->interface= NULL;

	free(ntpstate);

	return 1;
}

struct testops ntp_ops = { ntp_init, ntp_start, ntp_delete };

