/*
 * Copyright (c) 2013-2014 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * ntp.c
 */

#include "libbb.h"
#include <assert.h>
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

#define SAFE_PREFIX_REL ATLAS_DATA_NEW_REL

#define DBQ(str) "\"" #str "\""

#ifndef STANDALONE_BUSYBOX
#define uh_sport source
#define uh_dport dest
#define uh_ulen len
#define uh_sum check
#endif

#define NTP_PORT	123

#define NTP_OPT_STRING ("!46c:i:s:w:A:B:O:R:W:")

#define OPT_4	(1 << 0)
#define OPT_6	(1 << 1)

#define IPHDR              20

#define SRC_BASE_PORT	(20480)
#define MAX_DATA_SIZE   (4096)

#define DBQ(str) "\"" #str "\""

#define RESP_PACKET		1
#define RESP_SOCKNAME		2
#define RESP_DSTADDR		3
#define RESP_TIMEOFDAY		4
#define RESP_ADDRINFO		5
#define RESP_ADDRINFO_SA	6

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

	/* For standalone ntp. Called when a ntp instance is
	 * done. Just one pointer for all instances. It is up to the caller
	 * to keep it consistent.
	 */
	void (*done)(void *state, int error);

	u_char packet[MAX_DATA_SIZE];
};

struct ntpstate
{
	/* Parameters */
	char *atlas;
	char *bundle;
	char *hostname;
	char *destportstr;
	char *out_filename;
	char *interface;
	char do_v6;
	char count;
	uint16_t size;
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
	unsigned report_dst:1;		/* Report dst anyhow */
	struct evutil_addrinfo *dns_res;
	struct evutil_addrinfo *dns_curr;

	time_t starttime;
	struct timeval xmit_time;

	struct timespec start_time;	/* At the moment only for
					 * DNS resolution
					 */
	double ttr;			/* Time to resolve a name, in ms */


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

struct ntpextension
{
	uint16_t ext_type;
	uint16_t ext_length;
};

/* RFC 5906 NTP Autokey extensions */
#define	NTP_EXT_REQUEST	0x0000
#define	NTP_EXT_MESSAGE	0x0002
#define	NTP_EXT_ERROR		0x4000
#define	NTP_EXT_RESPONSE	0x8000
#define	NTP_EXT_NOOP		0x0000
#define	NTP_EXT_ASSOC		0x0100
#define	NTP_EXT_CERT		0x0200
#define	NTP_EXT_COOKIE		0x0300
#define	NTP_EXT_AUTOKEY		0x0400
#define	NTP_EXT_LEAPSECS	0x0500
#define	NTP_EXT_SIGN		0x0600
#define	NTP_EXT_IFF_IDENT	0x0700
#define	NTP_EXT_GQ_IDENT	0x0800
#define	NTP_EXT_MV_IDENT	0x0900

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
	int r;
	FILE *fh;
	const char *proto;
	struct addrinfo *ai;
	char namebuf[NI_MAXHOST];
	char line[80];
	struct addrinfo hints;

	event_del(&state->timer);

	if (state->out_filename)
	{
		fh= fopen(state->out_filename, "a");
		if (!fh)
			crondlog(DIE9 "ntp: unable to append to '%s'",
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
			", " DBQ(time) ":%ld, ",
			state->atlas, atlas_get_version_json_str(),
			get_timesync(),
			state->starttime);
		if (state->bundle)
			fprintf(fh, DBQ(bundle) ":%s, ", state->bundle);
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

	if (!state->dnsip || state->report_dst)
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
		state->base->done(state, 0);
}

static void send_pkt(struct ntpstate *state)
{
	int r, len, serrno;
	struct ntpbase *base;
	struct ntphdr *ntphdr;
	struct ntpextension *ntpextension;
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

	if (state->size > 0) {
		ntpextension= base->packet + len;
		memset(ntpextension, '\0', state->size);
		// NTP autokey (RFC5906) no-operation request
		ntpextension->ext_type= htons(NTP_EXT_MESSAGE | NTP_EXT_REQUEST | NTP_EXT_NOOP);
		ntpextension->ext_length= htons(state->size);
		len+= state->size;
	}

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

		if (state->response_in)
		{
			/* Assume the send succeeded */
			r= len;
		}
		else
		{
			r= sendto(state->socket, base->packet, len, 0,
				(struct sockaddr *)&state->sin6,
				state->socklen);
		}

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

	state= s;

	if (state->response_in)
	{
		size_t len;

		len= sizeof(now);
		read_response(state->socket, RESP_TIMEOFDAY,
				&len, &now);
	}
	else
	{
		gettimeofday(&now, NULL);
		if (state->resp_file_out)
		{
			write_response(state->resp_file_out, RESP_TIMEOFDAY,
				sizeof(now), &now);
		}
	}

	base= state->base;

	slen= sizeof(remote);
	if (state->response_in)
	{
		size_t len;

		len= sizeof(base->packet);
		read_response(state->socket, RESP_PACKET,
			&len, base->packet);
		nrecv= len;
		len= sizeof(remote);
		read_response(state->socket, RESP_DSTADDR,
			&len, &remote);
		slen= len;
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
		write_response(state->resp_file_out, RESP_PACKET,
			nrecv, base->packet);
		write_response(state->resp_file_out, RESP_DSTADDR,
			sizeof(remote), &remote);
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
}

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
	void (*done)(void *state, int error))
{
	uint32_t opt;
	int i, do_v6;
	unsigned count, timeout, size;
		/* must be int-sized */
	size_t newsiz;
	char *str_Atlas;
	char *str_bundle;
	const char *hostname;
	char *out_filename;
	const char *destportstr;
	char *interface;
	char *response_in, *response_out;
	char *validated_response_in= NULL;
	char *validated_response_out= NULL;
	char *validated_out_filename= NULL;
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
	size= 0;
	interface= NULL;
	timeout= 1000;
	str_Atlas= NULL;
	str_bundle= NULL;
	out_filename= NULL;
	response_in= NULL;
	response_out= NULL;
	opt_complementary = "=1:4--6:i--u:c+:s+:w+:";

	opt = getopt32(argv, NTP_OPT_STRING, &count,
		&interface, &size, &timeout, &str_Atlas, &str_bundle, &out_filename,
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
		validated_response_in= rebased_validated_filename(response_in,
			ATLAS_FUZZING_REL);
		if (!validated_response_in)
		{
			crondlog(LVL8 "insecure fuzzing file '%s'",
				response_in);
			goto err;
		}
	}
	if (response_out)
	{
		validated_response_out= rebased_validated_filename(response_out,
			ATLAS_FUZZING_REL);
		if (!validated_response_out)
		{
			crondlog(LVL8 "insecure fuzzing file '%s'",
				response_out);
			goto err;
		}
	}

	if (out_filename)
	{
		validated_out_filename= rebased_validated_filename(out_filename,
			SAFE_PREFIX_REL);
		if (!validated_out_filename)
		{
			crondlog(LVL8 "insecure file '%s'", out_filename);
			goto err;
		}
		fh= fopen(validated_out_filename, "a");
		if (!fh)
		{
			crondlog(LVL8 "ntp: unable to append to '%s'",
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

        // sanity check: ntp_base->packet isn't smaller than expected
        if (size > sizeof(ntp_base->packet) - sizeof(struct ntphdr)) {
		crondlog(LVL8 "ntp: packet buffer only allows %u bytes maximum", sizeof(ntp_base->packet) - sizeof(struct ntphdr));
		goto err;
        }
	// trying to avoid fragmentation: 1280 mtu - 48 ntp - 8 udp - 40 ipv6
	// chrony has a max of 1092 byte extensions
	if (size > 1184) {
		crondlog(LVL8 "ntp: maximum extension size is 1184 bytes");
		goto err;
	}
	if (size > 0 && size < 28) {
		crondlog(LVL8 "ntp: mimimum extension size is 28 bytes per RFC7822");
		goto err;
	}
	if (size % 4 != 0) {
		crondlog(LVL8 "ntp: extension field size is a multiple of 4 per RFC7822");
		goto err;
	}

	destportstr= "123";

	state= xzalloc(sizeof(*state));
	state->count= count;
	state->interface= interface ? strdup(interface) : NULL;
	state->size= size;
	state->destportstr= strdup(destportstr);
	state->timeout= timeout*1000;
	state->atlas= str_Atlas ? strdup(str_Atlas) : NULL;
	state->bundle= str_bundle ? strdup(str_bundle) : NULL;
	state->hostname= strdup(hostname);
	state->do_v6= do_v6;
	state->out_filename= validated_out_filename;
		validated_out_filename= NULL;
	state->response_in= validated_response_in;
		validated_response_in= NULL;
	state->response_out= validated_response_out;
		validated_response_out= NULL;
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

err:
	if (validated_response_in) free(validated_response_in);
	if (validated_response_out) free(validated_response_out);
	if (validated_out_filename) free(validated_out_filename);
	return NULL;
}

static void ntp_start2(void *state)
{
	struct ntpstate *ntpstate;

	ntpstate= state;

	if (!ntpstate->busy)
	{
		printf("ntp_start: not busy, can't continue\n");
		return;
	}

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
	ntpstate->starttime= atlas_time();

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

	if (!state->response_in)
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
	if (state->response_in)
	{
		size_t len;

		len= sizeof(state->loc_sin6);
		read_response(state->socket, RESP_SOCKNAME,
			&len, &state->loc_sin6);
		state->loc_socklen= len;
	}
	else
	{
		if (getsockname(state->socket,
			&state->loc_sin6,
			&state->loc_socklen) == -1)
		{
			crondlog(DIE9 "getsockname failed");
		}
		if (state->resp_file_out)
		{
			write_response(state->resp_file_out,
				RESP_SOCKNAME, state->loc_socklen,
				&state->loc_sin6);
		}
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
	if (!state->response_in)
		event_add(&state->event_socket, NULL);

	return 0;
}

static void dns_cb(int result, struct evutil_addrinfo *res, void *ctx)
{
	int r;
	size_t tmp_len;
	struct ntpstate *env;
	double nsecs;
	struct timespec now, elapsed;
	struct addrinfo tmp_res;
	struct sockaddr_storage tmp_sockaddr;
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
	env->report_dst= 0;

	env->dns_res= res;
	env->dns_curr= res;

	if (env->response_in)
	{
	
		env->socket= open(env->response_in, O_RDONLY);
		if (env->socket == -1)
		{
			crondlog(DIE9 "unable to open '%s'",
				env->response_in);
		}
	
		tmp_len= sizeof(tmp_res);
		read_response(env->socket, RESP_ADDRINFO, &tmp_len, &tmp_res);
		assert(tmp_len == sizeof(tmp_res));
		tmp_len= sizeof(tmp_sockaddr);
		read_response(env->socket, RESP_ADDRINFO_SA,
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
			env->dnsip= 1;
			env->report_dst= 1;
			report(env);
			return;
		}

		ntp_start2(env);

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

static void ntp_start(void *state)
{
	struct ntpstate *ntpstate;
	struct evutil_addrinfo hints;

	ntpstate= state;

	if (ntpstate->busy)
	{
		printf("ntp_start: busy, can't start\n");
		return;
	}
	ntpstate->busy= 1;

	ntpstate->socket= -1;

	if (ntpstate->response_out)
	{
		ntpstate->resp_file_out= fopen(ntpstate->response_out, "w");
		if (!ntpstate->resp_file_out)
		{
			crondlog(DIE9 "unable to write to '%s'",
				ntpstate->response_out);
		}
	}


	if (ntpstate->response_in)
	{
		ntpstate->dnsip= 1;
		dns_cb(0, 0, ntpstate);
	}
	else
	{
		memset(&hints, '\0', sizeof(hints));
		hints.ai_socktype= SOCK_DGRAM;
		hints.ai_family= ntpstate->do_v6 ? AF_INET6 : AF_INET;
		ntpstate->dnsip= 1;
		gettime_mono(&ntpstate->start_time);
		(void) evdns_getaddrinfo(DnsBase, ntpstate->hostname,
			ntpstate->destportstr, &hints, dns_cb, ntpstate);
	}
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
	free(ntpstate->bundle);
	ntpstate->bundle= NULL;
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

