/*
 * Copyright (c) 2013-2014 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */
#include "libbb.h"

#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#define OPT_STRING	"lsI:P:r:u:"

enum {
        OPT_l = (1 << 0),
        OPT_s = (1 << 1),
};

#define DBQ(str) "\"" #str "\""

#define N_DNS	3	/* Number of DNS resolvers to keep track of */

#define IN6ADDR_ALL_NODES_INIT { { { 0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }
struct in6_addr in6addr_all_nodes = IN6ADDR_ALL_NODES_INIT;        /* ff02::1 */

#define OPT_RDNSS	25

#define RA_PREF_MASK	0x18
#define RA_PREF_HIGH	0x08
#define RA_PREF_LOW	0x18

/* RFC-4861 */
#define MAX_RTR_SOLICITATIONS 3
#define RTR_SOLICITATION_INTERVAL 4

struct opt_rdnss             /* RDNSS option */
{
	uint8_t   nd_opt_rdnss_type;
	uint8_t   nd_opt_rdnss_len;
	uint16_t  nd_opt_rdnss_reserved;
	uint32_t  nd_opt_rdnss_lifetime;
};

static int solicit_retries;
static int solicit_sock;
static char *update_cmd;

static void usage(void)
{
	fprintf(stderr, "Usage: rptra6 <new> <out>\n");
	exit(1);
}

static void do_resolv(char *str_resolv, char *str_resolv_new,
	char *packet, ssize_t nrecv,
	char dnscurr[N_DNS][INET6_ADDRSTRLEN], 
	time_t *dnsexpires)
{
	int i, olen, n_dns;
	size_t o;
	uint32_t lifetime;
	struct nd_router_advert *ra;
	struct nd_opt_hdr *oh;
	struct opt_rdnss *rdnss;
	FILE *f;
	char namebuf[NI_MAXHOST];
	char dnsnext[N_DNS][INET6_ADDRSTRLEN];

	ra= (struct nd_router_advert *)packet;

	/* Clear resolver list */
	for (n_dns= 0; n_dns < N_DNS; n_dns++)
		strcpy(dnsnext[n_dns], "");
			
	for (o= sizeof(*ra); o<nrecv;)
	{
		if (o+sizeof(*oh) > nrecv)
		{
			printf("partial option\n");
			break;
		}

		oh= (struct nd_opt_hdr *)&packet[o];
		if (oh->nd_opt_len == 0)
		{
			printf("bad option length (0) at %ld\n",
				(long)o);
			break;
		}
		olen= oh->nd_opt_len * 8;

		switch(oh->nd_opt_type)
		{
		case OPT_RDNSS:	/* 25 */

			rdnss= (struct opt_rdnss *)oh;
			lifetime= ntohl(rdnss->nd_opt_rdnss_lifetime);
			/* Assume one year is infinite enough */
			if (lifetime == (uint32_t)-1)
				lifetime= 365*24*3600;

			n_dns= 0;

			for (i= 8; i+16 <= olen; i+= 16)
			{
				if (lifetime == 0)
				{
					/* zero lifetime implies empty list */
					break;
				}
				inet_ntop(AF_INET6, ((char *)oh)+i,
					namebuf, sizeof(namebuf));
				if (n_dns < N_DNS)
				{
					strcpy(dnsnext[n_dns], namebuf);
					n_dns++;
				}
			}

			/* Check if the list of resolvers changed */
			for (n_dns= 0; n_dns < N_DNS; n_dns++)
			{
				if (strcmp(dnscurr[n_dns],
					dnsnext[n_dns]) != 0)
				{
					break;
				}
			}
			if (str_resolv && n_dns < N_DNS)
			{
				memcpy(dnscurr, dnsnext,
					sizeof(dnsnext));

				/* Ignore errors */
				f= fopen(str_resolv_new, "w");
				for (n_dns= 0; n_dns<N_DNS; n_dns++)
				{
					if (strlen(dnscurr[n_dns]) == 0)
						break;
					fprintf(f, "nameserver %s\n",
						dnscurr[n_dns]);
				}
				fclose(f);
				rename(str_resolv_new, str_resolv);
				if (update_cmd)
					system(update_cmd);
			}
			if (lifetime)
				*dnsexpires= time(NULL) + lifetime;
			else
				*dnsexpires= 0;
		
			break;
		}


		o += olen;
	}

	/* Check if we have to expire DNS entries */
	if (*dnsexpires && *dnsexpires < time(NULL))
	{
		*dnsexpires= 0;
		for (n_dns= 0; n_dns<N_DNS; n_dns++)
			strcpy(dnscurr[n_dns], "!");
		if (str_resolv)
		{
			/* Ignore errors */
			f= fopen(str_resolv_new, "w");
			fclose(f);
			rename(str_resolv_new, str_resolv);
		}
	}
}

static void log_ra(char *out_name, char *new_name,
	struct sockaddr_in6 *remotep,
	struct msghdr *msgp, char *packet, ssize_t nrecv)
{
	int i, r, first, rcvd_ttl, olen;
	uint8_t flags_reserved;
	size_t o;
	FILE *of;
	struct cmsghdr *cmsgptr;
	struct sockaddr_in6 *sin6p;
	struct sockaddr_in6 loc_sin6;
	struct nd_router_advert *ra;
	struct nd_opt_hdr *oh;
	struct nd_opt_prefix_info *pi;
	struct nd_opt_mtu *mtup;
	struct opt_rdnss *rdnssp;
	struct stat sb;
	char namebuf[NI_MAXHOST];

	of= fopen(new_name, "a");
	if (of == NULL)
	{
		fprintf(stderr, "unable to open '%s': %s\n", new_name, strerror(errno));
		exit(1);
	}

	fprintf(of, "RESULT { " DBQ(id) ": " DBQ(9019) ", " DBQ(time) ": %ld",
		(long)time(NULL));
	getnameinfo((struct sockaddr *)remotep, msgp->msg_namelen,
		namebuf, sizeof(namebuf), NULL, 0, NI_NUMERICHOST);
	fprintf(of, ", " DBQ(src) ": " DBQ(%s), namebuf);

	/* Set destination address of packet as local address */
	memset(&loc_sin6, '\0', sizeof(loc_sin6));
	for (cmsgptr= CMSG_FIRSTHDR(msgp); cmsgptr; 
		cmsgptr= CMSG_NXTHDR(msgp, cmsgptr))
	{
		if (cmsgptr->cmsg_len == 0)
			break;	/* Can this happen? */
		if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
			cmsgptr->cmsg_type == IPV6_PKTINFO)
		{
			sin6p= &loc_sin6;
			sin6p->sin6_family= AF_INET6;
			sin6p->sin6_addr= ((struct in6_pktinfo *)
				CMSG_DATA(cmsgptr))->ipi6_addr;
		}
		if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
			cmsgptr->cmsg_type == IPV6_HOPLIMIT)
		{
			rcvd_ttl= *(int *)CMSG_DATA(cmsgptr);
		}
	}

	if (memcmp(&loc_sin6.sin6_addr, &in6addr_all_nodes,
		sizeof(loc_sin6.sin6_addr)) != 0)
	{
		getnameinfo((struct sockaddr *)&loc_sin6, sizeof(loc_sin6),
			namebuf, sizeof(namebuf), NULL, 0, NI_NUMERICHOST);
		fprintf(of, ", " DBQ(dst) ": " DBQ(%s), namebuf);
	}
	if (rcvd_ttl != 255)
		fprintf(of, ", " DBQ(ttl) ": %d", rcvd_ttl);

	ra= (struct nd_router_advert *)packet;
	fprintf(of, ", " DBQ(hop_limit) ": %d", ra->nd_ra_curhoplimit);
	flags_reserved= ra->nd_ra_flags_reserved;
	if (flags_reserved & ND_RA_FLAG_OTHER)
	{
		fprintf(of, ", " DBQ(other_conf) ": true");
		flags_reserved &= ~ND_RA_FLAG_OTHER;
	}
	switch(flags_reserved & RA_PREF_MASK)
	{
	case RA_PREF_HIGH:
		fprintf(of, ", " DBQ(preference) ": " DBQ(high));
		flags_reserved &= ~RA_PREF_MASK;
		break;
	case RA_PREF_LOW:
		fprintf(of, ", " DBQ(preference) ": " DBQ(low));
		flags_reserved &= ~RA_PREF_MASK;
		break;
	}
	if (flags_reserved)
		fprintf(of, ", " DBQ(reserved) ": 0x%x", flags_reserved);
	fprintf(of, ", " DBQ(lifetime) ": %d", ntohs(ra->nd_ra_router_lifetime));
	if (ra->nd_ra_reachable)
		fprintf(of, ", " DBQ(reachable_time) ": %d", ntohl(ra->nd_ra_reachable));
	if (ra->nd_ra_retransmit)
		fprintf(of, ", " DBQ(retransmit_time) ": %d", ntohl(ra->nd_ra_retransmit));

	fprintf(of, ", " DBQ(options) ": [ ");
	first= 1;
	for (o= sizeof(*ra); o<nrecv;)
	{
		if (!first)
			fprintf(of, ", ");
		else
			first= 0;

		if (o+sizeof(*oh) > nrecv)
		{
			printf("partial option\n");
			break;
		}

		oh= (struct nd_opt_hdr *)&packet[o];
		if (oh->nd_opt_len == 0)
		{
			printf("bad option length (0) at %ld\n",
				(long)o);
			break;
		}
		olen= oh->nd_opt_len * 8;

		switch(oh->nd_opt_type)
		{
		case ND_OPT_SOURCE_LINKADDR:	/* 1 */
			fprintf(of, "{ " DBQ(type) ": " DBQ(link layer address) ", "
				DBQ(addr) ": \"");
			for (i= 2; i<olen; i++)
			{
				fprintf(of, "%s%02x", i == 2 ? "" : ":",
					((uint8_t *)oh)[i]);
			}
			fprintf(of, "\" }");
			break;
		case ND_OPT_PREFIX_INFORMATION:	/* 3 */
			if (olen < sizeof(*pi))
			{
				printf(
			"bad option length (%d) for prefix info\n",
					oh->nd_opt_len);
				break;
			}
			pi= (struct nd_opt_prefix_info *)oh;
			fprintf(of, "{ " DBQ(prefix_len) ": %d", 
				pi->nd_opt_pi_prefix_len);
			flags_reserved= pi->nd_opt_pi_flags_reserved;
			if (flags_reserved & ND_OPT_PI_FLAG_ONLINK)
			{
				fprintf(of, ", " DBQ(onlink) ": true");
				flags_reserved &= ~ND_OPT_PI_FLAG_ONLINK;
			}
			if (flags_reserved & ND_OPT_PI_FLAG_AUTO)
			{
				fprintf(of, ", " DBQ(auto) ": true");
				flags_reserved &= ~ND_OPT_PI_FLAG_AUTO;
			}
		
			if (flags_reserved)
			{
				fprintf(of, ", " DBQ(reserved1) ": 0x%x", flags_reserved);
			}
			fprintf(of, ", " DBQ(valid_time) ": %d",
				ntohl(pi-> nd_opt_pi_valid_time));
			fprintf(of, ", " DBQ(preferred_time) ": %d",
				ntohl(pi-> nd_opt_pi_preferred_time));
			if (pi-> nd_opt_pi_reserved2)
			{
				fprintf(of, ", " DBQ(reserved2) ": %d",
					ntohl(pi-> nd_opt_pi_reserved2));
			}

			fprintf(of, ", " DBQ(prefix) ": " DBQ(%s) " }",
				inet_ntop(AF_INET6, &pi->nd_opt_pi_prefix,
				namebuf, sizeof(namebuf)));
			break;

		case ND_OPT_MTU:	/* 5 */
			fprintf(of, "{ " DBQ(type) ": " DBQ(mtu));
			mtup= (struct nd_opt_mtu *)oh;
			if (mtup->nd_opt_mtu_reserved)
			{
				fprintf(of, ", " DBQ(reserved) ": 0x%x",
				ntohs(mtup->nd_opt_mtu_reserved));
			}
			fprintf(of, ", " DBQ(mtu) ": %d }",
				ntohl(mtup->nd_opt_mtu_mtu));
			break;

		case OPT_RDNSS:	/* 25 */
			fprintf(of, "{ " DBQ(type) ": " DBQ(rdnss));
			rdnssp= (struct opt_rdnss *)oh;
			if (rdnssp->nd_opt_rdnss_reserved)
			{
				fprintf(of, ", " DBQ(reserved) ": %d",
				ntohs(rdnssp->nd_opt_rdnss_reserved));
			}
			fprintf(of, ", " DBQ(lifetime) ": %d",
				ntohl(rdnssp->nd_opt_rdnss_lifetime));

			fprintf(of, ", " DBQ(addrs) ": [ ");
			for (i= 8; i+16 <= olen; i+= 16)
			{
				inet_ntop(AF_INET6, ((char *)oh)+i,
					namebuf, sizeof(namebuf));
				fprintf(of, "%s" DBQ(%s),
					i == 8 ? "" : ", ",
					namebuf);
			}
			fprintf(of, " ] }");

			break;

		default:
			fprintf(of, "{ " DBQ(type_no) ": %d }", oh->nd_opt_type);
			break;
		}


		o += olen;
	}
	fprintf(of, " ] }\n");

	fclose(of);

	r= stat(out_name, &sb);
	if (r == 0)
		return;
	if (errno == ENOENT)
	{
		rename(new_name, out_name);
		return;
	}
	fprintf(stderr, "stat '%s' failed: %s\n", out_name, strerror(errno));
	exit(1);
}

static int send_sol(int sock)
{
	struct icmp6_hdr pkt;
	struct sockaddr_in6 sin6;

	if (solicit_retries <= 0)
		return 0;	/* Done */
	solicit_retries--;

	pkt.icmp6_type= ND_ROUTER_SOLICIT;
	pkt.icmp6_code= 0;
	pkt.icmp6_data32[0]= 0;

	memset(&sin6, '\0', sizeof(sin6));
	inet_pton(AF_INET6, "FF02::2", &sin6.sin6_addr);
	sin6.sin6_family= AF_INET6;

	sendto(sock, &pkt, sizeof(pkt), 0, &sin6, sizeof(sin6));

	alarm(RTR_SOLICITATION_INTERVAL);

	return 0;
}

static void solicit_alarm(int sig UNUSED_PARAM)
{
	send_sol(solicit_sock);
}

int rptra6_main(int argc, char *argv[]) MAIN_EXTERNALLY_VISIBLE;
int rptra6_main(int argc, char *argv[])
{
	int i, sock, hlim, on, nrecv, do_log, do_solicit;
	unsigned opts;
	size_t len;
	time_t dnsexpires;
	char *new_name, *out_name,
		*str_interface, *str_resolv, *str_resolv_new, *str_update;
	struct icmp6_hdr * icmp;
	FILE *of;
	char *str_pidfile;
	struct sockaddr_in6 remote;          /* responding internet address */
	struct msghdr msg;
	struct sigaction sa;
	struct iovec iov[1];
	char dnscurr[N_DNS][INET6_ADDRSTRLEN];
	char cmsgbuf[256];
	char packet[4096];

	str_interface= NULL;
	str_pidfile= NULL;
	str_resolv= NULL;
	str_update= NULL;
	opts= getopt32(argv, OPT_STRING, &str_interface, &str_pidfile,
		&str_resolv, &str_update);

	do_log= !!(opts & OPT_l);
	do_solicit= !!(opts & OPT_s);
	
	if (do_log)
	{
		if (argc != optind+2)
			usage();

		new_name= argv[optind];
		out_name= argv[optind+1];
	}
	else
	{
		if (argc != optind)
			usage();
		new_name= NULL;
		out_name= NULL;
	}

	if (str_pidfile)
	{
		of= fopen(str_pidfile, "w");
		if (of)
		{
			fprintf(of, "%d\n", getpid());
			fclose(of);
		}
	}

	update_cmd= str_update;

	str_resolv_new= NULL;
	if (str_resolv)
	{
		len= strlen(str_resolv) + 4 + 1;
		str_resolv_new= malloc(len);
		snprintf(str_resolv_new, len, "%s.new", str_resolv);
	}
	
	of= NULL;

	sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (sock == -1)
	{
		printf("socket failed: %s\n", strerror(errno));
		return 1;
	}

	if (str_interface)
	{
		if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE,
			str_interface, strlen(str_interface)+1) == -1)
		{
			close(sock);
			return 1;
		}
	}

	on = 1;
	setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));

	on = 1;
	setsockopt(sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on));

	if (do_solicit)
	{
		hlim= 255;
		setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
			&hlim, sizeof(hlim));
		solicit_sock= sock;
		solicit_retries= MAX_RTR_SOLICITATIONS;
		sa.sa_handler= solicit_alarm;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags= 0;
		sigaction(SIGALRM, &sa, NULL);
		send_sol(sock);
	}

	icmp = (struct icmp6_hdr *) packet;

	/* Put something weird in the current list of DNS resolvers to 
	 * trigger an update.
	 */
	for (i= 0; i<N_DNS; i++)
		strcpy(dnscurr[i], "!");
	dnsexpires= 0;	/* Currently, there is no DNS info */

	for(;;)
	{
		iov[0].iov_base= packet;
		iov[0].iov_len= sizeof(packet);
		msg.msg_name= &remote;
		msg.msg_namelen= sizeof(remote);
		msg.msg_iov= iov;
		msg.msg_iovlen= 1;
		msg.msg_control= cmsgbuf;
		msg.msg_controllen= sizeof(cmsgbuf);
		msg.msg_flags= 0;			/* Not really needed */

		/* Receive data from the network */
		nrecv= recvmsg(sock, &msg, 0);
		if (nrecv < 0)
		{
			if (errno == EINTR)
				continue;
			printf("recvmsg failed: %s\n", strerror(errno));
			break;
		}

		/* Check for Destination Host Unreachable */
		if (icmp->icmp6_type != ND_ROUTER_ADVERT)
		{
			switch(icmp->icmp6_type)
			{
			case ICMP6_DST_UNREACH:		/*   1 */
			case ICMP6_PACKET_TOO_BIG:	/*   2 */
			case ICMP6_TIME_EXCEEDED:	/*   3 */
			case ICMP6_ECHO_REQUEST:	/* 128 */
			case ICMP6_ECHO_REPLY:		/* 129 */
			case MLD_LISTENER_QUERY:	/* 130 */
			case ND_NEIGHBOR_SOLICIT:	/* 135 */
			case ND_NEIGHBOR_ADVERT:	/* 136 */
			case ND_REDIRECT:		/* 137 */
				break;	/* Ignore */
			default:
				printf("icmp6_type %d\n", icmp->icmp6_type);
				break;
			}
			continue;
		}

		if (do_log)
		{
			log_ra(out_name, new_name, &remote, &msg,
				packet, nrecv);
		}
		if (str_resolv)
		{
			do_resolv(str_resolv, str_resolv_new, packet, nrecv,
				dnscurr, &dnsexpires);
		}
	}

	fprintf(stderr, "end of main\n");
	exit(1);
}
