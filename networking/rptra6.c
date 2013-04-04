#include "libbb.h"

#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#define DBQ(str) "\"" #str "\""

#define IN6ADDR_ALL_NODES_INIT { { { 0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }
struct in6_addr in6addr_all_nodes = IN6ADDR_ALL_NODES_INIT;        /* ff02::1 */

#define RA_PREF_MASK	0x18
#define RA_PREF_HIGH	0x08
#define RA_PREF_LOW	0x18

static void usage(void)
{
	fprintf(stderr, "Usage: rptra6 <new> <out>\n");
	exit(1);
}

int rptra6_main(int argc, char *argv[]) MAIN_EXTERNALLY_VISIBLE;
int rptra6_main(int argc, char *argv[])
{
	int i, r, first, sock, on, nrecv, rcvd_ttl, olen;
	uint8_t flags_reserved;
	size_t o;
	char *new_name, *out_name;
	struct nd_router_advert *ra;
	struct nd_opt_hdr *oh;
	struct nd_opt_prefix_info *pi;
	struct nd_opt_mtu *mtup;
	struct icmp6_hdr * icmp;
	struct cmsghdr *cmsgptr;
	struct sockaddr_in6 *sin6p;
	FILE *of;
	struct stat sb;
	struct sockaddr_in6 remote;          /* responding internet address */
	struct sockaddr_in6 loc_sin6;
	struct msghdr msg;
	struct iovec iov[1];
	char namebuf[NI_MAXHOST];
	char cmsgbuf[256];
	char packet[4096];

	if (argc != 3)
		usage();

	new_name= argv[1];
	out_name= argv[2];

	of= NULL;

	sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (sock == -1)
	{
		printf("socket failed: %s\n", strerror(errno));
		return 1;
	}

	on = 1;
	setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));

	on = 1;
	setsockopt(sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on));


	icmp = (struct icmp6_hdr *) packet;

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
			case ND_NEIGHBOR_SOLICIT:	/* 135 */
			case ND_NEIGHBOR_ADVERT:	/* 136 */
				break;	/* Ignore */
			default:
				printf("icmp6_type %d\n", icmp->icmp6_type);
				break;
			}
			continue;
		}

		of= fopen(new_name, "a");
		if (of == NULL)
		{
			fprintf(stderr, "unable to open '%s': %s\n", new_name, strerror(errno));
			exit(1);
		}

		fprintf(of, "RESULT { " DBQ(id) ": " DBQ(9019) ", " DBQ(time) ": %ld",
			(long)time(NULL));
		getnameinfo((struct sockaddr *)&remote, msg.msg_namelen,
			namebuf, sizeof(namebuf), NULL, 0, NI_NUMERICHOST);
		fprintf(of, ", " DBQ(src) ": " DBQ(%s), namebuf);

		/* Set destination address of packet as local address */
		memset(&loc_sin6, '\0', sizeof(loc_sin6));
		for (cmsgptr= CMSG_FIRSTHDR(&msg); cmsgptr; 
			cmsgptr= CMSG_NXTHDR(&msg, cmsgptr))
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
			oh= (struct nd_opt_hdr *)&packet[o];
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
				fprintf(of, ", " DBQ(reserved) ": 0x%x",
					ntohs(mtup->nd_opt_mtu_reserved));
				fprintf(of, ", " DBQ(mtu) ": %d", ntohs(mtup->nd_opt_mtu_mtu));
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
			continue;
		if (errno == ENOENT)
		{
			rename(new_name, out_name);
			continue;
		}
		fprintf(stderr, "stat '%s' failed: %s\n", out_name, strerror(errno));
		exit(1);
	}

	fprintf(stderr, "end of main\n");
	exit(1);
}
