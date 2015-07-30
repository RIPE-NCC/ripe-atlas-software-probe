/*
 * Copyright (c) 2015 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include "libbb.h"

struct ipv4_prefix
{
	uint32_t addr;
	unsigned len;
}
static bad_ipv4[] =
{
	{ 0x7F000000,  8 },	/*   127.0.0.0/8 localhost */
	{ 0x0A000000,  8 },	/*    10.0.0.0/8 (RFC-1918) */
	{ 0xAC100000, 12 },	/*  172.16.0.0/12 (RFC-1918) */
	{ 0xC0A80000, 16 },	/* 192.168.0.0/16 (RFC-1918) */
	{ 0xA9FE0000, 16 },	/* 169.254.0.0/16 (RFC-3927) */
	{ 0xE0000000,  3 },	/*   224.0.0.0/3 multicast and reserved */
};

struct ipv6_prefix
{
	uint16_t addr[8];
	unsigned len;
}
static bad_ipv6[] =
{
	{ { 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001 },
					128 },	/* ::1 loopback */
	{ { 0xE000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
			  3 }, 	/* e000::/3 ULA, link local, multicast */
};

int atlas_check_addr(const struct sockaddr *sa, socklen_t len)
{
	uint16_t addr2, mask2;
	int i, j, prefix_len;
	uint32_t addr4, mask4;
	uint16_t *addr2p;
	const struct sockaddr_in *sin4p;
	const struct sockaddr_in6 *sin6p;

	switch(sa->sa_family)
	{
	case AF_INET:
		if (len < sizeof(*sin4p))
			return -1;
		sin4p= (const struct sockaddr_in *)sa;
		addr4= sin4p->sin_addr.s_addr;
		addr4= ntohl(addr4);
		for (i= 0; i<sizeof(bad_ipv4)/sizeof(bad_ipv4[0]); i++)
		{
			mask4= ~((1ul << (32-bad_ipv4[i].len))-1);
			if ((addr4 & mask4) == bad_ipv4[i].addr)
				return -1;
		}
		return 0;

	case AF_INET6:
		if (len < sizeof(*sin6p))
			return -1;
		sin6p= (const struct sockaddr_in6 *)sa;
		addr2p= (uint16_t *)&sin6p->sin6_addr;
		for (i= 0; i<sizeof(bad_ipv6)/sizeof(bad_ipv6[0]); i++)
		{
			prefix_len= bad_ipv6[i].len;
			for (j= 0; j<prefix_len; j += 16)
			{
				addr2= ntohs(addr2p[j/16]);
				if (j+16 <= prefix_len)
				{
					/* Match entire word */
					if (addr2 != bad_ipv6[i].addr[j/16])
					{
						/* Different prefix */
						break;
					}
					continue;
				}
				mask2= ~((1ul << (16-(prefix_len % 16)))-1);
				if ((addr2 & mask2) == bad_ipv6[i].addr[j/16])
				{
					return -1;
				}
				break;
			}
			if (j < prefix_len)
			{
				/* No match, try the next one */
				continue;
			}

			/* Match */
			return -1;
		}
		return 0;
	}
	return -1;	/* Default to not allowed */
}

