/*
 * Copyright (c) 2015 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include "libbb.h"

struct ipv4_prefix
{
	uint32_t addr;
	unsigned len;
};
static struct ipv4_prefix bad_ipv4[] =
{
	{ 0x7F000000,  8 },	/*   127.0.0.0/8 localhost */
	{ 0x0A000000,  8 },	/*    10.0.0.0/8 (RFC-1918) */
	{ 0xAC100000, 12 },	/*  172.16.0.0/12 (RFC-1918) */
	{ 0xC0A80000, 16 },	/* 192.168.0.0/16 (RFC-1918) */
	{ 0xA9FE0000, 16 },	/* 169.254.0.0/16 (RFC-3927) */
	{ 0xE0000000,  4 },	/*   224.0.0.0/4 multicast */
};

struct ipv6_prefix
{
	uint16_t addr[8];
	unsigned len;
};
static struct ipv6_prefix bad_ipv6[] =
{
	{ { 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001 },
					128 },	/* ::1 loopback */
	{ { 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0xFFFF, 0x0000, 0x0000 },
				 96 }, /* ::ffff:0:0/96 IPv4-mapped */
	{ { 0xE000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
			  3 }, 	/* e000::/3 ULA, link local, multicast */
};

int atlas_check_addr(const struct sockaddr *sa, socklen_t len)
{
	uint16_t addr2, mask2;
	size_t i;
	int j, prefix_len;
	uint32_t addr4, mask4;
	uint16_t *addr2p;
	const struct sockaddr_in *sin4p;
	const struct sockaddr_in6 *sin6p;
	char *cp;

	static int allow_all= -1;

	if (allow_all == -1)
	{
		allow_all= 0;	/* Safe default */
		cp= getenv("ATLAS_DISABLE_CHECK_ADDR");
		if (cp != NULL && strcmp(cp, "yes") == 0)
			allow_all= 1;
	}

	if (allow_all)
		return 0;	/* All addresses are allowed */

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

#if 0	/* Not yet needed */
int ipv6_match_prefix(struct in6_addr *addr,
	struct in6_addr *prefix, int prefix_len)
{
	int i;
	uint16_t mask;

	for (i= 0; i<prefix_len; i += 16)
	{
		if (i+16 <= prefix_len)
		{
			/* Match entire word */
			if (addr->s6_addr16[i/16] !=
				prefix->s6_addr16[i/16])
			{
				/* Different prefix */
				break;
			}
			continue;
		}
		mask= ~((1ul << (16-(prefix_len % 16)))-1);
		mask= htons(mask);
		if ((addr->s6_addr16[i/16] & mask) ==
			prefix->s6_addr16[i/16])
		{
			return 1;
		}
		break;
	}
	if (i < prefix_len)
	{
		/* No match */
		return 0;
	}

	/* Match */
	return 1;
}
#endif 
