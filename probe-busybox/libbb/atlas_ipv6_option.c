/*
 * Copyright (c) 2018 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE for details.
 */

#include "libbb.h"
#include <netinet/in.h>

#ifdef __APPLE__
#ifndef IPV6_DSTOPTS
#define IPV6_DSTOPTS 23
#endif
#ifndef IPV6_HOPOPTS
#define IPV6_HOPOPTS 22
#endif
#endif

#define OPT_PAD1 0
#define OPT_PADN 1

int do_ipv6_option(int sock, int hbh_dest,
	unsigned size)
{
	int i, r;
	size_t totsize, ehlen, padlen;

	char packet[4096];	/* Assume we can put the on the stack. And
				 * assume this is big enough.
				 */

	if (size == 0)
	{
		r= setsockopt(sock, IPPROTO_IPV6,
			hbh_dest ? IPV6_DSTOPTS : IPV6_HOPOPTS, NULL, 0);
		return r;
	}

	/* Compute the totsize we need */
	totsize = 2 + size;
	if (totsize % 8)
		totsize += 8 - (totsize % 8);

	/* Consistency check */
	if (totsize > sizeof(packet))
	{
		errno= EINVAL;
		return -1;
	}

	ehlen= totsize/8 - 1;
	if (ehlen > 255)
	{
		errno= EINVAL;
		return -1;
	}

	memset(packet, '\0', totsize);
	packet[1]= ehlen;
	for (i= 2; i<totsize;)
	{
		padlen= totsize-i;
		if (padlen == 1)
		{
			packet[i]= OPT_PAD1;
			i++;
			continue;
		}
		padlen -= 2;
		if (padlen > 255)
			padlen= 255;
		packet[i]= OPT_PADN;
		packet[i+1]= padlen;
		i += 2+padlen;
	}
	if (hbh_dest)
	{
		r= setsockopt(sock, IPPROTO_IPV6, IPV6_DSTOPTS, packet,
			totsize);
	}
	else
	{
		r= setsockopt(sock, IPPROTO_IPV6, IPV6_HOPOPTS, packet,
			totsize);
	}

	return r;
}

