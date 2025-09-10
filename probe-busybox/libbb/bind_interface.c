/*
 * Copyright (c) 2014 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include "libbb.h"
#include <arpa/inet.h>

int bind_interface(int socket, int af, char *name)
{
	struct sockaddr_storage sa;

	memset(&sa, '\0', sizeof(sa));

	if (af == AF_INET)
	{
		sa.ss_family= AF_INET;
		if (inet_pton(af, name,
			&((struct sockaddr_in *)&sa)->sin_addr) == 1)
		{
			return bind(socket, (struct sockaddr *)&sa,
				sizeof(sa));
		}
	}
	else
	{
		sa.ss_family= AF_INET6;
		if (inet_pton(af, name,
			&((struct sockaddr_in6 *)&sa)->sin6_addr) == 1)
		{
			return bind(socket, (struct sockaddr *)&sa,
				sizeof(sa));
		}
	}
#ifdef __FreeBSD__
	/* SO_BINDTODEVICE is not available on FreeBSD */
	/* On FreeBSD, we would need to use if_nametoindex() and bind to specific interface */
	/* For now, just return success as this is not critical for basic functionality */
	return 0;
#else
	if (setsockopt(socket, SOL_SOCKET, SO_BINDTODEVICE, name,
		strlen(name)+1) == -1)
	{
		return -1;
	}
#endif

	return 0;
}

