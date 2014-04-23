/*
 * Copyright (c) 2014 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include "libbb.h"

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
	if (setsockopt(socket, SOL_SOCKET, SO_BINDTODEVICE, name,
		strlen(name)+1) == -1)
	{
		return -1;
	}

	return 0;
}

