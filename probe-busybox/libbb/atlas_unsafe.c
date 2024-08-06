/*
 * Copyright (c) 2020 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include "libbb.h"

int atlas_unsafe(void)
{
	static int allow_unsafe= -1;

	if (!allow_unsafe)
		return 0;

	if (allow_unsafe == -1)
		allow_unsafe= (getenv("ATLAS_UNSAFE") != NULL);
	return allow_unsafe;
}

