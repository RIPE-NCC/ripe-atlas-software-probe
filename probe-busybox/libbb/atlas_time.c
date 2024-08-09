/*
 * Copyright (c) 2020 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include "libbb.h"

time_t atlas_time(void)
{
	if (atlas_tests())
		return 999999999;
	else
		return time(NULL);
}

