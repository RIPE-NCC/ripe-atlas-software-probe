/*
 * Copyright (c) 2020 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include "libbb.h"

int gettime_mono(struct timespec *tsp)
{
	static time_t reproducible_time= 0;

	if (atlas_tests())
	{
		++reproducible_time;
		tsp->tv_sec= reproducible_time;
		tsp->tv_nsec= 1000*reproducible_time;
		return 0;
	}

	return clock_gettime(CLOCK_MONOTONIC_RAW, tsp);
}

