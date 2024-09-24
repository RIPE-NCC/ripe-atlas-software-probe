/*
 * Copyright (c) 2020 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include "libbb.h"

int atlas_tests(void)
{
	static int do_tests= -1;

	if (!do_tests)
		return 0;

	if (do_tests == -1)
		do_tests= (getenv("ATLAS_TESTS") != NULL);
	return do_tests;
}

