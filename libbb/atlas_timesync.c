/*
 * Copyright (c) 2013-2014 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include "libbb.h"
int get_timesync(void)
{
	FILE *fh;
	int lastsync;

	fh= fopen(ATLAS_TIMESYNC_FILE, "r");
	if (!fh)
		return -1;
	fscanf(fh, "%d", &lastsync);
	fclose(fh);
	return time(NULL)-lastsync;
}

