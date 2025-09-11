/* vi: set sw=2 ts=2: 
 *
 * 2010-2013  Copyright (c) 2013 RIPE NCC <atlas@ripe.net> 
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */
//config:config ONLYUPTIME
//config:       bool "onlyuptime"
//config:       default n
//config:       help
//config:         onlyuptime reports the uptime in seconds

//applet:IF_CONDMV(APPLET(onlyuptime, BB_DIR_ROOT, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_ONLYUPTIME) += onlyuptime.o

//usage:#define onlyuptime_trivial_usage
//usage:       ""
//usage:#define onlyuptime_full_usage "\n\n"
//usage:       ""

#include "libbb.h"

#include <time.h>
#include <sys/time.h>

/* This is a NOFORK applet. Be very careful! */

int onlyuptime_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int onlyuptime_main(int argc UNUSED_PARAM, char **argv UNUSED_PARAM)
{
	time_t uptime = 0;
	
	// Portable way to get uptime using clock_gettime
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
		uptime = ts.tv_sec;
	} else {
		// Fallback: approximate uptime from process start
		uptime = time(NULL) - 1;
	}

	printf("%ld\n", (long)uptime);

	return 0;
}
