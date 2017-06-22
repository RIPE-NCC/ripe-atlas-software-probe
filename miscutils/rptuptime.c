/* vi: set sw=2 ts=2: 
 *
 * 2010-2013  Copyright (c) 2013 RIPE NCC <atlas@ripe.net> 
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */
//config:config RPTUPTIME
//config:       bool "rptuptime"
//config:       default n
//config:       help
//config:         rptuptime reports the uptime in a JSON structure

//applet:IF_CONDMV(APPLET(rptuptime, BB_DIR_BIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_RPTUPTIME) += rptuptime.o

//usage:#define rptuptime_trivial_usage
//usage:       ""
//usage:#define rptuptime_full_usage "\n\n"
//usage:       ""

#include "libbb.h"

#include <sys/sysinfo.h>

#define DBQ(str) "\"" #str "\""

/* This is a NOFORK applet. Be very careful! */

int rptuptime_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int rptuptime_main(int argc UNUSED_PARAM, char **argv)
{
	struct sysinfo info; 

	printf("RESULT { " DBQ(id) ": " DBQ(7001) ", ");
	printf(DBQ(fw) ": %d, ", get_atlas_fw_version());
	printf(DBQ(time) ": %ld, ", (long)time(NULL));
	printf(DBQ(lts) ": %d, ", get_timesync());
	sysinfo(&info);
	printf(DBQ(uptime) ": %ld }\n", (long)info.uptime);

	return 0;
}
