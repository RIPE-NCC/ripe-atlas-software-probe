/* vi: set sw=2 ts=2: 
 *
 * 2010-2013  Copyright (c) 2013 RIPE NCC <atlas@ripe.net> 
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */
//config:config RCHOOSE
//config:       bool "rchoose"
//config:       default n
//config:       help
//config:         return a random choice from command line arguments

//applet:IF_CONDMV(APPLET(rchoose, BB_DIR_ROOT, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_RCHOOSE) += rchoose.o

//usage:#define rchoose_trivial_usage
//usage:       ""
//usage:#define rchoose_full_usage "\n\n"
//usage:       ""

#include "libbb.h"

#include <sys/sysinfo.h>

/* This is a NOFORK applet. Be very careful! */

int rchoose_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int rchoose_main(int argc UNUSED_PARAM, char **argv)
{
	int r;

	srandom (time (0));
	r = random();
	argv++;
	r %= (argc - 1);
	printf ("%s\n", argv[r]);
	return fflush(stdout);
}
