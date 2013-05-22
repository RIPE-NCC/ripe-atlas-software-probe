/* vi: set sw=4 ts=4: 
 *
 * Copyright (c) 2010-2013 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * simple find_pid_name. return 0 if a name is found
 */

#include "libbb.h"

/* This is a NOFORK applet. Be very careful! */

int findpid_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int findpid_main(int argc UNUSED_PARAM, char **argv)
{
	pid_t* pidList;
        procps_status_t* p = NULL;

	if (argc > 1)
	{
		while ((p = procps_scan(p, PSSCAN_PID|PSSCAN_COMM|PSSCAN_ARGVN))) 
		{
               	 if (comm_match(p, argv[1])
                /* or we require argv0 to match (essential for matching reexeced
 /proc/self/exe)*/
                 || (p->argv0 && strcmp(bb_basename(p->argv0), argv) == 0)
                /* TODO: we can also try /proc/NUM/exe link, do we want that? */
                ) {
			return EXIT_SUCCESS;
                }
        	}
	}
	return EXIT_FAILURE;
}
