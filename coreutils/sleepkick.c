/* vi: set sw=4 ts=4: 
 * Copyright (C) 2003  Manuel Novoa III  <mjn3@codepoet.org>
 * Copyright (c) 2010-2013 RIPE NCC, Antony <antony@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 *
 * sleep implementation for busybox with watchdog petting. 
 */

/* BB_AUDIT SUSv3 compliant */
/* BB_AUDIT GNU issues -- fancy version matches except args must be ints. */
/* http://www.opengroup.org/onlinepubs/007904975/utilities/sleep.html */

/* Mar 16, 2003      Manuel Novoa III   (mjn3@codepoet.org)
 *
 * Rewritten to do proper arg and error checking.
 * Also, added a 'fancy' configuration to accept multiple args with
 * time suffixes for seconds, minutes, hours, and days.
 */

#include "libbb.h"
#define WATCHDOGDEV "/dev/watchdog"

/* This is a NOFORK applet. Be very careful! */

int sleepkick_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int sleepkick_main(int argc UNUSED_PARAM, char **argv)
{
	unsigned duration;
	unsigned watchdog;
	++argv;
	if (!*argv)
		bb_show_usage();
	duration = xatou(*argv);
	++argv;

	if(*argv)
	{ 
		int fd;         /* File handler for watchdog */
		int i = 0;
		int iMax = 0;

		watchdog =  xatou(*argv);
		iMax =   (int) (duration / watchdog);

		int modDuration = 0;
		int wReminder = 0;
		if( duration >= watchdog)
		{
			modDuration =   duration % watchdog;
		}
		else {
			modDuration  = duration;
		}

		fd = open(WATCHDOGDEV, O_RDWR);
		for( i = 0; i < iMax; i++)
		{
			write(fd, "1", 1);
			sleep(watchdog);	
		}
		if(modDuration)
		{
			write(fd, "1", 1);
			sleep(modDuration);
			write(fd, "1", 1);
		}
 		close(fd);
	}
	else 
	{
		sleep(duration);
	}
	return EXIT_SUCCESS;
}
