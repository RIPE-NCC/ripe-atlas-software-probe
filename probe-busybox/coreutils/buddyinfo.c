/* vi: set sw=2 ts=2: 
 *
 * 2010-2013  Copyright (c) 2013 RIPE NCC <atlas@ripe.net> 
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * read /cat/proc/buddyinfo and print out.
 * if env variable LOWMEM_REBOOT is set KBytes same as buddyinfo reboot
 *
 */
//config:config BUDDYINFO
//config:       bool "buddyinfo"
//config:       default n
//config:       help
//config:         buddyinfo reports on the amount of free memory

//applet:IF_CONDMV(APPLET(buddyinfo, BB_DIR_ROOT, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_BUDDYINFO) += buddyinfo.o

//usage:#define buddyinfo_trivial_usage
//usage:       ""
//usage:#define buddyinfo_full_usage "\n\n"
//usage:       ""

#include "libbb.h"

#include <time.h>
#include <sys/time.h>
#ifdef __linux__
#include <sys/sysinfo.h>
#endif

#define DBQ(str) "\"" #str "\""

/* This is a NOFORK applet. Be very careful! */

int buddyinfo_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int buddyinfo_main(int argc UNUSED_PARAM, char **argv)
{
	char *lowmemChar;
	unsigned lowmem = 0;
	char *my_mac;
	int need_reboot = 0; // don't reboot 
	int freeMem = 0;
	time_t uptime = 0;
	struct timespec ts;
	FILE *fp __attribute__((unused)) = NULL;

	lowmemChar = argv[1];

	if(lowmemChar) 
		lowmem = xatou(lowmemChar);

	my_mac = getenv("ETHER_SCANNED");

	if (lowmem >= 4) 
	{
		/* We need to reboot unless we find a big enough chunk
		 * of memory.
		 */
		need_reboot = 1;
	}

	printf("RESULT { " DBQ(id) ": " DBQ(9001) ", " DBQ(time) ": %lld",
		(long long)time(0));
	if (my_mac != NULL)
		printf(", " DBQ(macaddr) ": " DBQ(%s), my_mac);

	/* get uptime and print it */
	// Portable way to get uptime using clock_gettime
	if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
		uptime = ts.tv_sec;
	} else {
		// Fallback: approximate uptime from process start
		uptime = time(NULL) - 1;
	}
	printf(", " DBQ(uptime) ": %ld", uptime);
	
	// Portable memory information
	printf(", " DBQ(buddyinfo) ": [ ");
	
	// Variables for memory processing
	
#ifdef __linux__
	// Linux: try /proc/buddyinfo first
	fp = fopen("/proc/buddyinfo", "r");
	if (fp) {
		char aa[256];
		int i, j;
		int memBlock = 4; // Start with 4KB
		int jMax = 11;    // Maximum number of buddy zones
		
		fscanf(fp, "%s", aa); 
		fscanf(fp, "%s", aa);
		fscanf(fp, "%s", aa);
		fscanf(fp, "%s", aa);

		for (j = 0; j < jMax; j++)  
		{
			if (fscanf(fp, "%d", &i) != 1)
				break;
			printf("%s%d", j == 0 ? "" : ", ", i);
			freeMem += (memBlock * i);
			if (i > 0 && lowmem >= 4 && memBlock >= lowmem)
			{
				/* Found a big enough chunk */
				need_reboot = 0;
			}
			memBlock *= 2; 
		}
		fclose(fp);
	} else {
		// Fallback to sysinfo for basic memory info
		struct sysinfo info;
		if (sysinfo(&info) == 0) {
			freeMem = info.freeram * (info.mem_unit / 1024); // Convert to KB
			printf("0"); // Simple buddyinfo representation
		} else {
			printf("0"); // Fallback
		}
	}
#else
	// Non-Linux: use platform-specific memory APIs
	// For now, provide basic memory info
	freeMem = 1024; // Default 1MB
	printf("0"); // Simple buddyinfo representation
#endif

	printf(" ], " DBQ(freemem) ": %d }\n", freeMem);

	if(need_reboot)
	{
		fprintf(stderr, "buddyinfo: nothing found for size %d\n", lowmem);
		return (EXIT_FAILURE);
	}
	return 0;
}
