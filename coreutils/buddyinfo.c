/* vi: set sw=2 ts=2: 
 *
 * 2010-2013  Copyright (c) 2013 RIPE NCC <atlas@ripe.net> 
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * read /cat/proc/buddyinfo and print out.
 * if env variable LOWMEM_REBOOT is set KBytes same as buddyinfo reboot
 *
 */

#include "libbb.h"

/* This is a NOFORK applet. Be very careful! */

int buddyinfo_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int buddyinfo_main(int argc UNUSED_PARAM, char **argv)
{
	char *lowmemChar;
	unsigned lowmem = 0;
	lowmemChar = getenv("LOW_MEM_T");
	if(lowmemChar) 
		lowmem = xatou(lowmemChar);
	
        FILE *fp = xfopen_for_read("/proc/buddyinfo");
        char aa[10];
        fscanf(fp, "%s", aa);
        fscanf(fp, "%s", aa);
        fscanf(fp, "%s", aa);
        fscanf(fp, "%s", aa);

	char *my_mac ;
        my_mac = getenv("ETHER_SCANNED");

        int i = 0;
        int j = 0;
	int memBlock = 4;
	int fReboot = 1; // don't reboot 
	if (lowmem >= 4 ) 
	{
		fReboot = 0; // env variable is set sow we check for low thershhold
	}
        printf ("RESULT 9001.0 ongoing %d ", (int)time(0));
	if (my_mac !=  NULL)
		printf("%s ", my_mac);
        for (j=0; j< 11; j++)
        {
                fscanf(fp, "%d", &i);
                printf("%-3d ", i);
		if ( lowmem >= 4) 
		{
			if(  memBlock >=  lowmem)
			{
		 		if(fReboot == 0)
				{ 
			  		if (i > 0 )
						{
							fReboot = 1;
							
						}
				} 
			}
		}
		memBlock  *= 2; 
        }
        printf ("\n"); 
        fclose(fp);
	if(fReboot == 0 )
	{
		fprintf(stderr, "buddy info returned 1 for block %d\n", lowmem);
		return (EXIT_FAILURE);
	}
        return EXIT_SUCCESS;
}
