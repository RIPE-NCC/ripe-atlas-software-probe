/*
 * Copyright (c) 2013-2014 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#define LINEL (INET6_ADDRSTRLEN * 2)
#include "libbb.h"
#include "resolv.h"
#include "eperd.h"
#include "readresolv.h"
#include <math.h>

static  void nameserver_ip_add (char **nsentry, char *ip_as_string) 
{
	*nsentry= strdup(ip_as_string);
}

static int resolv_conf_parse_line (char **nsentry, char *line)  
{

#define NEXT_TOKEN strtok_r(NULL, delims, &strtok_state)
	char *strtok_state;
	static const char *const delims = " \t";
	char *const first_token = strtok_r(line, delims, &strtok_state);  

	if (!first_token) return 0;

	if (!strcmp(first_token, "nameserver")) { 
		char *const nameserver = NEXT_TOKEN;
		if (nameserver) {
			if(nameserver[(strlen(nameserver) - 1)] == '\n')
			nameserver[(strlen(nameserver) - 1)] = '\0';
			nameserver_ip_add(nsentry, nameserver);
		        //printf("AA added nameserver %s\n", nsentry);
			return 1;
		}
	}
	return 0;
} 

void get_local_resolvers(char *nslist[MAXNS], int *resolv_max, char *ifname)
{

#ifndef RESOLV_CONF 
#define RESOLV_CONF     "/etc/resolv.conf"
#endif 	
	char buf[LINEL]; 
	char filename[80];
	char *buf_start;
	int  i = 0;
	struct stat sb;
	FILE *R;

	if (ifname)
	{
		snprintf(filename, sizeof(filename), "%s.%s",
			RESOLV_CONF, ifname);
		
		/* Check if it exists */
		if (stat(filename, &sb) == -1)
		{
			crondlog(LVL8 "get_local_resolvers: stat of %s failed: %s",
				filename, strerror(errno));
			/* Fall back to resolv.conf */
			strlcpy(filename, RESOLV_CONF, sizeof(filename));
		}
	}
	else
	{
		/* Just use resolv.conf */
		strlcpy(filename, RESOLV_CONF, sizeof(filename));
	}

	crondlog(LVL8 "get_local_resolvers: using %s", filename);

	R = fopen (filename, "r");
	if (R != NULL) {
		while ( (fgets (buf, LINEL, R)) && (i < MAXNS)) {	
			buf_start = buf;
			if(resolv_conf_parse_line(&nslist[i], buf) ) {
				crondlog(LVL5 "parsed file %s , line %s i=%d", filename, buf_start, i);
				i++;
			}
			else 
				crondlog(LVL5 "ERROR failed to parse from  %s i=%d, line %s", filename, i, buf_start);
		}
		fclose (R);
	}

	*resolv_max = i;
}
