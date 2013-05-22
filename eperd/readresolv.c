/*
 * Copyright (c) 2013 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#define LINEL (INET6_ADDRSTRLEN * 2)
#include "libbb.h"
#include "resolv.h"

static  void nameserver_ip_add (char *nsentry, char *ip_as_string) 
{

	strncpy (nsentry, ip_as_string, LINEL);
	// printf("AA added nameserver %s\n", ip_as_string);
	// printf("AA added nameserver to ns %s\n", nsentry);
	return;
}

static int resolv_conf_parse_line (char *nsentry, char *line)  
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
			nameserver[(strlen(nameserver) - 1)] = NULL;
			nameserver_ip_add(nsentry, nameserver);
		        //printf("AA added nameserver %s\n", nsentry);
			return 1;
		}
	}
	return 0;
} 

int get_local_resolvers(char  nslist[MAXNS][INET6_ADDRSTRLEN * 2])
{
	char buf[LINEL]; 
	int  i = 0;

	FILE *R = fopen ("/etc/resolv.conf", "r");
	if (R != NULL) {
		while ( (fgets (buf, LINEL, R)) && (i < MAXNS)) {	
			if(resolv_conf_parse_line(nslist[i], buf) )
				i++;
		}
		fclose (R);
	}
	return i;
}
