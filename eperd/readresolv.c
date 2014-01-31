/*
 * Copyright (c) 2013 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#define LINEL (INET6_ADDRSTRLEN * 2)
#include "libbb.h"
#include "resolv.h"
#include "eperd.h"
#include <math.h>

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

void get_local_resolvers(char  nslist[MAXNS][INET6_ADDRSTRLEN * 2], 
		int *resolv_max)
{

#ifndef RESOLV_CONF 
#define RESOLV_CONF     "/etc/resolv.conf"
#endif 	
	char buf[LINEL]; 
	char *buf_start;
	int  i = 0;
	time_t now;
	int r;
	struct stat sb;

	static resolv_last_check = -1;
	static time_t last_time= -1;

	now = time(NULL);

	if(*resolv_max){
		if ( pow (resolv_last_check - now, 2) > 3) {
			crondlog(LVL5 "check the %s", RESOLV_CONF);
		}
		else {
			return;
		}

	}


	r = stat(RESOLV_CONF, &sb);
	if (r == -1)
	{
		crondlog(LVL8 "error accessing resolv.conf: %s",
				strerror(errno));
		return;
	}

	resolv_last_check = now;

	if (last_time  == sb.st_mtime) 
	{
		/* nothing changed */
		crondlog(LVL5 "re-read %s. not reading this time", RESOLV_CONF);
		return;
	}
	else {
		crondlog(LVL5 "re-read %s . it has changed", RESOLV_CONF);
	}

	FILE *R = fopen (RESOLV_CONF, "r");
	if (R != NULL) {
		while ( (fgets (buf, LINEL, R)) && (i < MAXNS)) {	
			buf_start = buf;
			if(resolv_conf_parse_line(nslist[i], buf) ) {
				crondlog(LVL5 "parsed file %s , line %s i=%d", RESOLV_CONF, buf_start, i);
				i++;
			}
			else 
				crondlog(LVL5 "ERROR failed to parse from  %s i=%d, line %s", RESOLV_CONF, i, buf_start);
		}
		fclose (R);
	}

	last_time = sb.st_mtime;

	*resolv_max = i;
	return;
}
