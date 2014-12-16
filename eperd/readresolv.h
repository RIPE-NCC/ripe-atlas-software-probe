/*
 * Copyright (c) 2013-2014 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */
void get_local_resolvers(char  nslist[MAXNS][INET6_ADDRSTRLEN * 2], int *resolv_max);
void get_local_resolvers_nocache(char  nslist[MAXNS][INET6_ADDRSTRLEN * 2], 
		int *resolv_max);
