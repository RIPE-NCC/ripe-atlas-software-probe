/*
 * portable_networking.h
 * Portable networking types and functions for cross-platform support
 * Copyright (c) 2013-2014 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#ifndef PORTABLE_NETWORKING_H
#define PORTABLE_NETWORKING_H

#include <netinet/in.h>
#include <net/if.h>

#ifdef __FreeBSD__
#include <ifaddrs.h>
#include <net/if.h>
#else
/* Linux/glibc compatibility */
#include <ifaddrs.h>
#include <net/if.h>
#endif

/* Portable interface information structure */
typedef struct {
    char name[IF_NAMESIZE];
    unsigned int flags;
    struct in_addr addr;
    struct in_addr netmask;
    struct in_addr broadcast;
    struct in6_addr addr6;
    int prefix_len;
} portable_if_info_t;

/* Ensure IFF_UP is defined */
#ifndef IFF_UP
#define IFF_UP 0x1
#endif

/* Ensure getifaddrs and freeifaddrs are available */
#ifndef HAVE_GETIFADDRS
#ifdef __FreeBSD__
/* FreeBSD has these natively */
#else
/* Linux/glibc compatibility - these should be available */
#endif
#endif

#endif /* PORTABLE_NETWORKING_H */
