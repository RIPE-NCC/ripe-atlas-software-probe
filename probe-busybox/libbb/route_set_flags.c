#include <platform.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/route.h>

#include "libbb.h"

#ifdef __APPLE__
#ifndef RTF_REINSTATE
#define RTF_REINSTATE 0x1000
#endif
#ifndef RTF_DEFAULT
#define RTF_DEFAULT 0x2000
#endif
#ifndef RTF_ADDRCONF
#define RTF_ADDRCONF 0x4000
#endif
#ifndef RTF_CACHE
#define RTF_CACHE 0x8000
#endif
#ifndef RTF_NONEXTHOP
#define RTF_NONEXTHOP 0x10000
#endif
#endif

#ifdef __FreeBSD__
/* FreeBSD route flags - define missing ones */
#ifndef RTF_REINSTATE
#define RTF_REINSTATE 0x0008
#endif
#ifndef RTF_DEFAULT
#define RTF_DEFAULT 0x0002
#endif
#ifndef RTF_ADDRCONF
#define RTF_ADDRCONF 0x0004
#endif
#ifndef RTF_CACHE
#define RTF_CACHE 0x0001
#endif
#ifndef RTF_NONEXTHOP
#define RTF_NONEXTHOP 0x0020
#endif
#endif

static const
IF_NOT_FEATURE_IPV6(uint16_t)
IF_FEATURE_IPV6(unsigned)
flagvals[] = { /* Must agree with flagchars[]. */
	RTF_UP,
	RTF_GATEWAY,
	RTF_HOST,
	RTF_REINSTATE,
	RTF_DYNAMIC,
	RTF_MODIFIED,
#if ENABLE_FEATURE_IPV6
	RTF_DEFAULT,
	RTF_ADDRCONF,
	RTF_CACHE,
	RTF_REJECT,
	RTF_NONEXTHOP, /* this one doesn't fit into 16 bits */
#endif
};
/* Must agree with flagvals[]. */
static const char flagchars[] ALIGN1 =
	"UGHRDM"
#if ENABLE_FEATURE_IPV6
	"DAC!n"
#endif
;

void route_set_flags(char *flagstr, int flags)
{
	int i;

	for (i = 0; (*flagstr = flagchars[i]) != 0; i++) {
		if (flags & flagvals[i]) {
			++flagstr;
		}
	}
}

