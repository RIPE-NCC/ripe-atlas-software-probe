#include <platform.h>
#include <net/route.h>

#include "libbb.h"

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

