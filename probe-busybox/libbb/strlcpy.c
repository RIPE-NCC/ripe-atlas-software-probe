/*
 * Copyright (C) 2002     Manuel Novoa III
 * Copyright (C) 2000-2005 Erik Andersen <andersen@uclibc.org>
 *
 * Licensed under the LGPL v2.1, see the file COPYING.LIB in this tarball.
 */

#include "libbb.h"

#ifdef WANT_WIDE
# define Wstrlcpy __wcslcpy
# define Wstrxfrm wcsxfrm
#else
// libc_hidden_proto(strlcpy)
# define Wstrlcpy strlcpy
# define Wstrxfrm strxfrm
# define Wchar char
#endif


/* OpenBSD function:
 * Copy at most n-1 chars from src to dst and nul-terminate dst.
 * Returns strlen(src), so truncation occurred if the return value is >= n. */

#ifdef WANT_WIDE
size_t Wstrlcpy(register Wchar *__restrict dst,
				  register const Wchar *__restrict src,
				  size_t n) attribute_hidden;
#endif
size_t Wstrlcpy(register Wchar *__restrict dst,
				  register const Wchar *__restrict src,
				  size_t n)
{
	const Wchar *src0 = src;
	Wchar dummy[1];

	if (!n) {
		dst = dummy;
	} else {
		--n;
	}

	while ((*dst = *src) != 0) {
		if (n) {
			--n;
			++dst;
		}
		++src;
	}

	return src - src0;
}
#ifndef WANT_WIDE
//libc_hidden_def(strlcpy)
#ifndef __UCLIBC_HAS_LOCALE__
//libc_hidden_proto(strxfrm)
//strong_alias(strlcpy,strxfrm)
//libc_hidden_def(strxfrm)
#endif
#else
#ifndef __UCLIBC_HAS_LOCALE__
strong_alias(__wcslcpy,wcsxfrm)
#endif
#endif
