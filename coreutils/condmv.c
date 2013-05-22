/*
 * Copyright (c) 2013 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * condmv.c -- move a file only if the destination doesn't exist
 */

#include "libbb.h"

#define SAFE_PREFIX_FROM ATLAS_DATA_NEW
#define SAFE_PREFIX_TO ATLAS_DATA_OUT

#define A_FLAG	(1 << 0)
#define F_FLAG	(1 << 1)

int condmv_main(int argc, char *argv[])
{
	char *opt_add, *from, *to;
	uint32_t opt;
	struct stat sb;
	FILE *file;
	time_t mytime;

	opt_add= NULL;
	opt_complementary= NULL;	/* For when we are called by crond */
	opt= getopt32(argv, "!A:f", &opt_add);

	if (opt == (uint32_t)-1)
	{
		fprintf(stderr, "condmv: bad options\n");
		return 1;
	}

	if (argc != optind + 2)
	{
		fprintf(stderr, "condmv: two arguments expected\n");
		return 1;
	}

	from= argv[optind];
	to= argv[optind+1];

	if (!validate_filename(from, SAFE_PREFIX_FROM))
	{
		fprintf(stderr, "insecure from file '%s'\n", from);
		return 1;
	}
	if (!validate_filename(to, SAFE_PREFIX_TO) &&
		!validate_filename(to, SAFE_PREFIX_FROM))
	{
		fprintf(stderr, "insecure to file '%s'\n", to);
		return 1;
	}

	if (stat(to, &sb) == 0 && !(opt & F_FLAG))
	{
		/* Destination exists */
		fprintf(stderr, "condmv: not moving, destination '%s' exists\n",
			to);
		return 1;
	}

	if (opt_add)
	{
		mytime = time(NULL);
		/* We have to add something to the existing file before moving
		 * to.
		 */
		file= fopen(from, "a");
		if (file == NULL)
		{
			fprintf(stderr,
				"condmv: unable to append to '%s': %s\n",
				from, strerror(errno));
			return 1;
		}
		if (fprintf(file, "%s %lu %s\n", opt_add, mytime, from) < 0)
		{
			fprintf(stderr,
				"condmv: unable to append to '%s': %s\n",
				from, strerror(errno));
			fclose(file);
			return 1;
		}
		if (fclose(file) != 0)
		{
			fprintf(stderr,
				"condmv: unable to close '%s': %s\n",
				from, strerror(errno));
			return 1;
		}
	}
	if (rename(from, to) != 0)
	{
		fprintf(stderr, "condmv: unable to rename '%s' to '%s': %s\n",
				from, to, strerror(errno));
		return 1;
	}

	return 0;
}
