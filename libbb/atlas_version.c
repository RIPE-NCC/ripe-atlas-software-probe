/*
 * Copyright (c) 2019 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include "libbb.h"

#define ATLAS_FW_VERSION_REL	"state/FIRMWARE_APPS_VERSION"

#define DBQ(str) "\"" #str "\""

static int get_atlas_fw_version(void)
{
	static int fw_version= -1;

	int r, fw;
	char *fn;
	FILE *file;

	if (fw_version != -1)
		return fw_version;

	fn= atlas_path(ATLAS_FW_VERSION_REL);
	file= fopen(fn, "r");
	if (file == NULL)
	{
		free(fn); fn= NULL;
		return -1;
	}
	r= fscanf(file, "%d", &fw);
	fclose(file);
	if (r == -1)
	{
		free(fn); fn= NULL;
		return -1;
	}
	free(fn); fn= NULL;

	fw_version= fw;
	return fw;
}

char *atlas_get_version_json_str(void)
{
	static char version_buf[80];	/* Enough? */
	static int first= 1;

	if (first)
	{
		first= 0;

		if (getenv("ATLAS_TESTS"))
		{
			snprintf(version_buf, sizeof(version_buf),
				DBQ(fw) ":%d, " DBQ(mver) ": " DBQ(%s),
				9999, "0.0.0");
		}
		else
		{
			snprintf(version_buf, sizeof(version_buf),
				DBQ(fw) ":%d, " DBQ(mver) ": " DBQ(%s),
				get_atlas_fw_version(), ATLAS_MSM_VERSION);
		}
	}
	return version_buf;
}

