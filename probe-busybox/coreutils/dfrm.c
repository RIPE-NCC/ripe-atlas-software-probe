/*
 * Copyright (c) 2013 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * dfrm.c
 * Remove the contents of directories if the amount of free space gets too low
 */
//config:config DFRM
//config:       bool "dfrm"
//config:       default n
//config:       help
//config:         dfrm deletes files from directories when the amount of free space is
//config:         too low

//applet:IF_DFRM(APPLET(dfrm, BB_DIR_ROOT, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_DFRM) += dfrm.o

//usage:#define dfrm_trivial_usage
//usage:       "<fs> <min-size> <dir>..."
//usage:#define dfrm_full_usage
//usage:       "<fs> <min-size> <dir>..."

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../config.h"
#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#elif defined(HAVE_SYS_VFS_H)
#include <sys/vfs.h>
#endif

#include "libbb.h"

#define DBQ(str) "\"" #str "\""

int dfrm_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int dfrm_main(int argc, char *argv[])
{
	int i;
	size_t len;
	unsigned long limit, avail;
	char *opt_atlas;
	char *dev, *limit_str, *dir_str, *check, *path;
	DIR *dir;
	struct dirent *de;
	struct statfs sb;

	opt_atlas= NULL;
	opt_complementary= NULL;        /* Just in case */
	getopt32(argv, "A:", &opt_atlas);

	if (argc < optind+3)
	{
		printf("not enough arguments\n");
		return 1;
	}
	dev= argv[optind];
	limit_str= argv[optind+1];

	if (statfs(dev, &sb) != 0)
	{
		fprintf(stderr, "statfs on %s failed: %s\n", 
			dev, strerror(errno));
		return 1;
	}

	printf("RESULT { ");
	if (opt_atlas)
	{
		printf(
		DBQ(id) ":" DBQ(%s) ", %s, " DBQ(time) ": %ld, ",
			opt_atlas, atlas_get_version_json_str(),
			(long)time(NULL));
	}
	printf(DBQ(bsize) ": %ld, " DBQ(blocks) ": %ld, "
		DBQ(bfree) ": %ld, " DBQ(free) ": %ld",
		(long)sb.f_bsize, (long)sb.f_blocks, (long)sb.f_bfree,
		(long)sb.f_bfree*(sb.f_bsize/1024));
	printf(" }\n");

	avail= sb.f_bavail*(sb.f_bsize/1024);

	limit= strtoul(limit_str, &check, 10);
	if (check[0] != '\0')
	{
		fprintf(stderr, "unable to parse limit '%s'\n", limit_str);
		return 1;
	}
	if (avail > limit)
		return 1;

	for (i= optind+2; i < argc; i++)
	{
		dir_str= argv[i];

		dir= opendir(dir_str);
		if (!dir)
		{
			fprintf(stderr, "opendir failed for '%s'\n", dir_str);
			continue;
		}

		path= NULL;
		while (de= readdir(dir), de != NULL)
		{
			if (strcmp(de->d_name, ".") == 0 ||
				strcmp(de->d_name, "..") == 0)
			{
				continue;
			}
			len= strlen(dir_str) + 1 + strlen(de->d_name) + 1;
			path= realloc(path, len);	/* Avoid leaks */
			if (path == NULL)
			{
				fprintf(stderr,
					"unable to allocate %ld bytes\n",
					(long)len);
				continue;
			}
			strlcpy(path, dir_str, len);
			strlcat(path, "/", len);
			strlcat(path, de->d_name, len);

			if (unlink(path) != 0)
			{
				fprintf(stderr, "unable to unlink '%s': %s\n",
					path, strerror(errno));
				continue;
			}
			fprintf(stderr, "rm %s\n", path);
		}
		closedir(dir);
		free(path); path= NULL;

	}

	return 0;
}
