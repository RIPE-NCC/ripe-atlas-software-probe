/*
dfrm.c

Remove the contents of directories if the amount of free space gets too low
*/

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/vfs.h>

#include "libbb.h"

int dfrm_main(int argc, char *argv[])
{
	int i;
	size_t len;
	unsigned long limit, avail;
	char *dev, *limit_str, *dir_str, *check, *path;
	DIR *dir;
	struct dirent *de;
	struct statfs sb;

	if (argc < 3)
	{
		printf("not enough arguments\n");
		return 1;
	}
	dev= argv[1];
	limit_str= argv[2];

	if (statfs(dev, &sb) != 0)
	{
		fprintf(stderr, "statfs on %s failed: %s\n", 
			dev, strerror(errno));
		return 1;
	}

	printf("bsize: %d\n", sb.f_bsize);
	printf("blocks: %d\n", sb.f_blocks);
	printf("bfree: %d\n", sb.f_bfree);
	printf("bavail: %d\n", sb.f_bavail);
	printf("free: %dKByte, free (non-root): %dKByte\n",
		sb.f_bfree*(sb.f_bsize/1024),
		sb.f_bavail*(sb.f_bsize/1024));

	avail= sb.f_bavail*(sb.f_bsize/1024);

	limit= strtoul(limit_str, &check, 10);
	if (check[0] != '\0')
	{
		fprintf(stderr, "unable to parse limit '%s'\n", limit_str);
		return 1;
	}
	if (avail > limit)
	{
		printf("enough space free, no need to do anything\n");
		return 1;
	}

	for (i= 3; i < argc; i++)
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
				fprintf(stderr, "unable to allocate %d bytes\n",
					len);
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
			printf("rm %s\n", path);
		}
		closedir(dir);
		free(path); path= NULL;

	}

	return 0;
}
