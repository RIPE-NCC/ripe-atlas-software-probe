/*
 * Copyright (c) 2013 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * condmv.c -- move a file only if the destination doesn't exist
 */

#include "libbb.h"
#include "eperd.h"

#define SAFE_PREFIX_FROM ATLAS_DATA_NEW
#define SAFE_PREFIX_TO ATLAS_DATA_OUT

#define A_FLAG	(1 << 0)
#define F_FLAG	(1 << 1)

#define DEFAULT_INTERVAL	60

struct condmvstate
{
	char *from;
	char *to;
	char *atlas;
	int force;
	int interval;
};

static void *condmv_init(int argc, char *argv[],
	void (*done)(void *state) UNUSED_PARAM)
{
	char *opt_add, *opt_interval, *from, *to, *check;
	int interval;
	uint32_t opt;
	struct condmvstate *state;

	opt_add= NULL;
	opt_interval= NULL;
	opt_complementary= NULL;	/* For when we are called by crond */
	opt= getopt32(argv, "!A:fi:", &opt_add, &opt_interval);
	if (opt == (uint32_t)-1)
		return NULL;

	if (argc != optind + 2)
	{
		crondlog(LVL8 "too many or too few arguments (required 2)"); 
		return NULL;
	}

	if (opt_interval)
	{
		interval= strtoul(opt_interval, &check, 0);
		if (interval <= 0)
		{
			crondlog(LVL8 "unable to parse interval '%s'",
				opt_interval); 
			return NULL;
		}
	}
	else
		interval= DEFAULT_INTERVAL;

	from= argv[optind];
	to= argv[optind+1];

	if (!validate_filename(from, SAFE_PREFIX_FROM))
	{
		fprintf(stderr, "insecure from file '%s'\n", from);
		return NULL;
	}
	if (!validate_filename(to, SAFE_PREFIX_TO))
	{
		fprintf(stderr, "insecure to file '%s'\n", to);
		return NULL;
	}

	state= malloc(sizeof(*state));
	state->from= strdup(from);
	state->to= strdup(to);
	state->atlas= opt_add ? strdup(opt_add) : NULL;
	state->force= !!(opt & F_FLAG);
	state->interval= interval;

	return state;
}

static void condmv_start(void *state)
{
	size_t len;
	time_t mytime;
	char *to;
	FILE *file;
	struct condmvstate *condmvstate;
	struct stat sb;

	condmvstate= state;

	len= strlen(condmvstate->to) + 20;
	to= malloc(len);
	snprintf(to, len, "%s.%ld", condmvstate->to,
		(long)time(NULL)/condmvstate->interval);

	crondlog(LVL7 "condmv_start: destination '%s'\n", to);

	if (stat(to, &sb) == 0 && !condmvstate->force)
	{
		free(to);
		return;
	}

	if (condmvstate->atlas)
	{
		mytime = time(NULL);
		/* We have to add something to the existing file before moving
		 * to.
		 */
		file= fopen(condmvstate->from, "a");
		if (file == NULL)
		{
			crondlog(LVL9 "condmv: unable to append to '%s': %s\n",
				condmvstate->from, strerror(errno));
			free(to);
			return;
		}
		if (fprintf(file, "%s %lu %s\n", condmvstate->atlas, mytime,
			condmvstate->from) < 0)
		{
			crondlog(LVL9 "condmv: unable to append to '%s': %s\n",
				condmvstate->from, strerror(errno));
			fclose(file);
			free(to);
			return;
		}
		if (fclose(file) != 0)
		{
			crondlog(LVL9 "condmv: unable to close '%s': %s\n",
				condmvstate->from, strerror(errno));
			free(to);
			return;
		}
	}
	if (rename(condmvstate->from, to) != 0)
	{
		crondlog(LVL9 "condmv: unable to rename '%s' to '%s': %s\n",
			condmvstate->from, to, strerror(errno));
	}	
	free(to);
}

static int condmv_delete(void *state)
{
	struct condmvstate *condmvstate;

	condmvstate= state;
	free(condmvstate->from);
	condmvstate->from= NULL;
	free(condmvstate->to);
	condmvstate->to= NULL;
	free(condmvstate->atlas);
	condmvstate->atlas= NULL;

	free(condmvstate);
	
	return 1;
}

struct testops condmv_ops = { condmv_init, condmv_start, condmv_delete };

