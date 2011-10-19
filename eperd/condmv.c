/*
condmv.c -- move a file only if the destination doesn't exist

*/

#include "libbb.h"
#include "eperd.h"

#define A_FLAG	(1 << 0)
#define F_FLAG	(1 << 1)

struct condmvstate
{
	char *from;
	char *to;
	char *atlas;
	int force;
};

static void *condmv_init(int argc, char *argv[])
{
	char *opt_add, *from, *to;
	unsigned opt;
	struct condmvstate *state;

	opt_add= NULL;
	opt_complementary= NULL;	/* For when we are called by crond */
	opt= getopt32(argv, "A:f", &opt_add);

	if (argc != optind + 2)
		bb_show_usage();

	from= argv[optind];
	to= argv[optind+1];

	state= malloc(sizeof(*state));
	state->from= strdup(from);
	state->to= strdup(to);
	state->atlas= opt_add ? strdup(opt_add) : NULL;
	state->force= !!(opt & F_FLAG);

	return state;
}

static void condmv_start(void *state)
{
	struct stat sb;
	FILE *file;
	time_t mytime;
	struct condmvstate *condmvstate;

	condmvstate= state;

	if (stat(condmvstate->to, &sb) == 0 && !condmvstate->force)
	{
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
			return;
		}
		if (fprintf(file, "%s %lu %s\n", condmvstate->atlas, mytime,
			condmvstate->from) < 0)
		{
			crondlog(LVL9 "condmv: unable to append to '%s': %s\n",
				condmvstate->from, strerror(errno));
			fclose(file);
			return;
		}
		if (fclose(file) != 0)
		{
			crondlog(LVL9 "condmv: unable to close '%s': %s\n",
				condmvstate->from, strerror(errno));
			return;
		}
	}
	if (rename(condmvstate->from, condmvstate->to) != 0)
	{
		crondlog(LVL9 "condmv: unable to rename '%s' to '%s': %s\n",
			condmvstate->from, condmvstate->to, strerror(errno));
		return;
	}
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

