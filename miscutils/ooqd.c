/*
 * ooqd.c One-off queue daemon
 * Copyright (c) 2011-2014 RIPE NCC <atlas@ripe.net>
 */

#include <stdio.h>
#include <string.h>

#include <libbb.h>
#include <cmdtable.h>

#define SUFFIX 		".curr"
#define WAIT_TIME	10	/* in seconds */
#define NARGS		40	/* Max arguments to a built-in command */
#define WIFIMSM_PATH	"/home/atlas/bin/wifimsm"

#define SAFE_PREFIX ATLAS_DATA_NEW

#ifdef __uClinux__
#define NO_FORK	1
#endif

static void process(FILE *file);
static void report(const char *fmt, ...);
static void report_err(const char *fmt, ...);

int ooqd_main(int argc, char *argv[]) MAIN_EXTERNALLY_VISIBLE;
int ooqd_main(int argc, char *argv[])
{
	char *queue_file;
	FILE *file;
	char curr_qfile[256];

	if (argc != 2)
	{
		bb_show_usage();
		return 1;
	}

	queue_file= argv[1];

	if (strlen(queue_file) + strlen(SUFFIX) + 1 > sizeof(curr_qfile))
	{
		report("filename too long ('%s')", queue_file);
		return 1;
	}

	strlcpy(curr_qfile, queue_file, sizeof(curr_qfile));
	strlcat(curr_qfile, SUFFIX, sizeof(curr_qfile));

	for(;;)
	{
		/* Try to move queue_file to curr_qfile. This provide at most
		 * once behavior and allows producers to create a new
		 * queue_file while we process the old one.
		 */
		if (rename(queue_file, curr_qfile) == -1)
		{
			if (errno == ENOENT)
			{
				sleep(WAIT_TIME);
				continue;
			}
			report_err("rename failed");
			return 1;
		}

		file= fopen(curr_qfile, "r");
		if (file == NULL)
		{
			report_err("open '%s' failed", curr_qfile);
			continue;
		}

		process(file);

		fclose(file);

		/* No need to delete curr_qfile */
	}
	return 0;
}

static void skip_space(char *cp, char **ncpp)
{
	while (cp[0] != '\0' && isspace(*(unsigned char *)cp))
		cp++;
	*ncpp= cp;
}

static void skip_nonspace(char *cp, char **ncpp)
{
	while (cp[0] != '\0' && !isspace(*(unsigned char *)cp))
		cp++;
	*ncpp= cp;
}

static void find_eos(char *cp, char **ncpp)
{
	while (cp[0] != '\0' && cp[0] != '"')
		cp++;
	*ncpp= cp;
}

static void process(FILE *file)
{
	int i, argc, do_append, saved_fd, out_fd, flags;
	size_t len;
	char *cp, *ncp, *outfile;
	struct builtin *bp;
	char line[2048];
	char *argv[NARGS];

printf("in process\n");
	while (cp= fgets(line, sizeof(line), file), cp  != NULL)
	{
printf("got cp %p, line %p, '%s'\n", cp, line, cp);
		if (strchr(line, '\n') == NULL)
		{
			report("line '%s' too long", line);
			return;
		}

		/* Skip leading white space */
		cp= line;
		while (cp[0] != '\0' && isspace((unsigned char)cp[0]))
			cp++;

		if (cp[0] == '\0' || cp[0] == '#')
			continue;	/* Empty or comment line */

		for (bp= builtin_cmds; bp->cmd != NULL; bp++)
		{
			len= strlen(bp->cmd);
			if (strncmp(cp, bp->cmd, len) != 0)
				continue;
			if (cp[len] != ' ')
				continue;
			break;
		}
		if (bp->cmd == NULL)
		{
			report("nothing found for '%s'", cp);
			return;		/* Nothing found */
		}

		/* Remove trailing white space */
		len= strlen(cp);
		while (len > 0 && isspace((unsigned char)cp[len-1]))
		{
			cp[len-1]= '\0';
			len--;
		}
		
		outfile= NULL;
		do_append= 0;

		/* Split the command line */
		argc= 0;
		argv[argc]= cp;
		skip_nonspace(cp, &ncp);
		cp= ncp;

		for(;;)
		{
			/* End of list */
			if (cp[0] == '\0')
			{
				argc++;
				break;
			}

			/* Find start of next argument */
			skip_space(cp, &ncp);

			/* Terminate current one */
			cp[0]= '\0';

			/* Special case for '>' */
			if (argv[argc][0] == '>')
			{
				cp= argv[argc]+1;
				if (cp[0] == '>')
				{
					/* Append */
					do_append= 1;
					cp++;
				}
				if (cp[0] != '\0')
				{
					/* Filename immediately follows '>' */
					outfile= cp;
					
					/* And move on with the next option */
				}
				else
				{
					/* Get the next argument */
					outfile= ncp;
					cp= ncp;
					skip_nonspace(cp, &ncp);
					cp= ncp;

					if (cp[0] == '\0')
						break;

					/* Find start of next argument */
					skip_space(cp, &ncp);
					*cp= '\0';

					if (ncp[0] == '\0')
						break;	/* No more arguments */
				}
			}
			else
			{
				argc++;
			}

			if (argc >= NARGS-1)
			{
				report("command line '%s', too many arguments",
					line);
				continue;	/* Just skip it */
			}

			cp= ncp;
			argv[argc]= cp;
			if (cp[0] == '"')
			{
				/* Special code for strings */
				find_eos(cp+1, &ncp);
				if (ncp[0] != '"')
				{
					report(
			"command line '%s', end of string not found",
						line);
					continue;	/* Just skip it */
				}
				argv[argc]= cp+1;
				cp= ncp;
				cp[0]= '\0';
				cp++;
			}
			else
			{
				skip_nonspace(cp, &ncp);
				cp= ncp;
			}
		}

		if (argc >= NARGS)
		{
			report("command line '%s', too many arguments", line);
			return;
		}
		argv[argc]= NULL;

		for (i= 0; i<argc; i++)
			report("argv[%d] = '%s'", i, argv[i]);

		saved_fd= -1;	/* lint */
		if (outfile)
		{
			/* Redirect I/O */
			report("sending output to '%s'", outfile);
			if (!validate_filename(outfile, SAFE_PREFIX))
			{
				report("insecure output file '%s'", outfile);
				return;
			}
			flags= O_CREAT | O_WRONLY;
			if (do_append)
				flags |= O_APPEND;
			out_fd= open(outfile, flags, 0644);
			if (out_fd == -1)
			{
				report_err("unable to create output file '%s'",
					outfile);
				return;
			}
			fflush(stdout);
			saved_fd= dup(1);
			if (saved_fd == -1)
			{
				report("unable to dub stdout");
				close(out_fd);
				return;
			}
			dup2(out_fd, 1);
			close(out_fd);
		}

		bp->func(argc, argv);

		if (outfile)
		{
			fflush(stdout);
			dup2(saved_fd, 1);
			close(saved_fd);
		}
	}
}

static void report(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "ooqd: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");

	va_end(ap);
}

static void report_err(const char *fmt, ...)
{
	int terrno;
	va_list ap;

	terrno= errno;

	va_start(ap, fmt);
	fprintf(stderr, "ooqd: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, ": %s\n", strerror(terrno));

	va_end(ap);
}

int wifimsm_main(int argc UNUSED_PARAM, char *argv[])
{
#if NO_FORK
	return 1;
#else
	pid_t pid;
	int r, status;

	pid= fork();
	if (pid == -1)
	{
		report_err("wifimsm_main: fork failed");
		return 1;
	}
	if (pid)
	{
		r= waitpid(pid, &status, 0);
		if (r == -1)
		{
			report_err("wifimsm_main: waitpid failed");
			return 1;
		}
		if (WIFEXITED(status))
			return WEXITSTATUS(status);
		return 1;
	}

	execv(WIFIMSM_PATH, argv);
	report_err("wifimsm_main: execv '%s' failed", WIFIMSM_PATH);
	return 1;
#endif
}
