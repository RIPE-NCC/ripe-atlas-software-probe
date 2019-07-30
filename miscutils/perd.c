/* vi: set sw=4 ts=4: */
/*
 * perd formerly crond but now heavily hacked for Atlas
 *
 * crond -d[#] -c <crondir> -f -b
 *
 * run as root, but NOT setuid root
 *
 * Copyright 1994 Matthew Dillon (dillon@apollo.west.oic.com)
 * Copyright (c) 2014 RIPE NCC <atlas@ripe.net>
 * (version 2.3.2)
 * Vladimir Oleynik <dzo@simtreas.ru> (C) 2002
 *
 * Licensed under the GPL v2 or later, see the file LICENSE in this tarball.
 */
//config:config PERD
//config:       bool "perd"
//config:       default n
//config:       select FEATURE_SUID
//config:       select FEATURE_SYSLOG
//config:       help
//config:         Perd periodically runs Atlas measurements. It is based on crond.
//config:config FEATURE_PERD_D
//config:       bool "Support option -d to redirect output to stderr"
//config:       depends on PERD
//config:       default n
//config:       help
//config:         -d sets loglevel to 0 (most verbose) and directs all output to stderr.

//applet:IF_PERD(APPLET(perd, BB_DIR_BIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_PERD) += perd.o

//usage:#define perd_trivial_usage
//usage:       "-fbSAD -P pidfile -l N -d N -L LOGFILE -c DIR"
//usage:#define perd_full_usage "\n\n"
//usage:       "       -f      Foreground"
//usage:     "\n       -b      Background (default)"
//usage:     "\n       -S      Log to syslog (default)"
//usage:     "\n       -l      Set log level. 0 is the most verbose, default 8"
//usage:     "\n       -d      Set log level, log to stderr"
//usage:     "\n       -L      Log to file"
//usage:     "\n       -c      Working dir"
//usage:     "\n       -A      Atlas specific processing"
//usage:     "\n       -D      Periodically kick watchdog"
//usage:     "\n       -P      pidfile to use"

#include "libbb.h"
#include <syslog.h>

#define ATLAS 1

#define DBQ(str) "\"" #str "\""

/* glibc frees previous setenv'ed value when we do next setenv()
 * of the same variable. uclibc does not do this! */
#if (defined(__GLIBC__) && !defined(__UCLIBC__)) /* || OTHER_SAFE_LIBC... */
#define SETENV_LEAKS 0
#else
#define SETENV_LEAKS 1
#endif


#ifndef CRONTABS
#define CRONTABS        "/var/spool/cron/crontabs"
#endif
#ifndef TMPDIR
#define TMPDIR          "/var/spool/cron"
#endif
#ifndef CRONUPDATE
#define CRONUPDATE      "cron.update"
#endif
#ifndef MAXLINES
#define MAXLINES        256	/* max lines in non-root crontabs */
#endif

#define MAX_INTERVAL	(2*366*24*3600)	/* No intervals bigger than 2 years */

#ifdef ATLAS
#include <cmdtable.h>

#define SAFE_PREFIX_REL ATLAS_DATA_NEW_REL
#endif

#define URANDOM_DEV	"/dev/urandom"

typedef struct CronFile {
	struct CronFile *cf_Next;
	struct CronLine *cf_LineBase;
	char *cf_User;                  /* username                     */
	smallint cf_Ready;              /* bool: one or more jobs ready */
	smallint cf_Running;            /* bool: one or more jobs running */
	smallint cf_ToBeDeleted;        /* marked for deletion, ignore  */
	smallint cf_Deleted;            /* deleted but some entries are
					 * still busy
					 */
} CronFile;

typedef struct CronLine {
	struct CronLine *cl_Next;
	char *cl_Shell;         /* shell command                        */
	pid_t cl_Pid;           /* running pid, 0, or armed (-1)        */
	unsigned interval;
	time_t nextcycle;
	time_t start_time;
	time_t end_time;
	enum distribution { DISTR_NONE, DISTR_UNIFORM } distribution;
	int distr_param;	/* Parameter for distribution, if any */
	int distr_offset;	/* Current offset to randomize the interval */

	/* For debugging */
	time_t lasttime;
} CronLine;


#define DaemonUid 0


enum {
	OPT_l = (1 << 0),
	OPT_L = (1 << 1),
	OPT_f = (1 << 2),
	OPT_b = (1 << 3),
	OPT_S = (1 << 4),
	OPT_c = (1 << 5),
	OPT_A = (1 << 6),
	OPT_D = (1 << 7),
	OPT_d = (1 << 8) * ENABLE_FEATURE_CROND_D,
};
#if ENABLE_FEATURE_CROND_D
#define DebugOpt (option_mask32 & OPT_d)
#else
#define DebugOpt 0
#endif


struct globals {
	unsigned LogLevel; /* = 8; */
	const char *LogFile;
	const char *CDir; /* = CRONTABS; */
	CronFile *FileBase;
	CronFile *oldFile;
	CronLine *oldLine;
#if SETENV_LEAKS
	char *env_var_user;
	char *env_var_home;
#endif
};
#ifdef ATLAS
static struct globals G;
#else
#define G (*(struct globals*)&bb_common_bufsiz1)
#endif
#define LogLevel           (G.LogLevel               )
#define LogFile            (G.LogFile                )
#define CDir               (G.CDir                   )
#define FileBase           (G.FileBase               )
#define oldFile            (G.oldFile                )
#define oldLine            (G.oldLine                )
#define env_var_user       (G.env_var_user           )
#define env_var_home       (G.env_var_home           )
#define INIT_G() do { \
	LogLevel = 8; \
	CDir = CRONTABS; \
} while (0)

#ifdef ATLAS
static int do_kick_watchdog;
static char *atlas_id= NULL;
static char *out_filename= NULL;

static int atlas_run(char *cmdline);
#endif

static void CheckUpdates(void);
static void SynchronizeDir(void);
static int TestJobs(time_t *nextp);
static void RunJobs(void);
static int CheckJobs(void);
static void RunJob(const char *user, CronLine *line);
#define EndJob(user, line)  ((line)->cl_Pid = 0)
static void DeleteFile(CronFile *tfile);
static void SetOld(const char *userName);
static void CopyFromOld(CronLine *line);


#define LVL5  "\x05"
#define LVL7  "\x07"
#define LVL8  "\x08"
#define LVL9  "\x09"
#define WARN9 "\x49"
#define DIE9  "\xc9"
/* level >= 20 is "error" */
#define ERR20 "\x14"

static void crondlog(const char *ctl, ...)
{
	va_list va;
	int level = (ctl[0] & 0x1f);

	va_start(va, ctl);
	if (level >= (int)LogLevel) {
		/* Debug mode: all to (non-redirected) stderr, */
		/* Syslog mode: all to syslog (logmode = LOGMODE_SYSLOG), */
		if (!DebugOpt && LogFile) {
			/* Otherwise (log to file): we reopen log file at every write: */
			int logfd = open3_or_warn(LogFile, O_WRONLY | O_CREAT | O_APPEND, 0600);
			if (logfd >= 0)
				xmove_fd(logfd, STDERR_FILENO);
		}
// TODO: ERR -> error, WARN -> warning, LVL -> info
		bb_verror_msg(ctl + 1, va, /* strerr: */ NULL);
	}
	va_end(va);
	if (ctl[0] & 0x80)
		exit(20);
}

static void my_exit(void)
{
	crondlog(LVL8 "in my_exit (exit was called!)");
	abort();
}

static void kick_watchdog(void)
{
	if(do_kick_watchdog) 
	{
		int fdwatchdog = open("/dev/watchdog", O_RDWR);
		write(fdwatchdog, "1", 1);
		close(fdwatchdog);
	}
}

int perd_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int perd_main(int argc UNUSED_PARAM, char **argv)
{
	unsigned opt;
	int fd;
	unsigned seed;

	const char *PidFileName = NULL;
	atexit(my_exit);

	INIT_G();

	/* "-b after -f is ignored", and so on for every pair a-b */
	opt_complementary = "f-b:b-f:S-L:L-S:d-l"
			":l+:d+"; /* -l and -d have numeric param */
	opt = getopt32(argv, "l:L:fbSc:A:DP:d:O:",
			&LogLevel, &LogFile, &CDir, &atlas_id,
			&PidFileName, &LogLevel, &out_filename);
	/* both -d N and -l N set the same variable: LogLevel */

	if (!(opt & OPT_f)) {
		/* close stdin, stdout, stderr.
		 * close unused descriptors - don't need them. */
		bb_daemonize_or_rexec(DAEMON_CLOSE_EXTRA_FDS, argv);
	}

	if (!DebugOpt && LogFile == NULL) {
		/* logging to syslog */
		openlog(applet_name, LOG_CONS | LOG_PID, LOG_LOCAL6);
		logmode = LOGMODE_SYSLOG;
	}

	do_kick_watchdog= !!(opt & OPT_D);

	xchdir(CDir);
	//signal(SIGHUP, SIG_IGN); /* ? original crond dies on HUP... */
	xsetenv("SHELL", DEFAULT_SHELL); /* once, for all future children */
	crondlog(LVL9 "crond (busybox "BB_VER") started, log level %d", LogLevel);

	fd= open(URANDOM_DEV, O_RDONLY);

	/* Best effort, just ignore errors */
	if (fd != -1)
	{
		read(fd, &seed, sizeof(seed));
		close(fd);
	}
	crondlog(LVL7 "using seed '%u'", seed);
	srandom(seed);

	SynchronizeDir();

	/* main loop - synchronize to 1 second after the minute, minimum sleep
	 * of 1 second. */
	{
		time_t t1 = time(NULL);
		time_t next;
		time_t last_minutely= 0;
		time_t last_hourly= 0;
		int sleep_time = 10; /* AA previously 60 */
		if(PidFileName)
		{
			write_pidfile(PidFileName);
		}
		else 
		{
			write_pidfile("/var/run/crond.pid");
		}
		for (;;) {
			kick_watchdog();
			sleep(sleep_time);

			kick_watchdog();

			if (t1 >= last_minutely + 60)
			{
				last_minutely= t1;
				CheckUpdates();
			}
			if (t1 < last_minutely)
			{
				/* Time is going backward */
				last_minutely= t1;
			}
			if (t1 >= last_hourly + 3600)
			{
				last_hourly= t1;
				SynchronizeDir();
			}
			if (t1 < last_hourly)
			{
				/* Time is going backward */
				last_hourly= t1;
			}
			{
				sleep_time= 60;
				if (do_kick_watchdog)
					sleep_time= 10;
				TestJobs(&next);
				crondlog(LVL7 "got next %d, now %d",
					next, time(NULL));
				if (!next)
				{
					crondlog(LVL7 "calling RunJobs at %d",
						time(NULL));
					RunJobs();
					crondlog(LVL7 "RunJobs ended at %d",
						time(NULL));
					sleep_time= 1;
				} else if (next > t1 && next < t1+sleep_time)
					sleep_time= next-t1;
				if (CheckJobs() > 0) {
					sleep_time = 10;
				}
				crondlog(
				LVL7 "t1 = %d, next = %d, sleep_time = %d",
					t1, next, sleep_time);
			}
			t1= time(NULL);
		}
	}
	return 0; /* not reached */
}

#if SETENV_LEAKS
/* We set environment *before* vfork (because we want to use vfork),
 * so we cannot use setenv() - repeated calls to setenv() may leak memory!
 * Using putenv(), and freeing memory after unsetenv() won't leak */
static void safe_setenv4(char **pvar_val, const char *var, const char *val /*, int len*/)
{
	const int len = 4; /* both var names are 4 char long */
	char *var_val = *pvar_val;

	if (var_val) {
		var_val[len] = '\0'; /* nuke '=' */
		unsetenv(var_val);
		free(var_val);
	}
	*pvar_val = xasprintf("%s=%s", var, val);
	putenv(*pvar_val);
}
#endif

static void SetEnv(struct passwd *pas)
{
#if SETENV_LEAKS
	safe_setenv4(&env_var_user, "USER", pas->pw_name);
	safe_setenv4(&env_var_home, "HOME", pas->pw_dir);
	/* if we want to set user's shell instead: */
	/*safe_setenv(env_var_user, "SHELL", pas->pw_shell, 5);*/
#else
	xsetenv("USER", pas->pw_name);
	xsetenv("HOME", pas->pw_dir);
#endif
	/* currently, we use constant one: */
	/*setenv("SHELL", DEFAULT_SHELL, 1); - done earlier */
}

static void ChangeUser(struct passwd *pas)
{
	/* careful: we're after vfork! */
	change_identity(pas); /* - initgroups, setgid, setuid */
	if (chdir(pas->pw_dir) < 0) {
		crondlog(LVL9 "can't chdir(%s)", pas->pw_dir);
		if (chdir(TMPDIR) < 0) {
			crondlog(DIE9 "can't chdir(%s)", TMPDIR); /* exits */
		}
	}
}

static const char DowAry[] ALIGN1 =
	"sun""mon""tue""wed""thu""fri""sat"
	/* "Sun""Mon""Tue""Wed""Thu""Fri""Sat" */
;

static const char MonAry[] ALIGN1 =
	"jan""feb""mar""apr""may""jun""jul""aug""sep""oct""nov""dec"
	/* "Jan""Feb""Mar""Apr""May""Jun""Jul""Aug""Sep""Oct""Nov""Dec" */
;


static void do_distr(CronLine *line)
{
	long n, r, modulus, max;

	line->distr_offset= 0;		/* Safe default */
	if (line->distribution == DISTR_UNIFORM)
	{
		/* Generate a random number in the range [0..distr_param] */
		modulus= line->distr_param+1;
		n= LONG_MAX/modulus;
		max= n*modulus;
		do
		{
			r= random();
		} while (r >= max);
		r %= modulus;
		line->distr_offset= r - line->distr_param/2;
	}
	crondlog(LVL7 "do_distr: using %d", line->distr_offset);
}

static void SynchronizeFile(const char *fileName)
{
	struct parser_t *parser;
	struct stat sbuf;
	int maxLines;
	char *tokens[6];
	char *check0, *check1, *check2;
	time_t now;

	if (!fileName)
		return;

	SetOld(fileName);

	parser = config_open(fileName);
	if (!parser)
	{
		/* We have to get rid of the old entries if the file is not
		 * there. Assume a non-existant file is the only reason for
		 * failure.
		 */
		DeleteFile(oldFile);
		return;
	}

	maxLines = (strcmp(fileName, "root") == 0) ? 65535 : MAXLINES;

	now= time(NULL);

	if (fstat(fileno(parser->fp), &sbuf) == 0 /* && sbuf.st_uid == DaemonUid */ ) {
		CronFile *file = xzalloc(sizeof(CronFile));
		CronLine **pline;
		int n;

		file->cf_User = xstrdup(fileName);
		pline = &file->cf_LineBase;

		while (1) {
			CronLine *line;

			if (!--maxLines)
				break;
			n = config_read(parser, tokens, 6, 1, "# \t", PARSE_NORMAL | PARSE_KEEP_COPY);
			if (!n)
				break;

			if (DebugOpt)
				crondlog(LVL5 "user:%s entry:%s", fileName, parser->data);

			/* check if line is setting MAILTO= */
			if (0 == strncmp(tokens[0], "MAILTO=", 7)) {
				continue;
			}
			/* check if a minimum of tokens is specified */
			if (n < 6)
				continue;
			*pline = line = xzalloc(sizeof(*line));
			line->interval= strtoul(tokens[0], &check0, 10);
			line->start_time= strtoul(tokens[1], &check1, 10);
			line->end_time= strtoul(tokens[2], &check2, 10);

			if (line->interval <= 0 ||
				line->interval > MAX_INTERVAL ||
				check0[0] != '\0' ||
				check1[0] != '\0' ||
				check2[0] != '\0')
			{
				crondlog(LVL9 "bad crontab line");
				free(line);
				continue;
			}

			line->nextcycle= (now-line->start_time)/
				line->interval + 1;

			if (strcmp(tokens[3], "NONE") == 0)
			{
				line->distribution= DISTR_NONE;
			}
			else if (strcmp(tokens[3], "UNIFORM") == 0)
			{
				line->distribution= DISTR_UNIFORM;
				line->distr_param=
					strtoul(tokens[4], &check0, 10);
				if (check0[0] != '\0')
				{
					crondlog(LVL9 "bad crontab line");
					free(line);
					continue;
				}
				if (line->distr_param == 0 ||
					LONG_MAX/line->distr_param == 0)
				{
					line->distribution= DISTR_NONE;
				}
			}
			do_distr(line);

			line->lasttime= 0;
			/* copy command */
			line->cl_Shell = xstrdup(tokens[5]);
			if (DebugOpt) {
				crondlog(LVL5 " command:%s", tokens[5]);
			}
			pline = &line->cl_Next;
//bb_error_msg("M[%s]F[%s][%s][%s][%s][%s][%s]", mailTo, tokens[0], tokens[1], tokens[2], tokens[3], tokens[4], tokens[5]);

			CopyFromOld(line);

			kick_watchdog();
		}
		*pline = NULL;

		file->cf_Next = FileBase;
		FileBase = file;

		if (maxLines == 0) {
			crondlog(WARN9 "user %s: too many lines", fileName);
		}
	}
	config_close(parser);

	DeleteFile(oldFile);
}

static void CheckUpdates(void)
{
	FILE *fi;
	char buf[256];

	fi = fopen_for_read(CRONUPDATE);
	if (fi != NULL) {
		unlink(CRONUPDATE);
		while (fgets(buf, sizeof(buf), fi) != NULL) {
			/* use first word only */
			SynchronizeFile(strtok(buf, " \t\r\n"));
		}
		fclose(fi);
	}
}

static void SynchronizeDir(void)
{
	CronFile *file;

	/* Mark all file in the current database for deletion */
	for (file = FileBase; file; file = file->cf_Next) {
		file->cf_ToBeDeleted= 1;
	}

	/*
	 * Remove cron update file
	 *
	 * Re-chdir, in case directory was renamed & deleted, or otherwise
	 * screwed up.
	 *
	 * scan directory and add associated users
	 */
	unlink(CRONUPDATE);
	if (chdir(CDir) < 0) {
		crondlog(DIE9 "can't chdir(%s)", CDir);
	}
	{
		DIR *dir = opendir(".");
		struct dirent *den;

		if (!dir)
			crondlog(DIE9 "can't chdir(%s)", "."); /* exits */
		while ((den = readdir(dir)) != NULL) {
			if (strchr(den->d_name, '.') != NULL) {
				continue;
			}
			if (getpwnam(den->d_name)) {
				SynchronizeFile(den->d_name);
			} else {
				crondlog(LVL7 "ignoring %s", den->d_name);
			}
		}
		closedir(dir);
	}

	/* Clear the cf_Deleted flags on all file and try to delete everything
	 * marked as cf_ToBeDeleted.
	 */
	for (file = FileBase; file; file = file->cf_Next) {
		file->cf_Deleted= 0;
	}

 again:
	for (file = FileBase; file; file = file->cf_Next) {
		if (file->cf_ToBeDeleted && !file->cf_Deleted) {
			DeleteFile(file);
			goto again;
		}
	}

}

/*
 * SetOld() - find a user database that is not marked for deletion set.
 */
static void SetOld(const char *userName)
{
	CronFile *file;

	oldFile= NULL;
	oldLine= NULL;
	for (file = FileBase; file; file = file->cf_Next) {
		if (file->cf_ToBeDeleted)
			continue;
		if (strcmp(file->cf_User, userName) != 0)
			continue;
		file->cf_ToBeDeleted= 1;
		oldFile= file;
		break;
	}
}

/*
 * CopyFromOld - copy nextcycle from old entry
 */
static void CopyFromOld(CronLine *line)
{
	if (!oldFile)
		return;		/* Nothing to do */

	if (oldLine)
	{
		/* Try to match line expected to be next */
		if (oldLine->interval == line->interval &&
			oldLine->start_time == line->start_time &&
			strcmp(oldLine->cl_Shell, line->cl_Shell) == 0)
		{
			crondlog(LVL7 "next line matches");
			; /* okay */
		}
		else
			oldLine= NULL;
	}

	if (!oldLine)
	{
		/* Try to find one */
		for (oldLine= oldFile->cf_LineBase; oldLine;
			oldLine= oldLine->cl_Next)
		{
			if (oldLine->interval == line->interval &&
				oldLine->start_time == line->start_time &&
				strcmp(oldLine->cl_Shell, line->cl_Shell) == 0)
			{
				crondlog(LVL7 "found matching line");
				break;
			}
		}
	}

	if (!oldLine)
	{
		crondlog(LVL7 "found no match for line '%s'", 
			line->cl_Shell);
		return;
	}

	crondlog(LVL7 "found old line for '%s'", oldLine->cl_Shell);
	if (line->nextcycle != oldLine->nextcycle)
	{
		crondlog(LVL9 "nextcycle %d -> %d for '%s'",
			line->nextcycle, oldLine->nextcycle,
			oldLine->cl_Shell);
	}
	line->nextcycle= oldLine->nextcycle;

	if (oldLine->distribution == line->distribution &&
		oldLine->distr_param == line->distr_param)
	{
		line->distr_offset= oldLine->distr_offset;
	}

	oldLine= oldLine->cl_Next;
}

/*
 *  DeleteFile() - delete user database
 *
 *  Note: multiple entries for same user may exist if we were unable to
 *  completely delete a database due to running processes.
 */
static void DeleteFile(CronFile *tfile)
{
	CronFile **pfile = &FileBase;
	CronFile *file;

	while ((file = *pfile) != NULL) {
		if (file == tfile) {
			CronLine **pline = &file->cf_LineBase;
			CronLine *line;

			file->cf_Running = 0;
			file->cf_Deleted = 1;

			while ((line = *pline) != NULL) {
				if (line->cl_Pid > 0) {
					file->cf_Running = 1;
					pline = &line->cl_Next;
				} else {
					*pline = line->cl_Next;
					free(line->cl_Shell);
					free(line);
				}
				kick_watchdog();
			}
			if (file->cf_Running == 0) {
				*pfile = file->cf_Next;
				free(file->cf_User);
				free(file);
			} else {
				pfile = &file->cf_Next;
			}
		} else {
			pfile = &file->cf_Next;
		}
	}
}

/*
 * TestJobs()
 *
 * determine which jobs need to be run.  Under normal conditions, the
 * period is about a minute (one scan).  Worst case it will be one
 * hour (60 scans).
 */
static int TestJobs(time_t *nextp)
{
	int nJobs = 0;
	time_t now;

	now= time(NULL);
	*nextp= now+3600;	/* Enough */

	{
		CronFile *file;
		CronLine *line;
		for (file = FileBase; file; file = file->cf_Next) {
			if (DebugOpt)
				crondlog(LVL5 "file %s:", file->cf_User);
			if (file->cf_Deleted)
				continue;
			for (line = file->cf_LineBase; line; line = line->cl_Next) {
				if (DebugOpt)
					crondlog(LVL5 " line %s", line->cl_Shell);
				if (now >= line->start_time &&
					now < line->start_time +
                                        (line->nextcycle-10)*line->interval)
				{
						crondlog(LVL7
				"time went backward, resetting nextcycle");
						line->lasttime= 0;
						line->nextcycle= 0;
				}
					
				if (line->lasttime != 0)
				{
					if (now > line->lasttime+
						line->interval+
						line->distr_param)
					{
						crondlog(
LVL7 "(TestJobs) job is late. Now %d, lasttime %d, max %d, nextcycle %d, should be %d: %s",
							now, line->lasttime,
							line->lasttime+
							line->interval+
							line->distr_param,
							line->interval,
							line->start_time +
							line->nextcycle*
							line->interval+
							line->distr_offset,
							line->cl_Shell);
					}
				}

				if (now >= line->start_time +
					line->nextcycle*line->interval +
					line->distr_offset &&
					now >= line->start_time &&
					now <= line->end_time
				)
				{
					if (DebugOpt) {
						crondlog(LVL5 " job: %d %s",
							(int)line->cl_Pid, line->cl_Shell);
					}
					if (line->cl_Pid > 0) {
						crondlog(LVL8 "user %s: process already running: %s",
							file->cf_User, line->cl_Shell);
					} else if (line->cl_Pid == 0) {
						line->cl_Pid = -1;
						file->cf_Ready = 1;
						++nJobs;
						*nextp= 0;
						line->nextcycle++;
						if (line->start_time +
							line->nextcycle*
							line->interval <= now)
						{
							line->nextcycle=
							(now-line->start_time)/
							line->interval + 1;
						}
						do_distr(line);
					}
				}
				else if (now >= line->start_time &&
					now <= line->end_time)
				{
					/* Compute next time */
					time_t next;

					next= line->start_time +
						line->nextcycle*line->interval +
						line->distr_offset;
					if (next < *nextp)
						*nextp= next;
				}
			}
		}
	}
	return nJobs;
}

static void RunJobs(void)
{
	CronFile *file;
	CronLine *line;

	for (file = FileBase; file; file = file->cf_Next) {
		if (!file->cf_Ready)
			continue;

		file->cf_Ready = 0;
		for (line = file->cf_LineBase; line; line = line->cl_Next) {
			if (line->cl_Pid >= 0)
				continue;

			kick_watchdog();

			RunJob(file->cf_User, line);
			crondlog(LVL8 "USER %s pid %3d cmd %s",
				file->cf_User, (int)line->cl_Pid, line->cl_Shell);
			if (line->cl_Pid < 0) {
				file->cf_Ready = 1;
			} else if (line->cl_Pid > 0) {
				file->cf_Running = 1;
			}
			// AA make it wait till the job is finished
			while (CheckJobs() > 0)                        
			{
                         	// crondlog(LVL9 "waiting for job %s ", line->cl_Shell);
                                sleep(5);
                        }

		}
	}
}

/*
 * CheckJobs() - check for job completion
 *
 * Check for job completion, return number of jobs still running after
 * all done.
 */
static int CheckJobs(void)
{
	CronFile *file;
	CronLine *line;
	int nStillRunning = 0;

	for (file = FileBase; file; file = file->cf_Next) {
		if (file->cf_Running) {
			file->cf_Running = 0;

			for (line = file->cf_LineBase; line; line = line->cl_Next) {
				int status, r;
				if (line->cl_Pid <= 0)
					continue;

				r = waitpid(line->cl_Pid, &status, WNOHANG);
				if (r < 0 || r == line->cl_Pid) {
					EndJob(file->cf_User, line);
					if (line->cl_Pid) {
						file->cf_Running = 1;
					}
				} else if (r == 0) {
					file->cf_Running = 1;
				}
			}
		}
		nStillRunning += file->cf_Running;
	}
	return nStillRunning;
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

static void find_eos(char *cp, char **ncpp, char quote_char)
{
	while (cp[0] != '\0' && cp[0] != quote_char)
		cp++;
	*ncpp= cp;
}


#define ATLAS_NARGS	40	/* Max arguments to a built-in command */
#define ATLAS_ARGSIZE	4096	/* Max size of the command line */

static int atlas_run(char *cmdline)
{
	char c;
	int i, r, argc, atlas_fd, saved_fd, do_append, flags;
	size_t len;
	char *cp, *ncp;
	struct builtin *bp;
	char *outfile;
	char *validated_fn= NULL;
	FILE *fn;
	char *reason;
	char *argv[ATLAS_NARGS];
	char args[ATLAS_ARGSIZE];

	crondlog(LVL7 "atlas_run: looking for %p '%s'", cmdline, cmdline);

	reason= NULL;
	for (bp= builtin_cmds; bp->cmd != NULL; bp++)
	{
		len= strlen(bp->cmd);
		if (strncmp(cmdline, bp->cmd, len) != 0)
			continue;
		if (cmdline[len] != ' ')
			continue;
		break;
	}
	if (bp->cmd == NULL)
	{
		crondlog(LVL8 "cmd not found '%s'", cmdline);
		r= -1;
		reason="cmd not found";
		goto error;
	}
	
	crondlog(LVL7 "found cmd '%s' for '%s'", bp->cmd, cmdline);

	outfile= NULL;
	do_append= 0;

	len= strlen(cmdline);
	if (len+1 > ATLAS_ARGSIZE)
	{
		crondlog(LVL8 "atlas_run: command line too big: '%s'", cmdline);
		r= -1;
		reason="command line too big";
		goto error;
	}
	strcpy(args, cmdline);

	/* Split the command line */
	cp= args;
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
			}
		}
		else
		{
			argc++;
		}

		if (argc >= ATLAS_NARGS-1)
		{
			crondlog(
			LVL8 "atlas_run: command line '%s', too many arguments",
				cmdline);
			r= -1;
			reason="too many arguments";
			goto error;
		}

		cp= ncp;
		argv[argc]= cp;
		if (cp[0] == '"')
		{
			/* Special code for strings */
			find_eos(cp+1, &ncp, '"');
			if (ncp[0] != '"')
			{
				crondlog(
		LVL8 "atlas_run: command line '%s', end of string not found",
					cmdline);
				r= -1;
				reason="end of string not found";
				goto error;
			}
			argv[argc]= cp+1;
			cp= ncp;
			cp[0]= '\0';
			cp++;
		}
		else if (cp[0] == '\'')
		{
			/* Also try single quotes */
			find_eos(cp+1, &ncp, '\'');
			if (ncp[0] != '\'')
			{
				crondlog(
		LVL8 "atlas_run: command line '%s', end of string not found",
					cmdline);
				r= -1;
				reason="end of string not found";
				goto error;
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

	if (argc >= ATLAS_NARGS)
	{
		crondlog(	
			LVL8 "atlas_run: command line '%s', too many arguments",
			cmdline);
		r= -1;
		reason="too many arguments";
		goto error;
	}
	argv[argc]= NULL;

	for (i= 0; i<argc; i++)
		crondlog(LVL7 "atlas_run: argv[%d] = '%s'", i, argv[i]);

	saved_fd= -1;	/* lint */
	if (outfile)
	{
		/* Redirect I/O */
		crondlog(LVL7 "sending output to '%s'", outfile);
		validated_fn= rebased_validated_filename(outfile,
			SAFE_PREFIX_REL);
		if (!validated_fn)
		{
			crondlog(
			LVL8 "atlas_run: insecure output file '%s'",
				outfile);
			r= -1;
			reason="insecure output file";
			goto error;
		}
		flags= O_CREAT | O_WRONLY;
		if (do_append)
			flags |= O_APPEND;
		atlas_fd= open(validated_fn, flags, 0644);
		if (atlas_fd == -1)
		{
			crondlog(
			LVL8 "atlas_run: unable to create output file '%s'",
				validated_fn);
			r= -1;
			reason="unable to create output file";
			goto error;
		}
		free(validated_fn); validated_fn= NULL;
		fflush(stdout);
		saved_fd= dup(1);
		if (saved_fd == -1)
		{
			crondlog(LVL8 "atlas_run: unable to dub stdout");
			close(atlas_fd);
			r= -1;
			reason="unable to dub stdout";
			goto error;
		}
		dup2(atlas_fd, 1);
		close(atlas_fd);
	}

	r= bp->func(argc, argv);

	alarm(0);

	if (outfile)
	{
		fflush(stdout);
		dup2(saved_fd, 1);
		close(saved_fd);
	}

error:
	if (validated_fn) free(validated_fn);
	if (r != 0 && out_filename)
	{
		fn= fopen(out_filename, "a");
		if (!fn)
			crondlog(DIE9 "unable to append to '%s'", out_filename);
		fprintf(fn, "RESULT { ");
		if (atlas_id)
			fprintf(fn, DBQ(id) ":" DBQ(%s) ", ", atlas_id);
		fprintf(fn, DBQ(fw) ":" DBQ(%d) ", " DBQ(time) ":%d, ",
			get_atlas_fw_version(), time(NULL));
		if (reason != NULL)
			fprintf(fn, DBQ(reason) ":" DBQ(%s) ", ", reason);
		fprintf(fn, DBQ(err) ":%d, " DBQ(cmd) ": \"", r);
		for (cp= cmdline; *cp; cp++)
		{
			c= *cp;
			if (c == '"' || c == '\\')
				fprintf(fn, "\\%c", c);
			else if (isprint_asciionly((unsigned char)c))
				fputc(c, fn);
			else
				fprintf(fn, "\\u%04x", (unsigned char)c);
		}
		fprintf(fn, "\"");
		fprintf(fn, " }\n");
		fclose(fn);
	}

	return 1;
}

static void RunJob(const char *user, CronLine *line)
{
	struct passwd *pas;
	pid_t pid;

	if (line->lasttime != 0)
	{
		time_t now= time(NULL);
		if (now > line->lasttime+line->interval+line->distr_param)
		{
			crondlog(LVL7 "job is late. Now %d, lasttime %d, max %d, should %d: %s",
				now, line->lasttime,
				line->lasttime+line->interval+line->distr_param,
				line->start_time +
				line->nextcycle*line->interval+
				line->distr_offset,
				line->cl_Shell);
		}
	}
	line->lasttime= time(NULL);

	if (atlas_run(line->cl_Shell))
	{
		/* Internal command */
		line->cl_Pid = 0;
		return;
	}

	/* Don't run external commands */
	line->cl_Pid = 0;
#if 0
	/* prepare things before vfork */
	pas = getpwnam(user);
	if (!pas) {
		crondlog(LVL9 "can't get uid for %s", user);
		goto err;
	}
	SetEnv(pas);

	/* fork as the user in question and run program */
	pid = vfork();
	if (pid == 0) {
		/* CHILD */
		/* change running state to the user in question */
		ChangeUser(pas);
		if (DebugOpt) {
			crondlog(LVL5 "child running %s", DEFAULT_SHELL);
		}
		/* crond 3.0pl1-100 puts tasks in separate process groups */
		bb_setpgrp();
		/* Disable execl for securty reasons */
		//execl(DEFAULT_SHELL, DEFAULT_SHELL, "-c", line->cl_Shell, NULL);
		crondlog(ERR20 "can't exec, user %s cmd %s %s %s", user,
				 DEFAULT_SHELL, "-c", line->cl_Shell);
		_exit(EXIT_SUCCESS);
	}
	if (pid < 0) {
		/* FORK FAILED */
		crondlog(ERR20 "can't vfork");
 err:
		pid = 0;
	}
	line->cl_Pid = pid;
#endif
}
