/* vi: set sw=4 ts=4: 
 * eperd formerly crond but now heavily hacked for Atlas
 *
 * crond -d[#] -c <crondir> -f -b
 *
 * run as root, but NOT setuid root
 *
 * Copyright(c) 2013 RIPE NCC <atlas@ripe.net>
 * Copyright 1994 Matthew Dillon (dillon@apollo.west.oic.com)
 * (version 2.3.2)
 * Vladimir Oleynik <dzo@simtreas.ru> (C) 2002
 *
 * Licensed under the GPL v2 or later, see the file LICENSE in this tarball.
 */

#include "libbb.h"
#include <syslog.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/dns.h>

#include "eperd.h"

#define SAFE_PREFIX ATLAS_DATA_NEW

/* glibc frees previous setenv'ed value when we do next setenv()
 * of the same variable. uclibc does not do this! */
#if (defined(__GLIBC__) && !defined(__UCLIBC__)) /* || OTHER_SAFE_LIBC... */
#define SETENV_LEAKS 0
#else
#define SETENV_LEAKS 1
#endif

#define DBQ(str) "\"" #str "\""

#ifndef CRONTABS
#define CRONTABS        "/var/spool/cron/crontabs"
#endif
#ifndef TMPDIR
#define TMPDIR          "/var/spool/cron"
#endif
#ifndef SENDMAIL
#define SENDMAIL        "sendmail"
#endif
#ifndef SENDMAIL_ARGS
#define SENDMAIL_ARGS   "-ti", "oem"
#endif
#ifndef CRONUPDATE
#define CRONUPDATE      "cron.update"
#endif
#ifndef MAXLINES
#define MAXLINES        256	/* max lines in non-root crontabs */
#endif

#define MAX_INTERVAL	(2*366*24*3600)	/* No intervals bigger than 2 years */

#define URANDOM_DEV	"/dev/urandom"
#define ATLAS_FW_VERSION	"/home/atlas/state/FIRMWARE_APPS_VERSION"

struct CronLine {
	struct CronLine *cl_Next;
	char *cl_Shell;         /* shell command                        */
	pid_t cl_Pid;           /* running pid, 0, or armed (-1)        */
#if ENABLE_FEATURE_CROND_CALL_SENDMAIL
	int cl_MailPos;         /* 'empty file' size                    */
	smallint cl_MailFlag;   /* running pid is for mail              */
	char *cl_MailTo;	/* whom to mail results			*/
#endif
	unsigned interval;
	time_t nextcycle;
	time_t start_time;
	time_t end_time;
	enum distribution { DISTR_NONE, DISTR_UNIFORM } distribution;
	int distr_param;	/* Parameter for distribution, if any */
	struct timeval distr_offset;	/* Current offset to randomize the
					 * interval
					 */
	struct event event;
	struct testops *testops;
	void *teststate;

	/* For cleanup */
	char needs_delete;

	/* For debugging */
	time_t lasttime;
	time_t nexttime;
	time_t waittime;
	time_t debug_cycle;
	time_t debug_generated;
};


#define DaemonUid 0


enum {
	OPT_i = (1 << 0),
	OPT_l = (1 << 1),
	OPT_L = (1 << 2),
	OPT_f = (1 << 3),
	OPT_c = (1 << 4),
	OPT_A = (1 << 5),
	OPT_D = (1 << 6),
	OPT_P = (1 << 7),
	OPT_d = (1 << 8) * ENABLE_FEATURE_CROND_D,
};
#if ENABLE_FEATURE_CROND_D
#define DebugOpt (option_mask32 & OPT_d)
#else
#define DebugOpt 0
#endif


struct globals G;
#define INIT_G() do { \
	LogLevel = 8; \
	CDir = CRONTABS; \
} while (0)

static int do_kick_watchdog;
static char *out_filename= NULL;
static char *atlas_id= NULL;

static void CheckUpdates(evutil_socket_t fd, short what, void *arg);
static void CheckUpdatesHour(evutil_socket_t fd, short what, void *arg);
static void SynchronizeDir(void);
#if ENABLE_FEATURE_CROND_CALL_SENDMAIL
static void EndJob(const char *user, CronLine *line);
#else
#define EndJob(user, line)  ((line)->cl_Pid = 0)
#endif
static void DeleteFile(void);
static int Insert(CronLine *line);
static void Start(CronLine *line);
static void atlas_init(CronLine *line);
static void RunJob(evutil_socket_t fd, short what, void *arg);

void crondlog(const char *ctl, ...)
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

int get_atlas_fw_version(void)
{
	static int fw_version= -1;

	int r, fw;
	FILE *file;

	if (fw_version != -1)
		return fw_version;

	file= fopen(ATLAS_FW_VERSION, "r");
	if (file == NULL)
	{
		crondlog(LVL9 "get_atlas_fw_version: unable to open '%s': %s",
			ATLAS_FW_VERSION, strerror(errno));
		return -1;
	}
	r= fscanf(file, "%d", &fw);
	fclose(file);
	if (r == -1)
	{
		crondlog(LVL9 "get_atlas_fw_version: unable to read from '%s'",
			ATLAS_FW_VERSION);
		return -1;
	}

	fw_version= fw;
	return fw;
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
		if (fdwatchdog != -1)
		{
			write(fdwatchdog, "1", 1);
			close(fdwatchdog);
		}
	}
}

#if 0
static void FAST_FUNC Xbb_daemonize_or_rexec(int flags, char **argv)
{
	int fd;

	if (flags & DAEMON_CHDIR_ROOT)
		xchdir("/");

	if (flags & DAEMON_DEVNULL_STDIO) {
		close(0);
		close(1);
		close(2);
	}

	fd = open(bb_dev_null, O_RDWR);
	if (fd < 0) {
		/* NB: we can be called as bb_sanitize_stdio() from init
		 * or mdev, and there /dev/null may legitimately not (yet) exist!
		 * Do not use xopen above, but obtain _ANY_ open descriptor,
		 * even bogus one as below. */
		fd = xopen("/", O_RDONLY); /* don't believe this can fail */
	}

	while ((unsigned)fd < 2)
		fd = dup(fd); /* have 0,1,2 open at least to /dev/null */

	if (!(flags & DAEMON_ONLY_SANITIZE)) {
		//forkexit_or_rexec(argv);
		/* if daemonizing, make sure we detach from stdio & ctty */
		setsid();
		dup2(fd, 0);
		dup2(fd, 1);
		dup2(fd, 2);
	}
	while (fd > 2) {
		close(fd--);
		if (!(flags & DAEMON_CLOSE_EXTRA_FDS))
			return;
		/* else close everything after fd#2 */
	}
}
#endif

int eperd_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int eperd_main(int argc UNUSED_PARAM, char **argv)
{
	unsigned opt;
	int r, fd;
	unsigned seed;
	struct event *updateEventMin, *updateEventHour;
	struct timeval tv;
	struct rlimit limit;

	const char *PidFileName = NULL;

	atexit(my_exit);

	INIT_G();

	/* "-b after -f is ignored", and so on for every pair a-b */
	opt_complementary = "f-b:b-f:S-L:L-S" USE_FEATURE_PERD_D(":d-l")
			"i:+:l+:d+"; /* -i, -l and -d have numeric param */
	opt = getopt32(argv, "i:l:L:fc:A:DP:" USE_FEATURE_PERD_D("d:") "O:",
			&instance_id, &LogLevel, &LogFile, &CDir,
			&atlas_id, &PidFileName
			USE_FEATURE_PERD_D(,&LogLevel), &out_filename);
	/* both -d N and -l N set the same variable: LogLevel */

	if (out_filename && !validate_filename(out_filename, SAFE_PREFIX))
	{
		crondlog(DIE9 "insecure file '%s'. allowed path '%s'", 
				out_filename, SAFE_PREFIX);
	}

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

	signal(SIGQUIT, SIG_DFL);
	limit.rlim_cur= RLIM_INFINITY;
	limit.rlim_max= RLIM_INFINITY;
	setrlimit(RLIMIT_CORE, &limit);

	/* Create libevent event base */
	EventBase= event_base_new();
	if (!EventBase)
	{
		crondlog(DIE9 "event_base_new failed"); /* exits */
	}
	DnsBase= evdns_base_new(EventBase, 1 /*initialize*/);
	if (!DnsBase)
	{
		crondlog(DIE9 "evdns_base_new failed"); /* exits */
	}

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

	updateEventMin= event_new(EventBase, -1, EV_TIMEOUT|EV_PERSIST,
		CheckUpdates, NULL);
	if (!updateEventMin)
		crondlog(DIE9 "event_new failed"); /* exits */
	tv.tv_sec= 60;
	tv.tv_usec= 0;
	event_add(updateEventMin, &tv);

	updateEventHour= event_new(EventBase, -1, EV_TIMEOUT|EV_PERSIST,
		CheckUpdatesHour, NULL);
	if (!updateEventHour)
		crondlog(DIE9 "event_new failed"); /* exits */
	tv.tv_sec= 3600;
	tv.tv_usec= 0;
	event_add(updateEventHour, &tv);
		
	if(PidFileName)
	{
		write_pidfile(PidFileName);
	}
	else 
	{
		write_pidfile("/var/run/crond.pid");
	}
#if 0
	/* main loop - synchronize to 1 second after the minute, minimum sleep
	 * of 1 second. */
	{
		time_t t1 = time(NULL);
		time_t next;
		time_t last_minutely= 0;
		time_t last_hourly= 0;
		int sleep_time = 10; /* AA previously 60 */
		for (;;) {
			kick_watchdog();
			sleep(sleep_time);

			kick_watchdog();

			if (t1 >= last_minutely + 60)
			{
				last_minutely= t1;
				CheckUpdates();
			}
			if (t1 >= last_hourly + 3600)
			{
				last_hourly= t1;
				SynchronizeDir();
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
#endif
	r= event_base_loop(EventBase, 0);
	if (r != 0)
		crondlog(LVL9 "event_base_loop failed");
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

static void do_distr(CronLine *line)
{
	long n, r, modulus, max;

	line->distr_offset.tv_sec= 0;		/* Safe default */
	line->distr_offset.tv_usec= 0;
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
		line->distr_offset.tv_sec= r - line->distr_param/2;
		line->distr_offset.tv_usec= random() % 1000000;
	}
	crondlog(LVL7 "do_distr: using %f", line->distr_offset.tv_sec + 
		line->distr_offset.tv_usec/1e6);
}

static void SynchronizeFile(const char *fileName)
{
	struct parser_t *parser;
	struct stat sbuf;
	int r, maxLines;
	char *tokens[6];
#if ENABLE_FEATURE_CROND_CALL_SENDMAIL
	char *mailTo = NULL;
#endif
	char *check0, *check1, *check2;
	CronLine *line;

	if (!fileName)
		return;

	for (line= LineBase; line; line= line->cl_Next)
		line->needs_delete= 1;

	parser = config_open(fileName);
	if (!parser)
	{
		/* We have to get rid of the old entries if the file is not
		 * there. Assume a non-existant file is the only reason for
		 * failure.
		 */
		DeleteFile();
		return;
	}

	maxLines = (strcmp(fileName, "root") == 0) ? 65535 : MAXLINES;

	if (fstat(fileno(parser->fp), &sbuf) == 0 /* && sbuf.st_uid == DaemonUid */) {
		int n;

		while (1) {
			if (!--maxLines)
				break;
			n = config_read(parser, tokens, 6, 1, "# \t", PARSE_NORMAL | PARSE_KEEP_COPY);
			if (!n)
				break;

			if (DebugOpt)
				crondlog(LVL5 "user:%s entry:%s", fileName, parser->data);

			/* check if line is setting MAILTO= */
			if (0 == strncmp(tokens[0], "MAILTO=", 7)) {
#if ENABLE_FEATURE_CROND_CALL_SENDMAIL
				free(mailTo);
				mailTo = (tokens[0][7]) ? xstrdup(&tokens[0][7]) : NULL;
#endif /* otherwise just ignore such lines */
				continue;
			}
			/* check if a minimum of tokens is specified */
			if (n < 6)
				continue;
			line = xzalloc(sizeof(*line));
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

			line->lasttime= 0;
#if ENABLE_FEATURE_CROND_CALL_SENDMAIL
			/* copy mailto (can be NULL) */
			line->cl_MailTo = xstrdup(mailTo);
#endif
			/* copy command */
			line->cl_Shell = xstrdup(tokens[5]);
			if (DebugOpt) {
				crondlog(LVL5 " command:%s", tokens[5]);
			}
//bb_error_msg("M[%s]F[%s][%s][%s][%s][%s][%s]", mailTo, tokens[0], tokens[1], tokens[2], tokens[3], tokens[4], tokens[5]);

			evtimer_assign(&line->event, EventBase, RunJob, line);

			r= Insert(line);
			if (!r)
			{
				/* Existing line. Delete new one */
#if ENABLE_FEATURE_CROND_CALL_SENDMAIL
				free(line->cl_MailTo);
#endif
				free(line->cl_Shell);
				free(line);
				continue;
			}

			/* New line, should schedule start event */
			Start(line);

			kick_watchdog();
		}

		if (maxLines == 0) {
			crondlog(WARN9 "user %s: too many lines", fileName);
		}
	}
	config_close(parser);

	DeleteFile();
}

#define RESOLV_CONF	"/etc/resolv.conf"
static void check_resolv_conf(void)
{
	static time_t last_time= -1;

	int r;
	FILE *fn;
	struct stat sb;

	r= stat(RESOLV_CONF, &sb);
	if (r == -1)
	{
		crondlog(LVL8 "error accessing resolv.conf: %s",
			strerror(errno));
		return;
	}

	if (sb.st_mtime == last_time)
		return;	/* resolv.conf did not change */
	evdns_base_clear_nameservers_and_suspend(DnsBase);
	r= evdns_base_resolv_conf_parse(DnsBase, DNS_OPTIONS_ALL,
		RESOLV_CONF);
	evdns_base_resume(DnsBase);

	if ((r != 0 || last_time != -1) && out_filename)
	{
		fn= fopen(out_filename, "a");
		if (!fn)
			crondlog(DIE9 "unable to append to '%s'", out_filename);
		fprintf(fn, "RESULT { ");
		if (atlas_id)
			fprintf(fn, DBQ(id) ":" DBQ(%s) ", ", atlas_id);
		fprintf(fn, DBQ(fw) ":" DBQ(%d) ", " DBQ(time) ":%ld, ",
			get_atlas_fw_version(), (long)time(NULL));
		fprintf(fn, DBQ(event) ": " DBQ(load resolv.conf)
			", " DBQ(result) ": %d", r);

		fprintf(fn, " }\n");
		fclose(fn);
	}

	last_time= sb.st_mtime;
}

static void CheckUpdates(evutil_socket_t __attribute__ ((unused)) fd,
	short __attribute__ ((unused)) what,
	void __attribute__ ((unused)) *arg)
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

	check_resolv_conf();
}

static void CheckUpdatesHour(evutil_socket_t __attribute__ ((unused)) fd,
	short __attribute__ ((unused)) what,
	void __attribute__ ((unused)) *arg)
{
	SynchronizeDir();
}

static void SynchronizeDir(void)
{
	/*
	 * Remove cron update file
	 *
	 * Re-chdir, in case directory was renamed & deleted, or otherwise
	 * screwed up.
	 *
	 * Only load th crontab for 'root'
	 */
	unlink(CRONUPDATE);
	if (chdir(CDir) < 0) {
		crondlog(DIE9 "can't chdir(%s)", CDir);
	}

	SynchronizeFile("root");
	DeleteFile();
}

static void set_timeout(CronLine *line, int init_next_cycle)
{
	struct timeval now, tv;

	gettimeofday(&now, NULL);
	if (now.tv_sec > line->end_time)
		return;			/* This job has expired */

	if (init_next_cycle)
	{
		if (now.tv_sec < line->start_time)
			line->nextcycle= 0;
		else
		{
			line->nextcycle= (now.tv_sec-line->start_time)/
				line->interval + 1;
		}
		do_distr(line);
	}

	tv.tv_sec= line->nextcycle*line->interval + line->start_time +
		line->distr_offset.tv_sec - now.tv_sec;
	tv.tv_usec= line->distr_offset.tv_usec - now.tv_usec;
	if (tv.tv_usec < 0)
	{
		tv.tv_usec += 1e6;
		tv.tv_sec--;
	}
	if (tv.tv_sec < 0)
		tv.tv_sec= tv.tv_usec= 0;
	crondlog(LVL7 "set_timeout: nextcycle %d, interval %d, start_time %d, distr_offset %f, now %d, tv_sec %d",
		line->nextcycle, line->interval,
		line->start_time,
		line->distr_offset.tv_sec + line->distr_offset.tv_usec/1e6,
		now.tv_sec, tv.tv_sec);
	line->debug_cycle= line->nextcycle;
	line->debug_generated= now.tv_sec;
	line->nexttime= line->nextcycle*line->interval + line->start_time +
                line->distr_offset.tv_sec;
	line->waittime= tv.tv_sec;
	event_add(&line->event, &tv);
}

/*
 * Insert - insert if not already there
 */
static int Insert(CronLine *line)
{
	CronLine *last;

	if (oldLine)
	{
		/* Try to match line expected to be next */
		if (oldLine->interval == line->interval &&
			oldLine->start_time == line->start_time &&
			strcmp(oldLine->cl_Shell, line->cl_Shell) == 0)
		{
			crondlog(LVL9 "next line matches");
			; /* okay */
		}
		else
			oldLine= NULL;
	}

	if (!oldLine)
	{
		/* Try to find one */
		for (last= NULL, oldLine= LineBase; oldLine;
			last= oldLine, oldLine= oldLine->cl_Next)
		{
			if (oldLine->interval == line->interval &&
				oldLine->start_time == line->start_time &&
				strcmp(oldLine->cl_Shell, line->cl_Shell) == 0)
			{
				break;
			}
		}
	}

	if (oldLine)
	{
		crondlog(LVL7 "Insert: found match for line '%s'",
			line->cl_Shell);
		crondlog(LVL7 "Insert: setting end time to %d", line->end_time);
		oldLine->end_time= line->end_time;
		oldLine->needs_delete= 0;

		/* Reschedule event */
		set_timeout(oldLine, 0 /*!init_netcycle*/);

		return 0;
	}

	crondlog(LVL7 "found no match for line '%s'", line->cl_Shell);
	line->cl_Next= NULL;
	if (last)
		last->cl_Next= line;
	else
		LineBase= line;
	return 1;
}

static void Start(CronLine *line)
{
	line->testops= NULL;

	/* Parse command line and init test */
	atlas_init(line);
	if (!line->testops)
		return;			/* Test failed to initialize */

	set_timeout(line, 1 /*init_nextcycle*/);
}

/*
 *  DeleteFile() - delete user database
 *
 *  Note: multiple entries for same user may exist if we were unable to
 *  completely delete a database due to running processes.
 */
static void DeleteFile(void)
{
	int r;
	CronLine **pline = &LineBase;
	CronLine *line;

	oldLine= NULL;

	while ((line = *pline) != NULL) {
		if (!line->needs_delete)
		{
			pline= &line->cl_Next;
			continue;
		}
		kick_watchdog();
		if (!line->teststate)
		{
			crondlog(LVL8 "DeleteFile: no state to delete for '%s'",
				line->cl_Shell);
		}
		if (line->testops && line->teststate)
		{
			r= line->testops->delete(line->teststate);
			if (r != 1)
			{
				crondlog(LVL9 "DeleteFile: line is busy");
				pline= &line->cl_Next;
				continue;
			}
			line->testops= NULL;
			line->teststate= NULL;
		}
		event_del(&line->event);
		free(line->cl_Shell);
		line->cl_Shell= NULL;

		*pline= line->cl_Next;
		free(line);
	}
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

static struct builtin 
{
	const char *cmd;
	struct testops *testops;
} builtin_cmds[]=
{
	{ "evhttpget", &httpget_ops },
	{ "evntp", &ntp_ops },
	{ "evping", &ping_ops },
	{ "evsslgetcert", &sslgetcert_ops },
	{ "evtdig", &tdig_ops },
	{ "evtraceroute", &traceroute_ops },
	{ "condmv", &condmv_ops },
	{ NULL, NULL }
};


#define ATLAS_NARGS	64	/* Max arguments to a built-in command */
#define ATLAS_ARGSIZE	512	/* Max size of the command line */

static void atlas_init(CronLine *line)
{
	char c;
	int i, argc;
	size_t len;
	char *cp, *ncp;
	struct builtin *bp;
	char *cmdline, *p;
	const char *reason;
	void *state;
	FILE *fn;
	char *argv[ATLAS_NARGS];
	char args[ATLAS_ARGSIZE];

	cmdline= line->cl_Shell;
	crondlog(LVL7 "atlas_run: looking for %p '%s'", cmdline, cmdline);

	state= NULL;
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
		reason="command not found";
		goto error;
	}
	
	crondlog(LVL7 "found cmd '%s' for '%s'", bp->cmd, cmdline);

	len= strlen(cmdline);
	if (len+1 > ATLAS_ARGSIZE)
	{
		crondlog(LVL8 "atlas_run: command line too big: '%s'", cmdline);
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
		argc++;

		if (argc >= ATLAS_NARGS-1)
		{
			crondlog(
			LVL8 "atlas_run: command line '%s', too many arguments",
				cmdline);
			reason="too many arguments";
			goto error;
		}

		cp= ncp;
		argv[argc]= cp;
		if (cp[0] == '"')
		{
			/* Special code for strings */
			find_eos(cp+1, &ncp);
			if (ncp[0] != '"')
			{
				crondlog(
		LVL8 "atlas_run: command line '%s', end of string not found",
					cmdline);
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
		reason="too many arguments";
		goto error;
	}
	argv[argc]= NULL;

	for (i= 0; i<argc; i++)
		crondlog(LVL7 "atlas_run: argv[%d] = '%s'", i, argv[i]);

	state= bp->testops->init(argc, argv, 0);
	crondlog(LVL7 "init returned %p for '%s'", state, line->cl_Shell);
	line->teststate= state;
	line->testops= bp->testops;

error:
	if (state == NULL && out_filename)
	{
		fn= fopen(out_filename, "a");
		if (!fn)
			crondlog(DIE9 "unable to append to '%s'", out_filename);
		fprintf(fn, "RESULT { ");
		if (atlas_id)
			fprintf(fn, DBQ(id) ":" DBQ(%s) ", ", atlas_id);
		fprintf(fn, DBQ(fw) ":" DBQ(%d) ", " DBQ(time) ":%ld, ",
			get_atlas_fw_version(), (long)time(NULL));
		if (reason)
			fprintf(fn, DBQ(reason) ":" DBQ(%s) ", ", reason);
		fprintf(fn, DBQ(cmd) ": \"");
		for (p= line->cl_Shell; *p; p++)
		{
			c= *p;
			if (c == '"' || c == '\\')
				fprintf(fn, "\\%c", c);
			else if (isprint((unsigned char)c))
				fputc(c, fn);
			else
				fprintf(fn, "\\u%04x", (unsigned char)c);
		}
		fprintf(fn, "\"");
		fprintf(fn, " }\n");
		fclose(fn);
	}
}

#if ENABLE_FEATURE_CROND_CALL_SENDMAIL

// TODO: sendmail should be _run-time_ option, not compile-time!

static void
ForkJob(const char *user, CronLine *line, int mailFd,
		const char *prog, const char *cmd, const char *arg,
		const char *mail_filename)
{
	struct passwd *pas;
	pid_t pid;

	/* prepare things before vfork */
	pas = getpwnam(user);
	if (!pas) {
		crondlog(LVL9 "can't get uid for %s", user);
		goto err;
	}
	SetEnv(pas);

	pid = vfork();
	if (pid == 0) {
		/* CHILD */
		/* change running state to the user in question */
		ChangeUser(pas);
		if (DebugOpt) {
			crondlog(LVL5 "child running %s", prog);
		}
		if (mailFd >= 0) {
			xmove_fd(mailFd, mail_filename ? 1 : 0);
			dup2(1, 2);
		}
		/* crond 3.0pl1-100 puts tasks in separate process groups */
		bb_setpgrp();
		execlp(prog, prog, cmd, arg, NULL);
		crondlog(ERR20 "can't exec, user %s cmd %s %s %s", user, prog, cmd, arg);
		if (mail_filename) {
			fdprintf(1, "Exec failed: %s -c %s\n", prog, arg);
		}
		_exit(EXIT_SUCCESS);
	}

	line->cl_Pid = pid;
	if (pid < 0) {
		/* FORK FAILED */
		crondlog(ERR20 "can't vfork");
 err:
		line->cl_Pid = 0;
		if (mail_filename) {
			unlink(mail_filename);
		}
	} else if (mail_filename) {
		/* PARENT, FORK SUCCESS
		 * rename mail-file based on pid of process
		 */
		char mailFile2[128];

		snprintf(mailFile2, sizeof(mailFile2), "%s/cron.%s.%d", TMPDIR, user, pid);
		rename(mail_filename, mailFile2); // TODO: xrename?
	}

	/*
	 * Close the mail file descriptor.. we can't just leave it open in
	 * a structure, closing it later, because we might run out of descriptors
	 */
	if (mailFd >= 0) {
		close(mailFd);
	}
}

static void RunJob(const char *user, CronLine *line)
{
	char mailFile[128];
	int mailFd = -1;

	line->cl_Pid = 0;
	line->cl_MailFlag = 0;

	if (line->cl_MailTo) {
		/* open mail file - owner root so nobody can screw with it. */
		snprintf(mailFile, sizeof(mailFile), "%s/cron.%s.%d", TMPDIR, user, getpid());
		mailFd = open(mailFile, O_CREAT | O_TRUNC | O_WRONLY | O_EXCL | O_APPEND, 0600);

		if (mailFd >= 0) {
			line->cl_MailFlag = 1;
			fdprintf(mailFd, "To: %s\nSubject: cron: %s\n\n", line->cl_MailTo,
				line->cl_Shell);
			line->cl_MailPos = lseek(mailFd, 0, SEEK_CUR);
		} else {
			crondlog(ERR20 "cannot create mail file %s for user %s, "
					"discarding output", mailFile, user);
		}
	}


	if (atlas_outfile && atlas_run(line->cl_Shell))
	{
		/* Internal command */
		return;
	}

	ForkJob(user, line, mailFd, DEFAULT_SHELL, "-c", line->cl_Shell, mailFile);
}

/*
 * EndJob - called when job terminates and when mail terminates
 */
static void EndJob(const char *user, CronLine *line)
{
	int mailFd;
	char mailFile[128];
	struct stat sbuf;

	/* No job */
	if (line->cl_Pid <= 0) {
		line->cl_Pid = 0;
		return;
	}

	/*
	 * End of job and no mail file
	 * End of sendmail job
	 */
	snprintf(mailFile, sizeof(mailFile), "%s/cron.%s.%d", TMPDIR, user, line->cl_Pid);
	line->cl_Pid = 0;

	if (line->cl_MailFlag == 0) {
		return;
	}
	line->cl_MailFlag = 0;

	/*
	 * End of primary job - check for mail file.  If size has increased and
	 * the file is still valid, we sendmail it.
	 */
	mailFd = open(mailFile, O_RDONLY);
	unlink(mailFile);
	if (mailFd < 0) {
		return;
	}

	if (fstat(mailFd, &sbuf) < 0 || sbuf.st_uid != DaemonUid
	 || sbuf.st_nlink != 0 || sbuf.st_size == line->cl_MailPos
	 || !S_ISREG(sbuf.st_mode)
	) {
		close(mailFd);
		return;
	}
	if (line->cl_MailTo)
		ForkJob(user, line, mailFd, SENDMAIL, SENDMAIL_ARGS, NULL);
}

#else /* crond without sendmail */

static void RunJob(evutil_socket_t __attribute__ ((unused)) fd,
	short __attribute__ ((unused)) what, void *arg)
{
	char c;
	char *p;
	CronLine *line;
	struct timeval now;
	FILE *fn;

	line= arg;

	crondlog(LVL7 "RunJob for %p, '%s'\n", arg, line->cl_Shell);

	if (line->needs_delete)
	{
		crondlog(LVL7 "RunJob: needs delete\n");
		return;			/* Line is to be deleted */
	}

	gettimeofday(&now, NULL);

	crondlog(LVL7 "RubJob, now %d, end_time %d\n", now.tv_sec,
		line->end_time);
	if (now.tv_sec < line->nexttime-10 || now.tv_sec > line->nexttime+10)
	{
		if (out_filename)
		{
			fn= fopen(out_filename, "a");
			if (!fn)
			{
				crondlog(DIE9 "unable to append to '%s'",
					out_filename);
			}
			fprintf(fn, "RESULT { ");
			if (atlas_id)
				fprintf(fn, DBQ(id) ":" DBQ(%s) ", ", atlas_id);
			fprintf(fn, DBQ(fw) ":" DBQ(%d) ", " DBQ(time) ":%ld, ",
				get_atlas_fw_version(), (long)time(NULL));
			fprintf(fn, DBQ(reason) ": "
		DBQ(inconsistent time; now %d; nexttime %d; waittime %d; cycle %d; generated %d) ", ",
				(int)now.tv_sec, (int)line->nexttime,
				(int)line->waittime, (int)line->debug_cycle,
				(int)line->debug_generated);

			fprintf(fn, DBQ(cmd) ": \"");
			for (p= line->cl_Shell; *p; p++)
			{
				c= *p;
				if (c == '"' || c == '\\')
					fprintf(fn, "\\%c", c);
				else if (isprint((unsigned char)c))
					fputc(c, fn);
				else
					fprintf(fn, "\\u%04x", (unsigned char)c);
			}
			fprintf(fn, "\"");
			fprintf(fn, " }\n");
			fclose(fn);
		}
		crondlog(
		LVL7 "RunJob: weird, now %d, nexttime %d, waittime %d\n",
			now.tv_sec, line->nexttime, line->waittime);

		/* Recompute nextcycle */
		set_timeout(line, 1 /*init_next_cycle*/);
		return;
	}
	
	if (now.tv_sec > line->end_time)
	{
		crondlog(LVL7 "RunJob: expired\n");
		return;			/* This job has expired */
	}

	if (!line->teststate)
	{
		crondlog(LVL8 "not starting cmd '%s' (not init)\n",
			line->cl_Shell);
		return;
	}

	line->testops->start(line->teststate);

	line->nextcycle++;
	if (line->start_time + line->nextcycle*line->interval < now.tv_sec)
	{
		crondlog(LVL7 "recomputing nextcycle");
		line->nextcycle= (now.tv_sec-line->start_time)/line->interval
			+ 1;
	}

	do_distr(line);

	set_timeout(line, 0 /*!init_nextcycle*/);
}

#endif /* ENABLE_FEATURE_CROND_CALL_SENDMAIL */
