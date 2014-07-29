/*
 * Copyright (c) 2013 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * eooqd.c  Libevent-based One-off queue daemon
 */

#include <stdio.h>
#include <string.h>

#include <libbb.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/dns.h>

#include "eperd.h"

#define SUFFIX 		".curr"
#define OOQD_NEW_PREFIX	"/home/atlas/data/new/ooq"
#define OOQD_OUT	"/home/atlas/data/ooq.out/ooq"
#define ATLAS_SESSION_FILE	"/home/atlas/status/con_session_id.txt"

#define ATLAS_NARGS	64	/* Max arguments to a built-in command */
#define ATLAS_ARGSIZE	512	/* Max size of the command line */

#define SAFE_PREFIX ATLAS_DATA_NEW

#define DBQ(str) "\"" #str "\""

struct slot
{
	void *cmdstate;
	struct builtin *bp;
};

static struct 
{
	char *queue_file;
	const char *atlas_id;
	char curr_qfile[256];
	FILE *curr_file;
	int max_busy;
	int curr_busy;
	int curr_index;
	struct slot *slots;
} *state;

static struct builtin 
{
	const char *cmd;
	struct testops *testops;
} builtin_cmds[]=
{
	{ "evhttpget", &httpget_ops },
	{ "evntp", &ntp_ops },
	{ "evping", &ping_ops },
	{ "evtdig", &tdig_ops },
	{ "evsslgetcert", &sslgetcert_ops },
	{ "evtraceroute", &traceroute_ops },
	{ NULL, NULL }
};

static const char *atlas_id;
static const char *out_filename;

static void report(const char *fmt, ...);
static void report_err(const char *fmt, ...);

static void checkQueue(evutil_socket_t fd, short what, void *arg);
static void add_line(void);
static void cmddone(void *cmdstate);
static void re_post(evutil_socket_t fd, short what, void *arg);
static void post_results(void);
static void skip_space(char *cp, char **ncpp);
static void skip_nonspace(char *cp, char **ncpp);
static void find_eos(char *cp, char **ncpp);
static void check_resolv_conf2(const char *out_file, const char *atlasid);
static const char *get_session_id(void);

extern int httppost_main(int argc, char *argv[]); /* in networking/httppost.c */

int eooqd_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int eooqd_main(int argc, char *argv[])
{
	int r;
	char *pid_file_name;
	struct event *checkQueueEvent, *rePostEvent;
	struct timeval tv;
	struct rlimit limit;

	atlas_id= NULL;
	pid_file_name= NULL;

	(void)getopt32(argv, "A:P:O:", &atlas_id, &pid_file_name,
		&out_filename);

	if (argc != optind+1)
	{
		bb_show_usage();
		return 1;
	}

	if(pid_file_name)
	{
		write_pidfile(pid_file_name);
	}

	state = xzalloc(sizeof(*state));

	state->atlas_id= atlas_id;
	state->queue_file= argv[optind];

	state->max_busy= 10;

	state->slots= xzalloc(sizeof(*state->slots) * state->max_busy);

	if (strlen(state->queue_file) + strlen(SUFFIX) + 1 >
		sizeof(state->curr_qfile))
	{
		report("filename too long ('%s')", state->queue_file);
		return 1;
	}

	strlcpy(state->curr_qfile, state->queue_file,
		sizeof(state->curr_qfile));
	strlcat(state->curr_qfile, SUFFIX, sizeof(state->curr_qfile));

	signal(SIGQUIT, SIG_DFL);
	chdir("/home/atlas/data");
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
		event_base_free(EventBase);
		crondlog(DIE9 "evdns_base_new failed"); /* exits */
	}

	checkQueueEvent= event_new(EventBase, -1, EV_TIMEOUT|EV_PERSIST,
		checkQueue, NULL);
	if (!checkQueueEvent)
		crondlog(DIE9 "event_new failed"); /* exits */
	tv.tv_sec= 1;
	tv.tv_usec= 0;
	event_add(checkQueueEvent, &tv);

	rePostEvent= event_new(EventBase, -1, EV_TIMEOUT|EV_PERSIST,
		re_post, NULL);
	if (!rePostEvent)
		crondlog(DIE9 "event_new failed"); /* exits */
	tv.tv_sec= 60;
	tv.tv_usec= 0;
	event_add(rePostEvent, &tv);

	r= event_base_loop(EventBase, 0);
	if (r != 0)
		crondlog(LVL9 "event_base_loop failed");
	return 0;
}

static void checkQueue(evutil_socket_t fd UNUSED_PARAM,
	short what UNUSED_PARAM, void *arg UNUSED_PARAM)
{
	if (!state->curr_file)
	{
		/* Try to move queue_file to curr_qfile. This provide at most
		 * once behavior and allows producers to create a new
		 * queue_file while we process the old one.
		 */
		if (rename(state->queue_file, state->curr_qfile) == -1)
		{
			if (errno == ENOENT)
			{
				return;
			}
			report_err("rename failed");
			return;
		}

		state->curr_file= fopen(state->curr_qfile, "r");
		if (state->curr_file == NULL)
		{
			report_err("open '%s' failed", state->curr_qfile);
			return;
		}
	}

	while (state->curr_file && state->curr_busy < state->max_busy)
	{
		add_line();
	}

	check_resolv_conf2(out_filename, atlas_id);
}

static void add_line(void)
{
	char c;
	int i, argc, skip, slot;
	size_t len;
	char *cp, *ncp;
	struct builtin *bp;
	char *p;
	const char *reason;
	void *cmdstate;
	FILE *fn;
	const char *argv[ATLAS_NARGS];
	char args[ATLAS_ARGSIZE];
	char cmdline[256];
	char filename[80];
	struct stat sb;

	if (fgets(cmdline, sizeof(cmdline), state->curr_file) == NULL)
	{
		if (ferror(state->curr_file))
			report_err("error reading queue file");
		fclose(state->curr_file);
		state->curr_file= NULL;
		return;
	}

	cp= strchr(cmdline, '\n');
	if (cp)
		*cp= '\0';

	crondlog(LVL7 "atlas_run: looking for '%s'", cmdline);

	cmdstate= NULL;
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

	if (argc >= ATLAS_NARGS-2)
	{
		crondlog(	
			LVL8 "atlas_run: command line '%s', too many arguments",
			cmdline);
		reason="too many arguments";
		goto error;
	}

	/* find a slot for this command */
	for (skip= 1; skip <= state->max_busy; skip++)
	{
		slot= (state->curr_index+skip) % state->max_busy;
		if (state->slots[slot].cmdstate == NULL)
			break;
	}
	if (state->slots[slot].cmdstate != NULL)
		crondlog(DIE9 "no empty slot?");
	argv[argc++]= "-O";
	snprintf(filename, sizeof(filename), OOQD_NEW_PREFIX ".%d", slot);
	argv[argc++]= filename;

	argv[argc]= NULL;

	for (i= 0; i<argc; i++)
		crondlog(LVL7 "atlas_run: argv[%d] = '%s'", i, argv[i]);

	cmdstate= bp->testops->init(argc, (char **)argv, cmddone);
	crondlog(LVL7 "init returned %p for '%s'", cmdstate, cmdline);

	if (cmdstate != NULL)
	{
		state->slots[slot].cmdstate= cmdstate;
		state->slots[slot].bp= bp;
		state->curr_index= slot;
		state->curr_busy++;

		bp->testops->start(cmdstate);
	}

error:
	if (cmdstate == NULL)
	{
		fn= fopen(OOQD_NEW_PREFIX, "a");
		if (!fn) 
		{
			crondlog(DIE9 "unable to append to '%s'",
				OOQD_NEW_PREFIX);
		}
		fprintf(fn, "RESULT { ");
		if (state->atlas_id)
			fprintf(fn, DBQ(id) ":" DBQ(%s) ", ", state->atlas_id);
		fprintf(fn, DBQ(fw) ":" DBQ(%d) ", " DBQ(time) ":%ld, ",
			get_atlas_fw_version(), (long)time(NULL));
		if (reason)
			fprintf(fn, DBQ(reason) ":" DBQ(%s) ", ", reason);
		fprintf(fn, DBQ(cmd) ": \"");
		for (p= cmdline; *p; p++)
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

		if (stat(OOQD_OUT, &sb) == -1 &&
			stat(OOQD_NEW_PREFIX, &sb) == 0)
		{
			if (rename(OOQD_NEW_PREFIX, OOQD_OUT) == -1)
			{
				report_err("move '%s' to '%s' failed",
					OOQD_NEW_PREFIX, OOQD_OUT);
			}
		}
		post_results();
	}
}

static void cmddone(void *cmdstate)
{
	int i, r;
	char from_filename[80];
	char to_filename[80];
	struct stat sb;

	report("command is done for cmdstate %p", cmdstate);

	/* Find command */
	for (i= 0; i<state->max_busy; i++)
	{
		if (state->slots[i].cmdstate == cmdstate)
			break;
	}
	if (i >= state->max_busy)
	{
		report("cmddone: state state %p", cmdstate);
		return;
	}
	r= state->slots[i].bp->testops->delete(cmdstate);
	if (r != 0)
	{
		state->slots[i].cmdstate= NULL;
		state->curr_busy--;
	}
	else
		report("cmddone: strange, cmd %p is busy", cmdstate);

	snprintf(from_filename, sizeof(from_filename),
		"/home/atlas/data/new/ooq.%d", i);
	snprintf(to_filename, sizeof(to_filename),
		"/home/atlas/data/ooq.out/%d", i);
	if (stat(to_filename, &sb) == 0)
	{
		report("output file '%s' is busy", to_filename);

		/* continue, we may have to post */
	}
	else if (rename(from_filename, to_filename) == -1)
	{
		report_err("move '%s' to '%s' failed",
			from_filename, to_filename);
	}

	if (state->curr_busy == 0)
	{
		post_results();
	}
}

#define RESOLV_CONF	"/etc/resolv.conf"
static void check_resolv_conf2(const char *out_file, const char *atlasid)
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

	if ((r != 0 || last_time != -1) && out_filename != NULL)
	{
		fn= fopen(out_file, "a");
		if (!fn)
			crondlog(DIE9 "unable to append to '%s'", out_file);
		fprintf(fn, "RESULT { ");
		if (atlasid)
			fprintf(fn, DBQ(id) ":" DBQ(%s) ", ", atlasid);
		fprintf(fn, DBQ(fw) ":" DBQ(%d) ", " DBQ(time) ":%ld, ",
			get_atlas_fw_version(), (long)time(NULL));
		fprintf(fn, DBQ(event) ": " DBQ(load resolv.conf)
			", " DBQ(result) ": %d", r);

		fprintf(fn, " }\n");
		fclose(fn);
	}

	last_time= sb.st_mtime;
}

static void re_post(evutil_socket_t fd UNUSED_PARAM, short what UNUSED_PARAM,
	void *arg UNUSED_PARAM)
{
	/* Just call post_results every once in awhile in case some results
	 * were left behind.
	 */
	post_results();
}

static void post_results(void)
{
	int i, j, r, need_post, probe_id;
	const char *session_id;
	const char *argv[20];
	char from_filename[80];
	char to_filename[80];
	char url[200];
	struct stat sb;

	for (j= 0; j<5; j++)
	{
		/* Grab results and see if something need to be done. */
		need_post= 0;

		if (stat(OOQD_OUT, &sb) == 0)
		{
			/* There is more to post */
			need_post= 1;	
		} else if (stat(OOQD_NEW_PREFIX, &sb) == 0)
		{
			if (rename(OOQD_NEW_PREFIX, OOQD_OUT) == 0)
				need_post= 1;
			else
			{
				report_err("move '%s' to '%s' failed",
					OOQD_NEW_PREFIX, OOQD_OUT);
			}
		}
		for (i= 0; i<state->max_busy; i++)
		{
			snprintf(from_filename, sizeof(from_filename),
				"/home/atlas/data/new/ooq.%d", i);
			snprintf(to_filename, sizeof(to_filename),
				"/home/atlas/data/ooq.out/%d", i);
			if (stat(to_filename, &sb) == 0)
			{
				/* There is more to post */
				need_post= 1;	
				continue;
			}
			if (stat(from_filename, &sb) == -1)
			{
				/* Nothing to do */
				continue;
			}

			need_post= 1;
			if (rename(from_filename, to_filename) == -1)
			{
				report_err("move '%s' to '%s' failed",
					from_filename, to_filename);
			}
		}
		
		if (!need_post)
			break;

		probe_id= get_probe_id();
		if (probe_id == -1)
			break;
		session_id= get_session_id();
		if (session_id == NULL)
			break;
		snprintf(url, sizeof(url),
			"http://127.0.0.1:8080/?PROBE_ID=%d&SESSION_ID=%s&SRC=oneoff",
			probe_id, session_id);

		i= 0;
		argv[i++]= "httppost";
		argv[i++]= "-A";
		argv[i++]= "9015";
		argv[i++]= "--delete-file";
		argv[i++]= "--post-header";
		argv[i++]= "/home/atlas/status/p_to_c_report_header";
		argv[i++]= "--post-dir";
		argv[i++]= "/home/atlas/data/ooq.out";
		argv[i++]= "--post-footer";
		argv[i++]= "/home/atlas/status/con_session_id.txt";
		argv[i++]= "-O";
		argv[i++]= "/home/atlas/data/new/ooq_sent.vol";
		argv[i++]= url;
		argv[i]= NULL;
		r= httppost_main(i, (char **)argv);
		if (r != 0)
		{
			report("httppost failed with %d", r);
			return;
		}

	}
}

static const char *get_session_id(void)
{
	static char session_id[80];

	char *cp;
	FILE *file;

	file= fopen(ATLAS_SESSION_FILE, "r");
	if (file == NULL)
	{
		return NULL;
	}

	/* Skip first empty line */
	fgets(session_id, sizeof(session_id), file);

	if (fgets(session_id, sizeof(session_id), file) == NULL)
	{
		fclose(file);
		return NULL;
	}
	fclose(file);
	cp= strchr(session_id, '\n');
	if (cp)
		*cp= '\0';
	cp= strrchr(session_id, ' ');
	if (!cp)
		return NULL;
	return cp+1;
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
