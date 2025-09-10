/*
 * Copyright (c) 2013-2014 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * eooqd.c  Libevent-based One-off queue daemon
 */
//config:config EOOQD
//config:       bool "Eooqd"
//config:       default n
//config:       select FEATURE_SUID
//config:       select FEATURE_SYSLOG
//config:       help
//config:           Eooqd runs Atlas measurements just once.

//applet:IF_EOOQD(APPLET(eooqd, BB_DIR_ROOT, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_EOOQD) += eooqd.o

//usage:#define eooqd_trivial_usage 
//usage:       "<queue-file>"
//usage:#define eooqd_full_usage 

#include <stdio.h>
#include <string.h>

#include <sys/time.h>
#include <sys/resource.h>

#include <libbb.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/dns.h>

#include "eperd.h"
#include "atlas_path.h"

#define SUFFIX 		".curr"
#define OOQD_NEW_PREFIX_REL	"data/new/ooq"
#define OOQD_OUT_PREFIX_REL	"data/out/ooq"
#define ATLAS_SESSION_FILE_REL	"status/con_session_id.txt"
#define REPORT_HEADER_REL	"status/p_to_c_report_header"
#define SESSION_ID_REL		"status/con_session_id.txt"
#define OOQ_SENT_REL		"data/new/ooq_sent.vol"

#define ATLAS_NARGS	64	/* Max arguments to a built-in command */
#define ATLAS_ARGSIZE	512	/* Max size of the command line */

#define SAFE_PREFIX_REL ATLAS_DATA_NEW_REL

#define DBQ(str) "\"" #str "\""

#define BARRIER_CMD "barrier"
#define POST_CMD "post"
#define RELOAD_RESOLV_CONF_CMD "reload_resolv_conf"

#define RESOLV_CONF	"/etc/resolv.conf"

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

	int barrier;
	char *barrier_file;
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
#if ENABLE_EVSSLGETCERT
	{ "evsslgetcert", &sslgetcert_ops },
#endif
#if ENABLE_EVTLSSCAN
	{ "evtlsscan", &tlsscan_ops },
#endif
	{ "evtraceroute", &traceroute_ops },
	{ NULL, NULL }
};

static const char *atlas_id;
static const char *queue_id;

static char *resolv_conf;
static char output_filename[80];

static void report(const char *fmt, ...);
static void report_err(const char *fmt, ...);

static void checkQueue(evutil_socket_t fd, short what, void *arg);
static int add_line(void);
static void cmddone(void *cmdstate, int error);
static void re_post(evutil_socket_t fd, short what, void *arg);
static void post_results(int force_post);
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
	size_t len;
	char *pid_file_name, *interface_name, *instance_id_str;
	char *check;
	struct event *checkQueueEvent, *rePostEvent;
	struct timeval tv;
	struct rlimit limit;
	struct stat sb;

	atlas_id= NULL;
	interface_name= NULL;
	instance_id_str= NULL;
	pid_file_name= NULL;
	queue_id= "";

	(void)getopt32(argv, "A:I:i:P:q:", &atlas_id, 
		&interface_name, &instance_id_str,
		&pid_file_name, &queue_id);

	if (argc != optind+1)
	{
		bb_show_usage();
		return 1;
	}

	instance_id= 0;
	if (instance_id_str)
	{
		instance_id= strtoul(instance_id_str, &check, 0);
		if (check[0] != '\0')
		{
			report("unable to parse instance id '%s'",
				instance_id_str);
			return 1;
		}
	}

	if (interface_name)
	{
		len= strlen(RESOLV_CONF) + 1 +
			strlen(interface_name) + 1;
		resolv_conf= malloc(len);
		snprintf(resolv_conf, len, "%s.%s",
			RESOLV_CONF, interface_name);

		/* Check if this resolv.conf exists. If it doen't, switch
		 * to the standard one.
		 */
		if (stat(resolv_conf, &sb) == -1)
		{
			free(resolv_conf);
			resolv_conf= strdup(RESOLV_CONF);
		}
	}
	else
	{
		resolv_conf= strdup(RESOLV_CONF);
	}

	if(pid_file_name)
	{
		if (!check_pidfile(pid_file_name)) {
			report("a process is still running");
			return 1;
		}

		if (write_pidfile(pid_file_name) < 0) {
			report("error writing PID file '%s'; %s", pid_file_name, strerror(errno));
			return 1;
		}
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

	snprintf(output_filename, sizeof(output_filename),
		"%s/" OOQD_OUT_PREFIX_REL "%s/ooq.out",
		ATLAS_SPOOLDIR, queue_id);

	signal(SIGQUIT, SIG_DFL);
	limit.rlim_cur= RLIM_INFINITY;
	limit.rlim_max= RLIM_INFINITY;
	setrlimit(RLIMIT_CORE, &limit);

	/* Ignore SIGPIPE, broken TCP sessions may trigger them */
	signal(SIGPIPE, SIG_IGN);

	/* Create libevent event base */
	EventBase= event_base_new();
	if (!EventBase)
	{
		crondlog(DIE9 "event_base_new failed"); /* exits */
	}
	DnsBase= evdns_base_new(EventBase, 0 /*initialize*/);
	if (!DnsBase)
	{
		event_base_free(EventBase);
		crondlog(DIE9 "evdns_base_new failed"); /* exits */
	}

	if (interface_name)
	{
		r= evdns_base_set_interface(DnsBase, interface_name);
		if (r == -1)
		{
			event_base_free(EventBase);
			crondlog(DIE9 "evdns_base_set_interface failed");
							 /* exits */
		}
	}

	r = evdns_base_resolv_conf_parse(DnsBase, DNS_OPTIONS_ALL,
		resolv_conf);
	if (r == -1)
	{
		event_base_free(EventBase);
		crondlog(DIE9 "evdns_base_resolv_conf_parse failed"); /* exits */
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
	int r;
	struct stat sb;

	if (!state->curr_file)
	{
		if (stat(state->queue_file, &sb) == -1)
		{
			if (errno == ENOENT)
			{
				return;
			}
			report_err("stat failed");
			return;
		}

		/* Remove curr_qfile. Renaming queue_file to curr_qfile 
		 * will silently fail to delete queue_file if queue_file and
		 * curr_qfile are hard links.
		 */
		if (unlink(state->curr_qfile) == -1)
		{
			/* Expect ENOENT */
			if (errno != ENOENT)
			{
				report_err("unlink failed");
				return;
			}
		}

		/* Try to move queue_file to curr_qfile. This provides at most
		 * once behavior and allows producers to create a new
		 * queue_file while we process the old one.
		 */
		if (rename(state->queue_file, state->curr_qfile) == -1)
		{
			/* We verified queue_file is there so any failure is
			 * fatal.
			 */
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
		r= add_line();
		if (r == -1)
			break;	/* Wait for barrier to complete */
	}

	check_resolv_conf2(output_filename, atlas_id);
}

static int add_line(void)
{
	char c;
	int i, argc, fd, skip, slot;
	size_t len;
	char *cp, *ncp;
	struct builtin *bp;
	char *p, *validated_fn;
	const char *reason;
	void *cmdstate;
	FILE *fn;
	const char *argv[ATLAS_NARGS];
	char args[ATLAS_ARGSIZE];
	char cmdline[256];
	char filename[80];
	char filename2[80];
	struct stat sb;

	if (state->barrier)
	{
		if (state->curr_busy > 0)
			return -1;
		fd= open(state->barrier_file, O_CREAT, 0);
		if (fd != -1)
			close(fd);
		else
		{
			report_err("unable to create barrier file '%s'",
				state->barrier_file);
		}
		free(state->barrier_file);
		state->barrier_file= NULL;
		state->barrier= 0;
	}

	if (fgets(cmdline, sizeof(cmdline), state->curr_file) == NULL)
	{
		if (ferror(state->curr_file))
			report_err("error reading queue file");
		fclose(state->curr_file);
		state->curr_file= NULL;
		return 0;
	}

	cp= strchr(cmdline, '\n');
	if (cp)
		*cp= '\0';

	crondlog(LVL7 "atlas_run: looking for '%s'", cmdline);

	/* Check for post command */
	if (strcmp(cmdline, POST_CMD) == 0)
	{
		/* Trigger a post */
		post_results(1 /* force_post */);
		return 0;	/* Done */
	}

	/* Check for barrier command */
	len= strlen(BARRIER_CMD);
	if (strlen(cmdline) >= len &&
		strncmp(cmdline, BARRIER_CMD, len) == 0 &&
		cmdline[len] == ' ')
	{
		p= &cmdline[len];
		while (*p != '\0' && *p == ' ')
			p++;
		validated_fn= rebased_validated_filename(ATLAS_SPOOLDIR,
			p, SAFE_PREFIX_REL);
		if (validated_fn == NULL)
		{
			crondlog(LVL8 "insecure file '%s'. allowed path '%s'", 
				p, SAFE_PREFIX_REL);
		}
		state->barrier= 1;
		state->barrier_file= validated_fn;
		return 0;
	}

	/* Check for the reload resolv.conf command */
	if (strcmp(cmdline, RELOAD_RESOLV_CONF_CMD) == 0)
	{
		/* Trigger a reload */
		check_resolv_conf2(output_filename, atlas_id);
		return 0;	/* Done */
	}

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
	slot = 0; /* Initialize slot */
	for (skip= 1; skip <= state->max_busy; skip++)
	{
		slot= (state->curr_index+skip) % state->max_busy;
		if (state->slots[slot].cmdstate == NULL)
			break;
	}
	if (state->slots[slot].cmdstate != NULL)
		crondlog(DIE9 "no empty slot?");
	argv[argc++]= "-O";
	snprintf(filename, sizeof(filename),
		"%s/" OOQD_NEW_PREFIX_REL "%s.%d",
		ATLAS_SPOOLDIR, queue_id, slot);
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
		snprintf(filename, sizeof(filename),
			"%s/" OOQD_NEW_PREFIX_REL "%s",
			ATLAS_SPOOLDIR, queue_id);
		fn= fopen(filename, "a");
		if (!fn) 
		{
			crondlog(DIE9 "unable to append to '%s'", filename);
		}
		fprintf(fn, "RESULT { ");
		if (state->atlas_id)
			fprintf(fn, DBQ(id) ":" DBQ(%s) ", ", state->atlas_id);
		fprintf(fn, "%s, " DBQ(time) ":%ld, ",
			atlas_get_version_json_str(), (long)time(NULL));
		if (reason)
			fprintf(fn, DBQ(reason) ":" DBQ(%s) ", ", reason);
		fprintf(fn, DBQ(cmd) ": \"");
		for (p= cmdline; *p; p++)
		{
			c= *p;
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

		snprintf(filename2, sizeof(filename2),
			"%s/" OOQD_OUT_PREFIX_REL "%s/ooq",
			ATLAS_SPOOLDIR, queue_id);
		if (stat(filename2, &sb) == -1 &&
			stat(filename, &sb) == 0)
		{
			if (rename(filename, filename2) == -1)
			{
				report_err("move '%s' to '%s' failed",
					filename, filename2);
			}
		}
		post_results(0 /* !force_post */);
	}

	return 0;
}

static void cmddone(void *cmdstate, int error UNUSED_PARAM)
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
		"%s/" OOQD_NEW_PREFIX_REL "%s.%d",
		ATLAS_SPOOLDIR, queue_id, i);
	
	snprintf(to_filename, sizeof(to_filename),
	         "%s/%s/%s/%d", ATLAS_SPOOLDIR,
	         OOQD_OUT_PREFIX_REL, queue_id, i);

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
		post_results(0 /* !force_post */);
	}
}

static void check_resolv_conf2(const char *out_file, const char *atlasid)
{
	static time_t last_time= -1;

	int r;
	FILE *fn;
	struct stat sb;

	r= stat(resolv_conf, &sb);
	if (r == -1)
	{
		crondlog(LVL8 "error accessing resolv.conf: %s",
			strerror(errno));
		return;
	}

	if (sb.st_mtime == last_time)
	{
		crondlog(LVL7 "check_resolv_conf2: no change (time %d)",
			sb.st_mtime);
		return;	/* resolv.conf did not change */
	}
	evdns_base_clear_nameservers_and_suspend(DnsBase);
	r= evdns_base_resolv_conf_parse(DnsBase, DNS_OPTIONS_ALL,
		resolv_conf);
	evdns_base_resume(DnsBase);

	if ((r != 0 || last_time != -1) && out_file != NULL)
	{
		fn= fopen(out_file, "a");
		if (!fn)
			crondlog(DIE9 "unable to append to '%s'", out_file);
		fprintf(fn, "RESULT { ");
		if (atlasid)
			fprintf(fn, DBQ(id) ":" DBQ(%s) ", ", atlasid);
		fprintf(fn, "%s, " DBQ(time) ":%ld, ",
			atlas_get_version_json_str(), (long)time(NULL));
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
	post_results(0 /* !force_post */);
}

static void post_results(int force_post)
{
	int i, j, r, need_post, probe_id;
	char *fn_header, *fn_session_id, *fn_ooq_sent;
	const char *session_id;
	const char *argv[20];
	char from_filename[80];
	char to_filename[80];
	char url[200];
	struct stat sb;

	for (j= 0; j<5; j++)
	{
		/* Grab results and see if something need to be done. */
		need_post= force_post;
		force_post= 0;	/* Only one time */

		snprintf(from_filename, sizeof(from_filename),
			"%s/" OOQD_NEW_PREFIX_REL "%s",
			ATLAS_SPOOLDIR, queue_id);
		snprintf(to_filename, sizeof(to_filename),
			"%s/" OOQD_OUT_PREFIX_REL "%s/ooq",
			ATLAS_SPOOLDIR, queue_id);
		if (stat(to_filename, &sb) == 0)
		{
			/* There is more to post */
			need_post= 1;	
		} else if (stat(from_filename, &sb) == 0)
		{
			if (rename(from_filename, to_filename) == 0)
				need_post= 1;
			else
			{
				report_err("move '%s' to '%s' failed",
					from_filename, to_filename);
			}
		}
		for (i= 0; i<state->max_busy; i++)
		{
			snprintf(from_filename, sizeof(from_filename),
				"%s/" OOQD_NEW_PREFIX_REL "%s.%d",
				ATLAS_SPOOLDIR, queue_id, i);
			snprintf(to_filename, sizeof(to_filename),
				"%s/" OOQD_OUT_PREFIX_REL "%s/%d",
				ATLAS_SPOOLDIR, queue_id, i);
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
		snprintf(from_filename, sizeof(from_filename),
			"%s/" OOQD_OUT_PREFIX_REL "%s",
			ATLAS_SPOOLDIR, queue_id);

		asprintf(&fn_header, "%s/%s", ATLAS_RUNDIR, REPORT_HEADER_REL);
		asprintf(&fn_session_id, "%s/%s", ATLAS_RUNDIR, SESSION_ID_REL);
		asprintf(&fn_ooq_sent, "%s/%s", ATLAS_SPOOLDIR, OOQ_SENT_REL);
		i= 0;
		argv[i++]= "httppost";
		argv[i++]= "-A";
		argv[i++]= "9015";
		argv[i++]= "--delete-file";
		argv[i++]= "--post-header";
		argv[i++]= fn_header;
		argv[i++]= "--post-dir";
		argv[i++]= from_filename;
		argv[i++]= "--post-footer";
		argv[i++]= fn_session_id;
		argv[i++]= "-O";
		argv[i++]= fn_ooq_sent;
		argv[i++]= url;
		argv[i]= NULL;
		r= httppost_main(i, (char **)argv);
		free(fn_header); fn_header= NULL;
		free(fn_session_id); fn_session_id= NULL;
		free(fn_ooq_sent); fn_ooq_sent= NULL;
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

	char *cp, *fn;
	FILE *file;

	asprintf(&fn, "%s/%s", ATLAS_RUNDIR, ATLAS_SESSION_FILE_REL);
	file= fopen(fn, "r");
	free(fn); fn= NULL;
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
