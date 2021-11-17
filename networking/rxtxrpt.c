/*
rxtxrpt.c

Report RX and TX statistics. Also report IPv6 address and the IPv6 routing
table if it has changed.
*/
//config:config RXTXRPT
//config:       bool "rxtxrpt"
//config:       default n
//config:       help
//config:         rxtxrpt report RX and TX statistics as well as IPv6 addresses and
//config:         routes

//applet:IF_RXTXRPT(APPLET(rxtxrpt, BB_DIR_BIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_RXTXRPT) += rxtxrpt.o

//usage:#define rxtxrpt_trivial_usage
//usage:       "[-A STRING]"
//usage:#define rxtxrpt_full_usage "\n\n"
//usage:       "Display RX and TX statistics\n"
//usage:       "\n     -A STRING       Use Atlas format with STRING"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "libbb.h"

#define NEW_FORMAT

#define DEV_FILE	"/proc/net/dev"

#define DBQ(str) "\"" #str "\""

int do_atlas= 0;

static int rpt_rxtx(void);
static void report_err(const char *fmt, ...);

int rxtxrpt_main(int argc, char *argv[])
{
	int r;
	char *opt_atlas;

	opt_atlas= NULL;
	opt_complementary= NULL;
	getopt32(argv, "A:", &opt_atlas);

	do_atlas= (opt_atlas != NULL);

	if (argc > optind)
		bb_show_usage();

	if (do_atlas)
	{
#ifdef NEW_FORMAT
		printf("RESULT { " DBQ(id) ": " DBQ(%s) ", ", opt_atlas);
		printf("%s, ", atlas_get_version_json_str());
		printf(DBQ(time) ": %lld, ", (long long)time(NULL));
		printf(DBQ(lts) ": %d, ", get_timesync());
		printf(DBQ(interfaces) ": [");
#else /* !NEW_FORMWAT */
		printf("%s %lu ", opt_atlas, time(NULL));
#endif /* NEW_FORMWAT */
	}

	r= rpt_rxtx();
	if (r != 0)
		return r;

	if (do_atlas)
	{
#ifdef NEW_FORMAT
		printf(" ] }\n");
#else /* !NEW_FORMAT */
		printf("\n");

#endif /* NEW_FORMAT */
	}

	return 0;
}

#ifdef NEW_FORMAT
static int rpt_rxtx(void)
{
	int i;
	unsigned long long bytes_recv, pkt_recv, errors_recv, dropped_recv,
		fifo_recv, framing_recv, compressed_recv, multicast_recv,
		bytes_sent, pkt_sent, errors_sent, dropped_sent,
		fifo_sent, collisions_sent, carr_lost_sent, compressed_sent;
	char *cp, *infname;
	FILE *file;
	char buf[256];

	file= fopen(DEV_FILE, "r");
	if (!file)
	{
		report_err("unable to open '%s'", DEV_FILE);
		return 1;
	}

	/* Skip two lines */
	if (fgets(buf, sizeof(buf), file) == NULL ||
		fgets(buf, sizeof(buf), file) == NULL)
	{
		report_err("unable to read from '%s'", DEV_FILE);
		fclose(file);
		return 1;
	}

	for (i= 0; i<100; i++)
	{
		if (fgets(buf, sizeof(buf), file) == NULL)
		{
			if (feof(file))
				break;
			report_err("unable to read from '%s'", DEV_FILE);
			fclose(file);
			return 1;
		}

		cp= buf;

		/* Skip leading white space */
		while (*cp == ' ')
			cp++;
		infname= cp;
		cp= strchr(cp, ':');
		if (cp == NULL)
		{
			report_err("format error in '%s'", DEV_FILE);
			fclose(file);
			return 1;
		}

		/* Get all the values */
		if (sscanf(cp+1, "%llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
			&bytes_recv, &pkt_recv, &errors_recv, &dropped_recv,
			&fifo_recv, &framing_recv, &compressed_recv,
			&multicast_recv,
			&bytes_sent, &pkt_sent, &errors_sent, &dropped_sent,
			&fifo_sent, &collisions_sent, &carr_lost_sent,
			&compressed_sent) != 16)
		{
			report_err("format error in '%s'", DEV_FILE);
			fclose(file);
			return 1;
		}

		*cp= '\0';

		printf("%s { " DBQ(name) ": " DBQ(%s) ", ",
			i == 0 ? "" : ",", infname);
	
		printf(DBQ(bytes_recv) ": %llu, ", bytes_recv);
		printf(DBQ(pkt_recv) ": %llu, ", pkt_recv);
		printf(DBQ(errors_recv) ": %llu, ", errors_recv);
		printf(DBQ(dropped_recv) ": %llu, ", dropped_recv);
		printf(DBQ(fifo_recv) ": %llu, ", fifo_recv);
		printf(DBQ(framing_recv) ": %llu, ", framing_recv);
		printf(DBQ(compressed_recv) ": %llu, ", compressed_recv);
		printf(DBQ(multicast_recv) ": %llu, ", multicast_recv);
		printf(DBQ(bytes_sent) ": %llu, ", bytes_sent);
		printf(DBQ(pkt_sent) ": %llu, ", pkt_sent);
		printf(DBQ(errors_sent) ": %llu, ", errors_sent);
		printf(DBQ(dropped_sent) ": %llu, ", dropped_sent);
		printf(DBQ(fifo_sent) ": %llu, ", fifo_sent);
		printf(DBQ(collisions_sent) ": %llu, ", collisions_sent);
		printf(DBQ(carr_lost_sent) ": %llu, ", carr_lost_sent);
		printf(DBQ(compressed_sent) ": %llu", compressed_sent);
		printf(" }");
	}
	fclose(file);

	return 0;
}
#else /* !NEW_FORMAT */
static int rpt_rxtx(void)
{
	int i;
	char *cp;
	FILE *file;
	char buf[256];

	file= fopen(DEV_FILE, "r");
	if (!file)
	{
		report_err("unable to open '%s'", DEV_FILE);
		return 1;
	}

	/* Skip two lines */
	if (fgets(buf, sizeof(buf), file) == NULL ||
		fgets(buf, sizeof(buf), file) == NULL)
	{
		report_err("unable to read from '%s'", DEV_FILE);
		fclose(file);
		return 1;
	}

	/* Copy two line */
	for (i= 0; i<2; i++)
	{
		if (fgets(buf, sizeof(buf), file) == NULL)
		{
			report_err("unable to read from '%s'", DEV_FILE);
			fclose(file);
			return 1;
		}

		if (do_atlas)
		{
			/* Get rid of newline */
			cp= strchr(buf, '\n');
			if (cp) *cp= '\0';

			if (i != 0)
				printf(" NEWLINE ");
		}
		fputs(buf, stdout);
	}
	fclose(file);

	return 0;
}
#endif /* NEW_FORMAT */

static void report_err(const char *fmt, ...)
{
	int t_errno;
	va_list ap;

	t_errno= errno;

	va_start(ap, fmt);

	fprintf(stderr, "rxtxrpt: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, ": %s\n", strerror(t_errno));

	va_end(ap);
}
