/*
rxtxrpt.c

Report RX and TX statistics. Also report IPv6 address and the IPv6 routing
table if it has changed.
*/

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "libbb.h"

#define NEW_FORMAT

#define DEV_FILE	"/proc/net/dev"
#define IF_INET6_FILE	"/proc/net/if_inet6"
#define IPV6_ROUTE_FILE	"/proc/net/ipv6_route"
#define SUFFIX		".new"

#define DBQ(str) "\"" #str "\""

int do_atlas= 0;

static int rpt_rxtx(void);
static int setup_ipv6_rpt(char *cache_name, int *need_report);
static int rpt_ipv6(char *cache_name);
static void report(const char *fmt, ...);
static void report_err(const char *fmt, ...);

int rxtxrpt_main(int argc, char *argv[])
{
	int r, need_report;
	unsigned opt;
	char *opt_atlas, *cache_name;

	opt_atlas= NULL;
	opt_complementary= NULL;
	opt= getopt32(argv, "A:", &opt_atlas);

	do_atlas= (opt_atlas != NULL);

	if (argc > optind+1)
		bb_show_usage();

	cache_name= NULL;
	if (argc == optind+1)
		cache_name= argv[optind];

	if (do_atlas)
	{
#ifdef NEW_FORMAT
		printf("RESULT { " DBQ(id) ": " DBQ(%s) ", ", opt_atlas);
		printf(DBQ(fw) ": %d, ", get_atlas_fw_version());
		printf(DBQ(time) ": %d, ", time(NULL));
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

	if (cache_name)
	{
		r= setup_ipv6_rpt(cache_name, &need_report);
		if (r != 0)
			return r;
		if (need_report)
		{
			r= rpt_ipv6(cache_name);
			if (r != 0)
				return r;
		}
	}

	return 0;
}

#ifdef NEW_FORMAT
static int rpt_rxtx(void)
{
	int i;
	unsigned long long rx_bytes, rx_packets, rx_errs, rx_drop,
		rx_fifo, rx_frame, rx_compressed, rx_multicast,
		tx_bytes, tx_packets, tx_errs, tx_drop,
		tx_fifo, tx_colls, tx_carrier, tx_compressed;
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

	/* Copy two line */
	for (i= 0; i<2; i++)
	{
		if (fgets(buf, sizeof(buf), file) == NULL)
		{
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
			&rx_bytes, &rx_packets, &rx_errs, &rx_drop,
			&rx_fifo, &rx_frame, &rx_compressed, &rx_multicast,
			&tx_bytes, &tx_packets, &tx_errs, &tx_drop,
			&tx_fifo, &tx_colls, &tx_carrier, &tx_compressed) != 16)
		{
			report_err("format error in '%s'", DEV_FILE);
			fclose(file);
			return 1;
		}

		*cp= '\0';

		printf("%s { " DBQ(infname) ": " DBQ(%s) ", ",
			i == 0 ? "" : ",", infname);
	
		printf(DBQ(rx-bytes) ": %llu, ", rx_bytes);
		printf(DBQ(rx-packets) ": %llu, ", rx_packets);
		printf(DBQ(rx-errs) ": %llu, ", rx_errs);
		printf(DBQ(rx-drop) ": %llu, ", rx_drop);
		printf(DBQ(rx-fifo) ": %llu, ", rx_fifo);
		printf(DBQ(rx-frame) ": %llu, ", rx_frame);
		printf(DBQ(rx-compressed) ": %llu, ", rx_compressed);
		printf(DBQ(rx-multicast) ": %llu, ", rx_multicast);
		printf(DBQ(tx-bytes) ": %llu, ", tx_bytes);
		printf(DBQ(tx-packets) ": %llu, ", tx_packets);
		printf(DBQ(tx-errs) ": %llu, ", tx_errs);
		printf(DBQ(tx-drop) ": %llu, ", tx_drop);
		printf(DBQ(tx-fifo) ": %llu, ", tx_fifo);
		printf(DBQ(tx-colls) ": %llu, ", tx_colls);
		printf(DBQ(tx-carrier) ": %llu, ", tx_carrier);
		printf(DBQ(tx-compressed) ": %llu", tx_compressed);
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

static int setup_ipv6_rpt(char *cache_name, int *need_report)
{
	int i, r;
	char *cp, *cp1;
	char filename[80];
	char buf1[1024];
	char buf2[1024];
	FILE *in_file, *out_file, *cache_file;

	*need_report= 0;

	if (strlen(cache_name) + strlen(SUFFIX) + 1 > sizeof(filename))
	{
		report("cache name '%s' too long", cache_name);
		return 1;
	}

	strlcpy(filename, cache_name, sizeof(filename));
	strlcat(filename, SUFFIX, sizeof(filename));

	out_file= fopen(filename, "w");
	if (out_file == NULL)
	{
		report_err("unable to create '%s'", filename);
		return 1;
	}

	/* Copy IF_INET6_FILE */
	in_file= fopen(IF_INET6_FILE, "r");
	if (in_file == NULL)
	{
		report_err("unable to open '%s'", IF_INET6_FILE);
		fclose(out_file);
		return 1;
	}

	while (r= fread(buf1, 1, sizeof(buf1), in_file), r > 0)
	{
		if (fwrite(buf1, 1, r, out_file) != r)
		{
			report_err("error writing to '%s'", filename);
			fclose(in_file);
			fclose(out_file);
			return 1;
		}
	}
	if (ferror(in_file))
	{
		report_err("error reading from '%s'", IF_INET6_FILE);
		fclose(in_file);
		fclose(out_file);
		return 1;
	}
	fclose(in_file);

	/* Copy IPV6_ROUTE_FILE */
	in_file= fopen(IPV6_ROUTE_FILE, "r");
	if (in_file == NULL)
	{
		report_err("unable to open '%s'", IPV6_ROUTE_FILE);
		fclose(out_file);
		return 1;
	}

	while (fgets(buf1, sizeof(buf1), in_file) != NULL)
	{
		/* Cut out Ref and Use fields */
		cp= buf1;
		for (i= 0; i<6; i++)
		{
			if (cp && cp[0] != '\0')
				cp= strchr(cp+1, ' ');
		}
		if (!cp && cp[0] == '\0')
		{
			report("bad data in '%s'", IPV6_ROUTE_FILE);
			fclose(in_file);
			fclose(out_file);
			return 1;
		}
		cp++;
		/* Find the end of the two fields */
		cp1= cp;
		for (i= 0; i<2; i++)
		{
			if (cp1 && cp1[0] != '\0')
				cp1= strchr(cp1+1, ' ');
		}
		if (!cp1 && cp1[0] == '\0')
		{
			report("bad data in '%s'", IPV6_ROUTE_FILE);
			fclose(in_file);
			fclose(out_file);
			return 1;
		}
		cp1++;
		/* And delete the two fields */
		memmove(cp, cp1, strlen(cp1)+1);

		if (fputs(buf1, out_file) == -1)
		{
			report_err("error writing to '%s'", filename);
			fclose(in_file);
			fclose(out_file);
			return 1;
		}
	}
	if (ferror(in_file))
	{
		report_err("error reading from '%s'", IPV6_ROUTE_FILE);
		fclose(in_file);
		fclose(out_file);
		return 1;
	}
	fclose(in_file);

	/* Now check if the new file is different from the cache one */
	fclose(out_file);
	cache_file= fopen(cache_name, "r");
	if (cache_file == NULL)
	{
		/* Assume that any kind of error here calls for reporting */
		*need_report= 1;
	}

	if (cache_file)
	{
		in_file= fopen(filename, "r");
		if (in_file == NULL)
		{
			report_err("unable to open '%s'", filename);
			fclose(cache_file);
			return 1;
		}

		/* Compare them */
		while (r= fread(buf1, 1, sizeof(buf1), cache_file), r > 0)
		{
			if (fread(buf2, 1, sizeof(buf2), in_file) != r)
			{
				/* Ignore errors, just report */
				*need_report= 1;
				break;
			}

			if (memcmp(buf1, buf2, r) != 0)
			{
				/* Something changed, report */
				*need_report= 1;
				break;
			}
		}

		/* Maybe something got added */
		if (!*need_report)
		{
			if (fread(buf2, 1, sizeof(buf2), in_file) != 0)
			{
				*need_report= 1;
			}
		}
		fclose(cache_file);
		fclose(in_file);
	}

	if (*need_report)
	{
		if (rename(filename, cache_name) == -1)
		{
			report_err("renaming '%s' to '%s' failed",
				filename, cache_name);
			return 1;
		}
	}
	else
	{
		if (unlink(filename) == -1)
		{
			report_err("unlinking '%s' failed",
				filename);
		}
	}

	return 0;
}

static int rpt_ipv6(char *cache_name)
{
	FILE *file;
	char *cp;
	char buf[256];

	file= fopen(cache_name, "r");
	if (!file)
	{
		report_err("unable to open '%s'", cache_name);
		return 1;
	}

	/* Copy all lines */
	while (fgets(buf, sizeof(buf), file) != NULL)
	{
		if (do_atlas)
		{
			/* Get rid of newline */
			cp= strchr(buf, '\n');
			if (cp) *cp= '\0';

			printf(" NEWLINE ");
		}
		fputs(buf, stdout);
	}
	fclose(file);

	return 0;
}

static void report(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	fprintf(stderr, "rxtxrpt: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");

	va_end(ap);
}

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
