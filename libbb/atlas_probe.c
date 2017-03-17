/*
 * Copyright (c) 2013 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include "libbb.h"
int get_probe_id(void)
{
        static int probe_id= -1;

        size_t len;
        char *check;
        const char *key;
        FILE *fp;
        char buf[80];

	if (probe_id > 0)
		return probe_id;	/* Assume probe ID never changes */

        fp= fopen("/home/atlas/status/reg_init_reply.txt", "r");
        if (!fp)
                return -1;

        probe_id= -1;
        while (fgets(buf, sizeof(buf), fp) != NULL)
        {
                if (strchr(buf, '\n') == NULL)
                        continue;
                key= "PROBE_ID ";
                len= strlen(key);

                if (strncmp(buf, key, len) != 0 || strlen(buf) <= len)
                        continue;
                probe_id= strtol(buf+len, &check, 10);
                break;
        }
        fclose(fp);
        return probe_id;
}
