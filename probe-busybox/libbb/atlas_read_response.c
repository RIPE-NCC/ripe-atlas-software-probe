/*
 * Copyright (c) 2020 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include "libbb.h"

static int got_type= 0;
static int stored_type;

void peek_response(int fd, int *typep)
{
	if (!got_type)
	{
		if (read(fd, &stored_type, sizeof(stored_type)) !=
			sizeof(stored_type))
		{
			fprintf(stderr, "peek_response: error reading\n");
			exit(1);
		}
		got_type= 1;
	}
	*typep= stored_type;
}

void peek_response_file(FILE *file, int *typep)
{
	if (!got_type)
	{
		if (fread(&stored_type, sizeof(stored_type), 1, file) != 1)
		{
			fprintf(stderr, "peek_response_file: error reading\n");
			exit(1);
		}
		got_type= 1;
	}
	*typep= stored_type;
}

void read_response(int fd, int type, size_t *sizep, void *data)
{
	int tmp_type;
	size_t tmp_size;

	if (got_type)
	{
		tmp_type= stored_type;
		got_type= 0;
	}
	else
	{
		if (read(fd, &tmp_type, sizeof(tmp_type)) != sizeof(tmp_type))
		{
			fprintf(stderr, "read_response: error reading\n");
			exit(1);
		}
	}
	if (tmp_type != type)
	{
		fprintf(stderr,
			 "read_response: wrong type, expected %d, got %d\n",
			type, tmp_type);
		exit(1);
	}
	if (read(fd, &tmp_size, sizeof(tmp_size)) != sizeof(tmp_size))
	{
		fprintf(stderr, "read_response: error reading\n");
		exit(1);
	}
	if (tmp_size > *sizep)
	{
		fprintf(stderr, "read_response: data bigger than buffer\n");
		exit(1);
	}
	*sizep= tmp_size;
	if (read(fd, data, tmp_size) != (ssize_t)tmp_size)
	{
		fprintf(stderr, "read_response: error reading\n");
		exit(1);
	}
}


void read_response_file(FILE *file, int type, size_t *sizep, void *data)
{
	int r, tmp_type;
	size_t tmp_size;

	if (got_type)
	{
		tmp_type= stored_type;
		got_type= 0;
	}
	else if (fread(&tmp_type, sizeof(tmp_type), 1, file) != 1)
	{
		fprintf(stderr, "read_response_file: error reading\n");
		exit(1);
	}
	if (tmp_type != type)
	{
		fprintf(stderr,
		 "read_response_file: wrong type, expected %d, got %d\n",
			type, tmp_type);
		exit(1);
	}
	if (fread(&tmp_size, sizeof(tmp_size), 1, file) != 1)
	{
		fprintf(stderr, "read_response_file: error reading\n");
		exit(1);
	}
	if (tmp_size > *sizep)
	{
		fprintf(stderr,
			"read_response_file: data bigger than buffer\n");
		exit(1);
	}
	*sizep= tmp_size;
	if (tmp_size != 0)
	{
		r= fread(data, tmp_size, 1, file);
		if (r != 1)
		{
			fprintf(stderr,
		"read_response_file: error reading %u bytes, got %d: %s\n",
				(unsigned)tmp_size, r, strerror(errno));
			exit(1);
		}
	}
}

