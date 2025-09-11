/*
 * Copyright (c) 2020 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include "libbb.h"
#include <netinet/in.h>

/* Response types for packet replay */
#define RESP_PACKET	1
#define RESP_SOCKNAME	2
#define RESP_DSTADDR	3
#define RESP_PEERNAME	4

static int got_type= 0;
static int stored_type;

/* Convert Linux sockaddr to local OS sockaddr */
static void convert_linux_sockaddr_to_local(const void *linux_data, size_t linux_size,
                                           void *local_data, size_t *local_size)
{
	const struct sockaddr_in *linux_sin = (const struct sockaddr_in *)linux_data;
	const struct sockaddr_in6 *linux_sin6 = (const struct sockaddr_in6 *)linux_data;
	
	if (linux_size == sizeof(struct sockaddr_in) && 
	    linux_sin->sin_family == AF_INET) {
		/* IPv4 address - direct copy should work */
		memcpy(local_data, linux_data, sizeof(struct sockaddr_in));
		*local_size = sizeof(struct sockaddr_in);
	} else if (linux_size == sizeof(struct sockaddr_in6) && 
	           linux_sin6->sin6_family == AF_INET6) {
		/* IPv6 address - direct copy should work */
		memcpy(local_data, linux_data, sizeof(struct sockaddr_in6));
		*local_size = sizeof(struct sockaddr_in6);
	} else {
		/* Unknown format, try direct copy */
		size_t copy_size = (linux_size < *local_size) ? linux_size : *local_size;
		memcpy(local_data, linux_data, copy_size);
		*local_size = copy_size;
	}
}

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
	char temp_buffer[256]; /* Buffer for reading data */

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
	
	/* Handle sockaddr types with platform conversion */
	if ((type == RESP_DSTADDR || type == RESP_SOCKNAME || type == RESP_PEERNAME) &&
	    tmp_size <= sizeof(temp_buffer)) {
		/* Read into temporary buffer first */
		if (read(fd, temp_buffer, tmp_size) != (ssize_t)tmp_size)
		{
			fprintf(stderr, "read_response: error reading\n");
			exit(1);
		}
		/* Convert Linux format to local OS format */
		convert_linux_sockaddr_to_local(temp_buffer, tmp_size, data, sizep);
	} else {
		/* Regular data, read directly */
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
}


void read_response_file(FILE *file, int type, size_t *sizep, void *data)
{
	int r, tmp_type;
	size_t tmp_size;
	char temp_buffer[256]; /* Buffer for reading data */

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
	
	/* Handle sockaddr types with platform conversion */
	if ((type == RESP_DSTADDR || type == RESP_SOCKNAME || type == RESP_PEERNAME) &&
	    tmp_size <= sizeof(temp_buffer)) {
		/* Read into temporary buffer first */
		if (tmp_size != 0)
		{
			r= fread(temp_buffer, tmp_size, 1, file);
			if (r != 1)
			{
				fprintf(stderr,
			"read_response_file: error reading %u bytes, got %d: %s\n",
					(unsigned)tmp_size, r, strerror(errno));
				exit(1);
			}
		}
		/* Convert Linux format to local OS format */
		convert_linux_sockaddr_to_local(temp_buffer, tmp_size, data, sizep);
	} else {
		/* Regular data, read directly */
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
}

