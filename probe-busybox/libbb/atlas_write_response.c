/*
 * Copyright (c) 2020 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include "libbb.h"

void write_response(FILE *file, int type, size_t size, void *data)
{
	fwrite(&type, sizeof(type), 1, file);
	fwrite(&size, sizeof(size), 1, file);
	fwrite(data, size, 1, file);
}

