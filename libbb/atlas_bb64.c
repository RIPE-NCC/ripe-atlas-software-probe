/*
 * Copyright (c) 2013 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include "libbb.h"
#define BUF_CHUNK       256

struct buf
{
	size_t offset;
	size_t size;
	size_t maxsize;
	unsigned char *buf;
	int fd;
};

void buf_init(struct buf *buf, int fd)
{
	buf->maxsize= 0;
	buf->size= 0;
	buf->offset= 0;
	buf->buf= NULL;
	buf->fd= fd;
}

int buf_add(struct buf *buf, const void *data, size_t len )
{
	size_t maxsize;
	void *newbuf;

	if (buf->size+len <= buf->maxsize)
	{
		/* Easy case, just add data */
		memcpy(buf->buf+buf->size, data, len);
		buf->size += len;
		return 0;
	}

	/* Just get a new buffer */
	maxsize= buf->size-buf->offset + len + BUF_CHUNK;

	newbuf= malloc(maxsize);
	if (!newbuf)
	{
		fprintf(stderr, "unable to allocate %ld bytes\n", maxsize);
		return (1);
	}

	if (buf->offset < buf->size)
	{
		/* Copy existing data */
		memcpy(newbuf, buf->buf+buf->offset, buf->size-buf->offset);
		buf->size -= buf->offset;
		buf->offset= 0;
	}
	else
	{
		buf->size= buf->offset= 0;
	}
	buf->maxsize= maxsize;
	free(buf->buf);
	buf->buf= newbuf;

	memcpy(buf->buf+buf->size, data, len);
	buf->size += len;
	return 0;
}

int buf_add_b64(struct buf *buf, void *data, size_t len, int mime_nl)
{
	char b64[]=
		"ABCDEFGHIJKLMNOP"
		"QRSTUVWXYZabcdef"
		"ghijklmnopqrstuv"
		"wxyz0123456789+/";
	int i;
	uint8_t *p;
	uint32_t v;
	char str[4];

	p= data;

	for (i= 0; i+3 <= len; i += 3, p += 3)
	{
		v= (p[0] << 16) + (p[1] << 8) + p[2];
		str[0]= b64[(v >> 18) & 63];
		str[1]= b64[(v >> 12) & 63];
		str[2]= b64[(v >> 6) & 63];
		str[3]= b64[(v >> 0) & 63];
		buf_add(buf, str, 4);
		if(mime_nl)
			if (i % 48 == 45)
				buf_add(buf, "\n", 1);
	}
	switch(len-i)
	{
		case 0:	break;	/* Nothing to do */
		case 1:
			v= (p[0] << 16);
			str[0]= b64[(v >> 18) & 63];
			str[1]= b64[(v >> 12) & 63];
			str[2]= '=';
			str[3]= '=';
			buf_add(buf, str, 4);
			break;
		case 2:
			v= (p[0] << 16) + (p[1] << 8);
			str[0]= b64[(v >> 18) & 63];
			str[1]= b64[(v >> 12) & 63];
			str[2]= b64[(v >> 6) & 63];
			str[3]= '=';
			buf_add(buf, str, 4);
			break;
		default:
			fprintf(stderr, "bad state in buf_add_b64");
	}
}

void buf_cleanup(struct buf *buf)
{
	if(buf->maxsize)
		 free(buf->buf);
	buf->buf = NULL;
	buf->offset= buf->size= buf->maxsize= 0;
}
