#include "libbb.h"

#define URANDOM_DEV "/dev/urandom"

static char hex_chars[]= "0123456789abcdef";

char *atlas_name_macro(char *str)
{
	unsigned char c;
	int i, fd;
	size_t len;
	char *p, *in, *out;
	char buf[256];
	unsigned char random_buf[8];

	p= strchr(str, '$');
	if (p == NULL)
		return strdup(str);

	in= str;
	out= buf;

	while (*in)
	{
		p= strchr(in, '$');
		if (p == NULL)
		{
			strlcpy(out, in, buf+sizeof(buf)-out);
			break;
		}
		if (p != in)
		{
			len= p-in;

			if (len+1 > buf+sizeof(buf)-out)
				return NULL;
			memcpy(out, in, len);
			out[len]= '\0';
			
			out += len;
		}

		switch(p[1])
		{
		case 'p':
			snprintf(out, buf+sizeof(buf)-out, "%d",
				get_probe_id());
			break;
		case 't':
			snprintf(out, buf+sizeof(buf)-out, "%ld",
				(long)time(NULL));
			break;
		case 'r':
			/* We need to hex digits per byte in random_buf */
			if (sizeof(random_buf)*2+1 > buf+sizeof(buf)-out)
				return NULL;

			fd= open(URANDOM_DEV, O_RDONLY);

			/* Best effort, just ignore errors */
			if (fd != -1)
			{
				read(fd, random_buf, sizeof(random_buf));
				close(fd);
			}

			for (i= 0; i<sizeof(random_buf); i++)
			{
				c= random_buf[i];

				out[0]= hex_chars[(c >> 4) & 0xf];
				out[1]= hex_chars[c & 0xf];
				out += 2;
			}
			
			out[0]= '\0';
			break;		

		default:
			return NULL;
		}
		in= p+2;
		out += strlen(out);
	}

	return strdup(buf);
}
