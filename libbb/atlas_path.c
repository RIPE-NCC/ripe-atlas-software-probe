#include "libbb.h"

const char *atlas_base(void)
{
	static const char *base_path= NULL;

	if (base_path == NULL)
	{
		base_path= getenv("ATLAS_BASE");
		if (base_path == NULL)
			base_path= ATLAS_HOME;
	}

	return base_path;
}

char *atlas_path(const char *rel_path)
{
	size_t len;
	const char *base_path;
	char *fn;

	base_path= atlas_base();

	len= strlen(base_path)+1 /* '/' */ +strlen(rel_path)+1 /* '\0' */;
	fn= xmalloc(len);
	snprintf(fn, len, "%s/%s", base_path, rel_path);

	return fn;
}
