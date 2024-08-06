#include "libbb.h"

int validate_atlas_id(const char *atlas_id)
{
	if (strspn(atlas_id, "0123456789") == strlen(atlas_id))
		return 1;
	return 0;
}
