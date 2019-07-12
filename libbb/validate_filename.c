#include "libbb.h"

int validate_filename(const char *path, const char *prefix)
{
	size_t path_len, prefix_len;

	/* Check for the following properties:
	 * 1) path start with prefix
	 * 2) the next character after prefix is a '/'
	 * 3) path does not contain '/../'
	 * 4) path does not end in '/..'
	 * return 0 if any of the properties does not hold
	 * return 1 if all properties hold
	 */
	path_len= strlen(path);
	prefix_len= strlen(prefix);
	if (path_len < prefix_len)
		return 0;

	if (memcmp(path, prefix, prefix_len) != 0)
		return 0;	/* property 1 */

	if (path[prefix_len] != '/')
		return 0;	/* property 2 */

	if (strstr(path, "/../") != NULL)
		return 0;	/* property 3 */

	if (path_len >= 3 && strcmp(&path[path_len-3], "/..") == 0)
		return 0;	/* property 4 */
	
	return 1;
}

char *rebased_validated_filename(const char *path, const char *prefix)
{
	size_t path_len, prefix_len, atlas_home_len, new_len;
	char *new_base, *new_path;

	/* Check for the following properties:
	 * 1) path starts with prefix or if prefix is relative,
	 * '/home/atlas' followed by the prefix.
	 * 2) the next character after prefix is a '/'
	 * 3) path does not contain '/../'
	 * 4) path does not end in '/..'
	 * return NULL if any of the properties does not hold
	 * return a new string that replaces '/home/atlas' with atlas_base().
	 */
	path_len= strlen(path);
	prefix_len= strlen(prefix);
	atlas_home_len= strlen(ATLAS_HOME);

	if (prefix[0] == '/')
	{
		if (path_len < prefix_len)
			return NULL;

		if (memcmp(path, prefix, prefix_len) != 0)
			return NULL;	/* property 1 */

		if (path[prefix_len] != '/')
			return NULL;	/* property 2 */
	}
	else
	{
		if (path_len < atlas_home_len + 1 + prefix_len)
			return NULL;
		if (memcmp(path, ATLAS_HOME, atlas_home_len) != 0)
			return NULL;	/* property 1 */
		if (path[atlas_home_len] != '/')
			return NULL;	/* property 1 */
		if (memcmp(path+atlas_home_len+1, prefix, prefix_len) != 0)
			return NULL;	/* property 1 */

		if (path[atlas_home_len+1+prefix_len] != '/')
			return NULL;	/* property 2 */
	}

	if (strstr(path, "/../") != NULL)
		return NULL;	/* property 3 */

	if (path_len >= 3 && strcmp(&path[path_len-3], "/..") == 0)
		return NULL;	/* property 4 */
	
	new_base= atlas_base();
	new_len= strlen(new_base) + (path_len-atlas_home_len) + 1;
	new_path= xmalloc(new_len);
	strlcpy(new_path, new_base, new_len);
	strlcat(new_path, path+atlas_home_len, new_len);

	return new_path;
}
