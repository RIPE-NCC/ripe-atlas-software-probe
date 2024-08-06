#include "libbb.h"

static char *rebased_validated_common(const char* base, const char *path,
	const char *prefix, int require_slash)
{
	size_t path_len, prefix_len, atlas_home_len, new_base_len, new_len;
	int do_replace, failed;
	const char *new_base;
	char *new_path;


	if (atlas_unsafe())
		return strdup(path);

	/* Check for the following properties:
	 * 1) path starts with prefix or if prefix is relative,
	 * ether '/home/atlas' or atlas_base() followed by the prefix.
	 * 2) the next character after prefix is a '/' (or '\0' if
	 *    require_slash is false)
	 * 3) path does not contain '/../'
	 * 4) path does not end in '/..'
	 * return NULL if any of the properties does not hold
	 * return a new string that replaces '/home/atlas' with base.
	 */
	path_len= strlen(path);
	prefix_len= strlen(prefix);
	atlas_home_len= strlen(ATLAS_HOME);
	new_base= base;
	new_base_len= strlen(new_base);

	do_replace= 0;
	if (prefix[0] == '/')
	{
		if (path_len < prefix_len)
			return NULL;

		if (memcmp(path, prefix, prefix_len) != 0)
			return NULL;	/* property 1 */

		if (path[prefix_len] != '/')
		{
			if (require_slash || path[prefix_len] != '\0')
				return NULL;	/* property 2 */
		}
	}
	else
	{
		failed= 0;
		do_replace= 1;	/* Assume /home/atlas */
		if (path_len < atlas_home_len + 1 + prefix_len)
			failed= 1;
		if (!failed && memcmp(path, ATLAS_HOME, atlas_home_len) != 0)
			failed= 1;	/* property 1 */
		if (!failed && path[atlas_home_len] != '/')
			failed= 1;	/* property 1 */
		if (!failed && 
			memcmp(path+atlas_home_len+1, prefix, prefix_len) != 0)
		{
			failed= 1;	/* property 1 */
		}

		if (!failed && path[atlas_home_len+1+prefix_len] != '/')
		{
			if (require_slash ||
				path[atlas_home_len+1+prefix_len] != '\0')
			{
				failed =1;	/* property 2 */
			}
		}

		if (failed)
		{
			do_replace= 0;
			failed= 0;
			if (path_len < new_base_len + 1 + prefix_len)
				failed= 1;
			if (!failed &&
				memcmp(path, new_base, new_base_len) != 0)
			{
				failed= 1;	/* property 1 */
			}
			if (!failed && path[new_base_len] != '/')
				failed= 1;	/* property 1 */
			if (!failed && 
				memcmp(path+new_base_len+1, prefix,
				prefix_len) != 0)
			{
				failed= 1;	/* property 1 */
			}

			if (!failed && path[new_base_len+1+prefix_len] !=
				'/')
			{
				if (require_slash ||
					path[new_base_len+1+prefix_len] !=
					'\0')
				{
					failed =1;	/* property 2 */
				}
			}
		}

		if (failed)
			return NULL;
	}

	if (strstr(path, "/../") != NULL)
		return NULL;	/* property 3 */

	if (path_len >= 3 && strcmp(&path[path_len-3], "/..") == 0)
		return NULL;	/* property 4 */
	
	if (do_replace)
	{
		new_len= strlen(new_base) + (path_len-atlas_home_len) + 1;
		new_path= xmalloc(new_len);
		strlcpy(new_path, new_base, new_len);
		strlcat(new_path, path+atlas_home_len, new_len);
	}
	else
		new_path= strdup(path);

	return new_path;
}

char *rebased_validated_filename(const char *base, const char *path, const char *prefix)
{
	return rebased_validated_common(base, path, prefix, 1 /*require_slash*/);
}

char *rebased_validated_dir(const char *base, const char *path, const char *prefix)
{
	return rebased_validated_common(base, path, prefix, 0 /*!require_slash*/);
}
