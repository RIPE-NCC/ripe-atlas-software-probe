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
