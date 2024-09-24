/* RIPEAtlas
 * All the configurable variables - and some non configurables too
 * $Id: $
 */

#ifndef _ATLASINIT_H
#define _ATLASINIT_H

#define ATLAS_BUF_SIZE 1024 
#define MAX_READ ATLAS_BUF_SIZE-2  /* should be enough to read controller keys */

/*********************************************************************
 * Set these constants to your liking
 */

extern const char atlas_log_file[];
extern const int atlas_log_level;

extern const char atlas_contr_known_hosts[];
extern const char atlas_rereg_timestamp[];

extern const int max_lines; /* maximum lines we'll process */
extern const int min_rereg_time; /* 12h */
extern const int max_rereg_time; /* 28d */
extern const int default_rereg_time; /* 7d */

/*********************************************************************/

enum { ALL, DEBUG, INFO, WARN, ERROR } error_level;

void atlas_log( int level, const char *msg, ... );

#endif
