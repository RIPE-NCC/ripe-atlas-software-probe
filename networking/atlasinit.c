/* RIPEAtlas
 * All the configurable variables - and some non configurables too
 * Usage1: ./init_resp_parse < init_messagefile
 * Usage2: ./init_resp_parse init_messagefile
 * $Id: $
 */
//config:config ATLASINIT
//config:       bool "atlasinit"
//config:       default n
//config:       help
//config:       RIPE NCC Atlas initialization and parsing applicaton.
//config:       antony@rip.net. Aug 2010.

//applet:IF_ATLASINIT(APPLET(atlasinit, BB_DIR_BIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_ATLASINIT) += atlasinit.o

//usage:#define atlasinit_trivial_usage
//usage:       "[OPTION]...[MANPAGE]..."
//usage:#define atlasinit_full_usage
//usage:       "atlasinit filename"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <stdarg.h>
#include "atlasinit.h"

//#ifndef NOTBUSYBOX
/* compiled to busybox. tested on 1.13  */
#include "libbb.h"
//#endif

#define ERROR 1
#define INFO  2
#define ATLAS_DEFAULT_WAIT 100
#define OPT_STRING "rcdsi:I:"
#define ATLAS_WAIT 0

enum 
{
	OPT_REG_INIT	= (1 << 0),  /* r */
	OPT_CNT_INIT	= (1 << 1),  /* c */
	OPT_CNT_HELLO	= (1 << 2),  /* d */	/* Should be removed */
	OPT_SINCELAST   = (1 << 3),  /* s */	/* Should be removed */
	OPT_P_TO_R_INIT = (1 << 4),  /* i */
};

#define DBQ(str) "\"" #str "\""

/*********************************************************************
 * Set these constants to your liking
 */
static int process_wait (const char *type, int delay);
static int reg_init_main( int argc, char *argv[] );
static int con_init_main( int argc, char *argv[] );
static void print_token_ver (FILE * write_to, int flag_rereg);

static char *skip_tag(char *start);
static char *skip_spaces(char *start);
static char *skip_port(char *start);
static char *skip_literal(char *start, const char *literal);

const char atlas_log_file[]="./probe.log";
const int atlas_log_level=INFO;

const char atlas_contr_known_hosts[]="./known_hosts_controllers";
const char atlas_rereg_timestamp[]="./rereg_time.sh";
// const char atlas_con_hello[]="./con_hello.txt";
const char atlas_con_session_id[]="./con_session_id.txt";
const char atlas_force_reg[] = "./force_reg.sh";
const char atlas_netconfig_v4[] = "./netconfig_v4.vol";
const char atlas_netconfig_v6[] = "./netconfig_v6.vol";
const char atlas_resolv_conf[] = "./resolv.conf.vol";
#define NETWORK_V4_STATIC_INFO_JSON_REL	"status/network_v4_static_info.json"
#define NETWORK_V6_STATIC_INFO_JSON_REL	"status/network_v6_static_info.json"
#define NETWORK_DNS_STATIC_INFO_JSON_REL	"status/network_dns_static_info.json"
#define FIRMWARE_APPS_VERSION_REL "state/FIRMWARE_APPS_VERSION"

const int max_lines = 16; /* maximum lines we'll process */
const int min_rereg_time = 100; 
const int max_rereg_time = 28*24*3600; /* 28d */
const int default_rereg_time = 7*24*3600; /* 7d */
char *str_reason;
const char *str_device;

/**********************************************************************/

static	char line[ATLAS_BUF_SIZE];

#ifdef NOTBUSYBOX
int main( int argc, char *argv[] )
#else
int atlasinit_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int atlasinit_main( int argc, char *argv[] )
#endif 
{
	int opt = 0;

	if(argc > 1) 
	{
		str_device= NULL;
		opt = getopt32(argv, OPT_STRING, &str_reason, &str_device);
		argv += optind;
		argc -= optind;
		argc++; // AA Hack
	}
	else 
	{	// AA improve
		// we are called without an option decide which is default
		reg_init_main( argc, argv);
	}	

	if(opt & OPT_REG_INIT)
	{	
		reg_init_main( argc, argv);
	} 
	else if ( opt & OPT_CNT_INIT) 
	{
		con_init_main(argc, argv);
		
	}
	else if(opt & OPT_P_TO_R_INIT)
	{
		print_token_ver(stdout, 1);
	}

	return 0;
}

static void print_token_ver (FILE * write_to, int flag_rereg) 
{
	float root_fs_ver = 0;
	FILE *fp = xfopen_for_read("/proc/version");
	FILE *fpv;
	char *my_mac, *path;

	bzero( line, ATLAS_BUF_SIZE );
	fscanf (fp, "%s", line);
	fscanf (fp, "%s", line);
	fscanf (fp, "%s", line);

	path= atlas_path(FIRMWARE_APPS_VERSION_REL);
	fpv = fopen(path, "r");
	free(path); path= NULL;
	if(fpv)
	{
		fscanf (fpv, "%f", &root_fs_ver);
		fclose(fpv); fpv= NULL;
	}
	else 
		root_fs_ver=3100; 

	if(flag_rereg >  0)
		fprintf(write_to, "P_TO_R_INIT\n");
	my_mac = getenv("ETHER_SCANNED");
	fprintf(write_to, "TOKEN_SPECS probev1 %s", line);
	if (my_mac !=  NULL) 
		fprintf(write_to, "-%s ", my_mac );
	fprintf(write_to, " %d\n", (int)root_fs_ver);
	if(flag_rereg >  0)
		fprintf(write_to, "REASON_FOR_REGISTRATION %s\n", str_reason);
	fclose(fp);
}

static char *skip_session_id(char *start)
{
	char *cp;
	char c;

	/* 0-9, A-F, a-f */
	cp= start;
	for (;;)
	{
		c= *cp;
		if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') ||
			(c >= 'a' && c <= 'f'))
		{
			cp++;
			continue;
		}
		if (c == '\0')
			break;
		if (c == ' ')
		{
			*cp= '\0';
			break;
		}

		/* Bad character */
		return NULL;
	}
	if (cp-start > 80)
		return NULL;	/* Wrong length */
	return cp;
}

static char *skip_seconds(char *start)
{
	char *cp;
	char c;

	/* 0-9 */
	cp= start;
	for (;;)
	{
		c= *cp;
		if (c >= '0' && c <= '9')
		{
			cp++;
			continue;
		}
		if (c == '\0')
			break;
		if (c == ' ')
		{
			*cp= '\0';
			break;
		}

		/* Bad character */
		return NULL;
	}
	if (cp-start > 6)
		return NULL;	/* Too long */
	return cp;
}

static int con_init_main( int argc, char *argv[] )
{
	int ret = 0;
	size_t len;
	unsigned long seconds;
	FILE *read_from = stdin;
	char *cp, *ecp, *check;

	if( argc > 1 ) {
                read_from = fopen( argv[0], "rt" );
                if( read_from==NULL ) {
                        atlas_log( ERROR, "Cannot read from file %s\n", argv[1] );
                        return 1;
                }
        }
	/* read OK */
	cp= fgets( line, sizeof(line), read_from );
	if (cp == NULL)
	{
		atlas_log( ERROR, "Read error\n");
		goto fail;
	}
	cp= strchr(line, '\n');
	if (cp == NULL)
	{
		atlas_log( ERROR, "Line too long\n");
		goto fail;
	}
	*cp= '\0';

	if( strcmp(line,"OK") == 0 ) {
        	int l=1;

       		while( l<=max_lines ) {
			cp= fgets( line, sizeof(line), read_from );
			if (cp == NULL)
			{
				if (feof(read_from))
					break;

				atlas_log( ERROR, "Read error\n");
				goto fail;
			}
			cp= strchr(line, '\n');
			if (cp == NULL)
			{
				atlas_log( ERROR, "Line too long\n");
				goto fail;
			}
			*cp= '\0';
			len= strlen(line);

			cp= line;
			ecp= skip_tag(cp);
			if (ecp == NULL)
			{
				atlas_log( ERROR, "missing tag\n");
				goto fail;
			}

                	if( strcmp(cp,"REMOTE_PORT")==0 ) {
				cp= skip_spaces(ecp+1);
				ecp= skip_port(cp);
				if (ecp == NULL)
				{
					atlas_log( ERROR, "missing port\n");
					goto fail;
				}
				printf ("REMOTE_PORT %s\n", cp);

				if (ecp+1 < line+len)
				{
					cp= skip_spaces(ecp+1);
					if (cp != line+len)
					{
						atlas_log(ERROR,
						"garbage at end of line\n");
						goto fail;
					}
				}
			}
			else if ( strncmp(line,"SESSION_ID", 10)==0 ) 
			{
			        FILE *f1;

				cp= skip_spaces(ecp+1);
				ecp= skip_session_id(cp);
				if (ecp == NULL)
				{
					atlas_log( ERROR,
						"missing session ID\n");
					goto fail;
				}

			        f1  = fopen( atlas_con_session_id, "wt" );
				fprintf  (f1, "\nSESSION_ID %s\n", cp);
				fclose (f1);

				if (ecp+1 < line+len)
				{
					cp= skip_spaces(ecp+1);
					if (cp != line+len)
					{
						atlas_log(ERROR,
						"garbage at end of line\n");
						goto fail;
					}
				}
			}
        		l++;
		}
	}
	else if  (strcmp(line,"WAIT") == 0 ) 
	{
		cp= fgets( line, sizeof(line), read_from );
		if (cp == NULL)
		{
			if (feof(read_from))
			{
				atlas_log( ERROR, "Unexepcted EOF\n");
				goto fail;
			}

			atlas_log( ERROR, "Read error\n");
			goto fail;
		}
		cp= strchr(line, '\n');
		if (cp == NULL)
		{
			atlas_log( ERROR, "Line too long\n");
			goto fail;
		}
		*cp= '\0';
		len= strlen(line);

		cp= line;
		ecp= skip_literal(cp, "TIMEOUT");
		if (ecp == NULL)
		{
			atlas_log( ERROR, "missing keyword TIMEOUT\n");
			goto fail;
		}

		cp= skip_spaces(ecp+1);
		ecp= skip_seconds(cp);
		if (ecp == NULL)
		{
			atlas_log( ERROR, "missing seconds value\n");
			goto fail;
		}

		seconds= strtoul(cp, &check, 10);
		if (seconds == 0 || seconds == ULONG_MAX ||
			check[0] != '\0')
		{
			atlas_log( ERROR,
				"bad seconds value\n");
			goto fail;
		}

		if (ecp+1 < line+len)
		{
			cp= skip_spaces(ecp+1);
			if (cp != line+len)
			{
				atlas_log(ERROR,
				"garbage at end of line\n");
				goto fail;
			}
		}

		process_wait("CON_WAIT_TIMER", seconds);
	}	
	else if  (strncmp(line,"REFUSED\n",8) == 0 )
	{
		FILE *f = fopen( atlas_force_reg, "wt" );

		// unlink(atlas_con_hello);
		bzero( line, ATLAS_BUF_SIZE );
        	fgets( line, MAX_READ, read_from );
		fprintf (f,"REASON=%s\n", line+8);
		fclose(f);
		
	}
	else  {
		char *p = strchr(line,'\n');
                if( p!=NULL ) *p = '\0';
                atlas_log( ERROR, "OK expected, got \"%s\" instead\n", line );
		process_wait("CON_WAIT_TIMER", ATLAS_DEFAULT_WAIT); /* we got error the only action from probe is wait. so force it*/
                ret = 1;
        }
	
	if (argc > 1 ) 
		fclose (read_from);
	return ret;

fail:
	if (read_from != stdin)
		fclose(read_from);
	return 1;

} 

static int process_wait (const char *type, int delay)
{
	time_t mytime = time(0);
	mytime = time(0);
	if(delay >  max_rereg_time ) {
               	atlas_log( ERROR, "Reregister time %d is too high\n", delay );
               	delay = max_rereg_time;
        }
	if(delay <  min_rereg_time ) {
               	atlas_log( ERROR, "Reregister time %d is too low\n", delay );
               	delay = min_rereg_time;
        }
	printf ("%s %u\n", type, (uint)(mytime + delay));
	return (delay);
}

static char *skip_spaces(char *start)
{
	while (*start == ' ')
		start++;
	return start;
}

static char *skip_tag(char *start)
{
	char *cp;
	char c;

	/* A-Z, _, and 0-9 */
	cp= start;
	for (;;)
	{
		c= *cp;
		if ((c >= 'A' && c <= 'Z') || c == '_' ||
			(c >= '0' && c <= '9'))
		{
			cp++;
			continue;
		}
		if (c == '\0')
			break;
		if (c == ' ')
		{
			*cp= '\0';
			break;
		}

		/* Bad character */
		return NULL;
	}
	return cp;
}

static char *skip_timestamp(char *start)
{
	char *cp;
	char c;

	/* 0-9 */
	cp= start;
	for (;;)
	{
		c= *cp;
		if (c >= '0' && c <= '9')
		{
			cp++;
			continue;
		}
		if (c == '\0')
			break;
		if (c == ' ')
		{
			*cp= '\0';
			break;
		}

		/* Bad character */
		return NULL;
	}
	if (cp-start > 12)
		return NULL;	/* Too long */
	return cp;
}

static char *skip_version(char *start)
{
	char c;
	char *cp;

	/* 0-9 */
	cp= start;
	for (;;)
	{
		c= *cp;
		if (c >= '0' && c <= '9')
		{
			cp++;
			continue;
		}
		if (c == '\0')
			break;
		if (c == ' ')
		{
			*cp= '\0';
			break;
		}

		/* Bad character */
		return NULL;
	}
	if (cp-start > 5)
		return NULL;	/* Too long */
	return cp;
}

static char *skip_literal(char *start, const char *target)
{
	char c;
	size_t len;
	char *cp;

	len= strlen(target);
	if (memcmp(start, target, len) != 0)
		return NULL;	/* No match */
	cp= start+len;
	c= *cp;
	if (c == '\0')
		; /* Okay */
	else if (c == ' ')
		*cp= '\0';
	else
		return NULL;	/* Bad character */
	return cp;
}

static char *skip_hash_algorithm(char *start)
{
	return skip_literal(start, "md5");
}

static char *skip_hash(char *start)
{
	char *cp;
	char c;

	/* 0-9, A-F, a-f */
	cp= start;
	for (;;)
	{
		c= *cp;
		if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') ||
			(c >= 'a' && c <= 'f'))
		{
			cp++;
			continue;
		}
		if (c == '\0')
			break;
		if (c == ' ')
		{
			*cp= '\0';
			break;
		}

		/* Bad character */
		return NULL;
	}
	if (cp-start != 32)
		return NULL;	/* Wrong length */
	return cp;
}

static char *skip_filename(char *start)
{
	char *cp;
	char c;

	/* 0-9, a-z, '.', '-', '_' */
	cp= start;
	for (;;)
	{
		c= *cp;
		if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
			c == '.' || c == '-' || c == '_')
		{
			cp++;
			continue;
		}
		if (c == '\0')
			break;
		if (c == ' ')
		{
			*cp= '\0';
			break;
		}

		/* Bad character */
		return NULL;
	}
	if (cp-start > 64)
		return NULL;	/* Too long */
	return cp;
}

static char *skip_hostname(char *start)
{
	char *cp;
	char c;

	/* 0-9, a-z, '.', '-' */ 
	cp= start;
	for (;;)
	{
		c= *cp;
		if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
			c =='.' || c == '-')
		{
			cp++;
			continue;
		}
		if (c == '\0')
			break;
		if (c == ' ')
		{
			*cp= '\0';
			break;
		}

		/* Bad character */
		return NULL;
	}
	if (cp-start > 32)
		return NULL;	/* Too long */
	return cp;
}

static char *skip_ipv4address(char *start)
{
	char *cp;
	char c;

	/* 0-9, '.' */
	cp= start;
	for (;;)
	{
		c= *cp;
		if ((c >= '0' && c <= '9') || c == '.')
		{
			cp++;
			continue;
		}
		if (c == '\0')
			break;
		if (c == ' ')
		{
			*cp= '\0';
			break;
		}

		/* Bad character */
		return NULL;
	}
	if (cp-start > 16)
		return NULL;	/* Wrong length */
	return cp;
}

static char *skip_ipv6address(char *start)
{
	char *cp;
	char c;

	/* 0-9, A-F, a-f, ':' */
	cp= start;
	for (;;)
	{
		c= *cp;
		if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') ||
			(c >= 'a' && c <= 'f') || c == ':')
		{
			cp++;
			continue;
		}
		if (c == '\0')
			break;
		if (c == ' ')
		{
			*cp= '\0';
			break;
		}

		/* Bad character */
		return NULL;
	}
	if (cp-start > 40)
		return NULL;	/* Wrong length */
	return cp;
}

static char *skip_address(char *start)
{
	char *cp;

	cp= skip_ipv4address(start);
	if (cp)
		return cp;
	return skip_ipv6address(start);
}

static char *skip_hostname_or_address(char *start)
{
	char *cp;

	cp= skip_hostname(start);
	if (cp)
		return cp;
	return skip_address(start);
}

static char *skip_port(char *start)
{
	char *cp;
	char c;

	/* 0-9 */
	cp= start;
	for (;;)
	{
		c= *cp;
		if (c >= '0' && c <= '9')
		{
			cp++;
			continue;
		}
		if (c == '\0')
			break;
		if (c == ' ')
		{
			*cp= '\0';
			break;
		}

		/* Bad character */
		return NULL;
	}
	if (cp-start > 5)
		return NULL;	/* Wrong length */
	return cp;
}

static char *skip_key_type(char *start)
{
	return skip_literal(start, "ssh-rsa");
}

static char *skip_key_material(char *start)
{
	char *cp;
	char c;

	/* 0-9, A-Z, a-z, '+', '/', '=' */
	cp= start;
	for (;;)
	{
		c= *cp;
		if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') || c == '+' || c == '/' ||
			c == '=')
		{
			cp++;
			continue;
		}
		if (c == '\0')
			break;
		if (c == ' ')
		{
			*cp= '\0';
			break;
		}

		/* Bad character */
		return NULL;
	}
	if (cp-start > 512)
		return NULL;	/* Wrong length */
	return cp;
}

static char *skip_boolean(char *start)
{
	char *cp;

	cp= skip_literal(start, "True");
	if (cp)
		return cp;
	return skip_literal(start, "False");
}

static char *skip_prefixlen(char *start)
{
	char *cp;
	char c;

	/* 0-9 */
	cp= start;
	for (;;)
	{
		c= *cp;
		if (c >= '0' && c <= '9')
		{
			cp++;
			continue;
		}
		if (c == '\0')
			break;
		if (c == ' ')
		{
			*cp= '\0';
			break;
		}

		/* Bad character */
		return NULL;
	}
	if (cp-start > 3)
		return NULL;	/* Wrong length */
	return cp;
}

static int reg_init_main( int argc, char *argv[] )
{

	time_t mytime;
	size_t len;
	unsigned long seconds;
	FILE *read_from = stdin;
	char *cp, *ecp, *check, *path;

	int ret = 0;
	int first;

	int reregister_time = default_rereg_time;
	mytime = time(NULL);

	if (!str_device)
		str_device= "eth0";

	if( argc >1 ) {
		read_from = fopen( argv[0], "rt" );
		if( read_from==NULL ) {
			atlas_log( ERROR, "Cannot read from file %s\n", argv[1] );
			return 1;
		}
	}

	/* read OK */
	cp= fgets( line, sizeof(line), read_from );
	if (cp == NULL)
	{
		atlas_log( ERROR, "Read error\n");
		goto fail;
	}
	cp= strchr(line, '\n');
	if (cp == NULL)
	{
		atlas_log( ERROR, "Line too long\n");
		goto fail;
	}
	*cp= '\0';

	if( strcmp(line,"OK") == 0 ) {
		int l=1;
		int n_controller = 0;
		char *host_name;
		char *type;
		char *key;
		int do_rm_v4_static_info;
		int do_rm_v6_static_info;
		int do_rm_dns_static_info;

		do_rm_v4_static_info= 1;
		do_rm_v6_static_info= 1;
		do_rm_dns_static_info= 1;
		while( l<=max_lines ) {

			cp= fgets( line, sizeof(line), read_from );
			if (cp == NULL)
			{
				if (feof(read_from))
					break;

				atlas_log( ERROR, "Read error\n");
				goto fail;
			}
			cp= strchr(line, '\n');
			if (cp == NULL)
			{
				atlas_log( ERROR, "Line too long\n");
				goto fail;
			}
			*cp= '\0';
			len= strlen(line);

			cp= line;
			ecp= skip_tag(cp);
			if (ecp == NULL)
			{
				atlas_log( ERROR, "missing tag\n");
				goto fail;
			}

			if( strcmp(cp, "REGSERVER_TIMESTAMP")==0 ) {
				unsigned long regserver_time;

				cp= skip_spaces(ecp+1);
				ecp= skip_timestamp(cp);
				if (ecp == NULL)
				{
					atlas_log( ERROR,
						"missing timestamp\n");
					goto fail;
				}

				regserver_time= strtoul(cp, &check, 10);
				if (regserver_time == 0 ||
					regserver_time == ULONG_MAX ||
					check[0] != '\0')
				{
					atlas_log( ERROR,
						"bad timestamp\n");
					goto fail;
				}

				if (mytime < regserver_time-2 ||
					mytime > regserver_time+2)
				{
					struct timeval tval;

					atlas_log( INFO,
			"Time difference is %d seconds, setting time\n",
						(int)(mytime-regserver_time) );

					tval.tv_sec = regserver_time;
					tval.tv_usec = 0;
				 	settimeofday( &tval, NULL);
				}

				/* Skip the rest of the line */
			} 
			else if( strcmp(line,"FIRMWARE_KERNEL")==0 ) 
			{ 
				unsigned long root_fs_ver = 0;

				cp= skip_spaces(ecp+1);
				ecp= skip_version(cp);
				if (ecp == NULL)
				{
					atlas_log( ERROR,
						"missing kernel version\n");
					goto fail;
				}

				root_fs_ver= strtoul(cp, &check, 10);
				if (root_fs_ver == 0 ||
					root_fs_ver == ULONG_MAX ||
					check[0] != '\0')
				{
					atlas_log( ERROR,
						"bad kernel version\n");
					goto fail;
				}

				printf("FIRMWARE_KERNEL_VERSION %u\n",
					(unsigned)root_fs_ver);

				cp= skip_spaces(ecp+1);
				ecp= skip_hash_algorithm(cp);
				if (ecp == NULL)
				{
					atlas_log(ERROR, "missing hash alg.\n");
					goto fail;
				}
				printf("FIRMWARE_KERNEL_CS_ALG %s\n", cp);

				cp= skip_spaces(ecp+1);
				ecp= skip_hash(cp);
				if (ecp == NULL)
				{
					atlas_log(ERROR, "missing hash\n");
					goto fail;
				}

				printf("FIRMWARE_KERNEL_CS_COMP %s\n", cp);

				cp= skip_spaces(ecp+1);
				ecp= skip_hash(cp);
				if (ecp == NULL)
				{
					atlas_log(ERROR, "missing hash\n");
					goto fail;
				}

				printf("FIRMWARE_KERNEL_CS_UNCOMP %s\n", cp);

				cp= skip_spaces(ecp+1);
				ecp= skip_filename(cp);
				if (ecp == NULL)
				{
					atlas_log(ERROR, "missing filename\n");
					goto fail;
				}

				printf( "FIRMWARE_KERNEL %s\n", cp) ;

				if (ecp+1 < line+len)
				{
					cp= skip_spaces(ecp+1);
					if (cp != line+len)
					{
						atlas_log(ERROR,
						"garbage at end of line\n");
						goto fail;
					}
				}
			} 
			else if( strcmp(line,"FIRMWARE_APPS")==0 ) 
			{ 
				unsigned long root_fs_ver = 0;

				cp= skip_spaces(ecp+1);
				ecp= skip_version(cp);
				if (ecp == NULL)
				{
					atlas_log( ERROR,
						"missing app version\n");
					goto fail;
				}

				root_fs_ver= strtoul(cp, &check, 10);
				if (root_fs_ver == 0 ||
					root_fs_ver == ULONG_MAX ||
					check[0] != '\0')
				{
					atlas_log( ERROR, "bad app version\n");
					goto fail;
				}

				printf("FIRMWARE_APPS_VERSION %lu\n",
					root_fs_ver);

				cp= skip_spaces(ecp+1);
				ecp= skip_hash_algorithm(cp);
				if (ecp == NULL)
				{
					atlas_log(ERROR, "missing hash alg.\n");
					goto fail;
				}
				printf("FIRMWARE_APPS_CS_ALG %s\n", cp);

				cp= skip_spaces(ecp+1);
				ecp= skip_hash(cp);
				if (ecp == NULL)
				{
					atlas_log(ERROR, "missing hash\n");
					goto fail;
				}

				printf("FIRMWARE_APPS_CS_COMP %s\n", cp);

				cp= skip_spaces(ecp+1);
				ecp= skip_hash(cp);
				if (ecp == NULL)
				{
					atlas_log(ERROR, "missing hash\n");
					goto fail;
				}

				printf("FIRMWARE_APPS_CS_UNCOMP %s\n", cp);

				cp= skip_spaces(ecp+1);
				ecp= skip_filename(cp);
				if (ecp == NULL)
				{
					atlas_log(ERROR, "missing filename\n");
					goto fail;
				}

				printf( "FIRMWARE_APPS %s\n", cp) ;

				if (ecp+1 < line+len)
				{
					cp= skip_spaces(ecp+1);
					if (cp != line+len)
					{
						atlas_log(ERROR,
						"garbage at end of line\n");
						goto fail;
					}
				}
			} 
			else if( strcmp(line,"CONTROLLER")==0 ) {
				FILE *f;

				n_controller++;

				cp= skip_spaces(ecp+1);
				ecp= skip_hostname_or_address(cp);
				if (ecp == NULL)
				{
					atlas_log( ERROR,
						"missing hostname/address\n");
					goto fail;
				}

				host_name = cp;
				printf ("CONTROLLER_%d_HOST %s\n",
					n_controller, host_name);

				cp= skip_spaces(ecp+1);
				ecp= skip_port(cp);
				if (ecp == NULL)
				{
					atlas_log( ERROR, "missing port\n");
					goto fail;
				}
				printf ("CONTROLLER_%d_PORT %s\n",
					n_controller, cp);

				cp= skip_spaces(ecp+1);
				ecp= skip_key_type(cp);
				if (ecp == NULL)
				{
					atlas_log( ERROR, "missing key type\n");
					goto fail;
				}
				type = cp;

				cp= skip_spaces(ecp+1);
				ecp= skip_key_material(cp);
				if (ecp == NULL)
				{
					printf("bad key material in '%s'\n", cp);
					atlas_log( ERROR,
						"missing key material\n");
					goto fail;
				}
				key = cp;

				f = fopen( atlas_contr_known_hosts, "wt" );
				if( f==NULL ) {
		         		atlas_log( ERROR,
					"Unable to append to file %s\n",
						atlas_contr_known_hosts );
					goto fail;
				}
				fprintf( f, "%s %s %s\n", host_name, type, key);
				fprintf (f, "ipv4.%s %s %s\n", host_name, type, key);
				fprintf (f, "ipv6.%s %s %s\n", host_name, type, key);
				fclose(f);

				if (ecp+1 < line+len)
				{
					cp= skip_spaces(ecp+1);
					if (cp != line+len)
					{
						atlas_log(ERROR,
						"garbage at end of line\n");
						goto fail;
					}
				}
			}
			else if( strcmp(line,"REREGISTER")==0 ) 
			{
				cp= skip_spaces(ecp+1);
				ecp= skip_version(cp);
				if (ecp == NULL)
				{
					atlas_log( ERROR,
						"missing seconds field\n");
					goto fail;
				}

				reregister_time= strtoul(cp, &check, 10);
				if (reregister_time == 0 ||
					reregister_time == ULONG_MAX ||
					check[0] != '\0')
				{
					atlas_log( ERROR,
						"bad seconds field\n");
					goto fail;
				}

				process_wait("REREG_TIMER", reregister_time);
				if (ecp+1 < line+len)
				{
					cp= skip_spaces(ecp+1);
					if (cp != line+len)
					{
						atlas_log(ERROR,
						"garbage at end of line\n");
						goto fail;
					}
				}
			} 
			else if( strcmp(line,"DHCPV4")==0 )
			{
				FILE *f= NULL;
				char *ipv4_address;
				char *netmask;
				char *broadcast;
				char *ipv4_gw;

				cp= skip_spaces(ecp+1);
				ecp= skip_boolean(cp);
				if (ecp == NULL)
				{
					atlas_log( ERROR,
						"missing boolean\n");
					goto fail;
				}

				if (strcmp(cp, "True") == 0)
				{
					/* Nothing more to do */
					goto dhcpv4_end;
				}

				// Statically configured probe.
//DHCPV4 False IPV4ADDRESS 10.0.0.151 IPV4NETMASK 255.255.255.0 IPV4NETWORK 10.0.0.0 IPV4BROADCAST 10.0.0.255 IPV4GATEWAY 10.0.0.137

				cp= skip_spaces(ecp+1);
				ecp= skip_literal(cp, "IPV4ADDRESS");
				if (ecp == NULL)
				{
					atlas_log( ERROR,
						"missing IPV4ADDRESS\n");
					goto fail;
				}

				cp= skip_spaces(ecp+1);
				ecp= skip_ipv4address(cp);
				if (ecp == NULL)
				{
					atlas_log( ERROR,
						"missing IPv4 address\n");
					goto fail;
				}

				ipv4_address = cp;

				cp= skip_spaces(ecp+1);
				ecp= skip_literal(cp, "IPV4NETMASK");
				if (ecp == NULL)
				{
					atlas_log( ERROR,
						"missing IPV4NETMASK\n");
					goto fail;
				}

				cp= skip_spaces(ecp+1);
				ecp= skip_ipv4address(cp);
				if (ecp == NULL)
				{
					atlas_log( ERROR,
						"missing IPv4 netmask\n");
					goto fail;
				}

				netmask = cp;	

				cp= skip_spaces(ecp+1);
				ecp= skip_literal(cp, "IPV4NETWORK");
				if (ecp == NULL)
				{
					atlas_log( ERROR,
						"missing IPV4NETWORK\n");
					goto fail;
				}

				cp= skip_spaces(ecp+1);
				ecp= skip_ipv4address(cp);
				if (ecp == NULL)
				{
					atlas_log( ERROR,
						"missing IPv4 network\n");
					goto fail;
				}

				cp= skip_spaces(ecp+1);
				ecp= skip_literal(cp, "IPV4BROADCAST");
				if (ecp == NULL)
				{
					atlas_log( ERROR,
						"missing IPV4BROADCAST\n");
					goto fail;
				}

				cp= skip_spaces(ecp+1);
				ecp= skip_ipv4address(cp);
				if (ecp == NULL)
				{
					atlas_log( ERROR,
						"missing IPv4 broadcast\n");
					goto fail;
				}

				broadcast = cp;

				cp= skip_spaces(ecp+1);
				ecp= skip_literal(cp, "IPV4GATEWAY");
				if (ecp == NULL)
				{
					atlas_log( ERROR,
						"missing IPV4GATEWAY\n");
					goto fail;
				}

				cp= skip_spaces(ecp+1);
				ecp= skip_ipv4address(cp);
				if (ecp == NULL)
				{
					atlas_log( ERROR,
						"missing IPv4 gateway\n");
					goto fail;
				}

				ipv4_gw = cp;
		
				f = fopen(atlas_netconfig_v4, "wt");

				if( f==NULL ) {
                                        atlas_log( ERROR, "Unable to create  %s\n", atlas_netconfig_v4 );
                                        goto fail;
                                }
	
			 	fprintf (f, "/sbin/ifconfig %s 0.0.0.0\n",
					str_device);
			 	fprintf (f, "/sbin/ifconfig %s:1 %s ",
					str_device, ipv4_address);
			 	fprintf (f, "netmask %s ", netmask);
			 	fprintf (f, "broadcast %s \n", broadcast); 
			 	fprintf (f, "/sbin/route add default gw %s\n",
					ipv4_gw); 

				// put parts in the shell script to make network info file

				fprintf (f, "IPV4_LOCAL_ADDR=%s\n",
					ipv4_address);
				fprintf (f, "IPV4_NETMASK=%s\n", netmask);
				fprintf (f, "IPV4_BROADCAST=%s\n", broadcast);
				fprintf (f, "IPV4_GW=%s\n",ipv4_gw);
				fprintf (f, "DHCP=False\n");
				
#if 0
				// second file for static 
				fprintf (f, "STATIC_IPV4_LOCAL_ADDR=%s\n",
					ipv4_address);
				fprintf (f, "STATIC_IPV4_NETMASK=%s\n",
					netmask);
				fprintf (f, "STATIC_IPV4_BROADCAST=%s\n",
					broadcast);
				fprintf (f, "STATIC_IPV4_GW=%s\n", ipv4_gw);
				fprintf (f, "IPV4_GW=%s; export IPV4_GW\n", ipv4_gw);
#endif

				path= atlas_path(
					NETWORK_V4_STATIC_INFO_JSON_REL);
				fprintf(f, "echo '"
					DBQ(static-inet-addresses) " : [ { "
					DBQ(inet-addr) ": " DBQ(%s) ", "
					DBQ(netmask) ": " DBQ(%s) ", "
					DBQ(interface) ": " DBQ(%s)
					" } ], "
					DBQ(static-inet-routes) " : [ { "
					DBQ(destination) ": " DBQ(0.0.0.0) ", "
					DBQ(netmask) ": " DBQ(0.0.0.0) ", "
					DBQ(next-hop) ": " DBQ(%s) ", "
					DBQ(interface) ": " DBQ(%s)
					" } ]' > %s\n",
					ipv4_address,
					netmask,
					str_device,
					ipv4_gw,
					str_device,
					path);
				free(path); path= NULL;

				fclose(f);

				do_rm_v4_static_info= 0;

				/* Fall through */
dhcpv4_end:
				if (ecp+1 < line+len)
				{
					cp= skip_spaces(ecp+1);
					if (cp != line+len)
					{
						atlas_log(ERROR,
						"garbage at end of line\n");
						goto fail;
					}
				}
			}
			else if( strcmp(line,"DHCPV6")==0 ) 
			{
				FILE *f = NULL;
				char *ipv6_address;
				char *prefixlen;
				char *ipv6_gw;

				cp= skip_spaces(ecp+1);
				ecp= skip_boolean(cp);
				if (ecp == NULL)
				{
					atlas_log( ERROR,
						"missing boolean\n");
					goto fail;
				}

				if (strcmp(cp, "True") == 0)
				{
					/* Nothing more to do */
					goto dhcpv6_end;
				}

				// Statically configured probe.

				cp= skip_spaces(ecp+1);
				ecp= skip_literal(cp, "IPV6ADDRESS");
				if (ecp == NULL)
				{
					atlas_log( ERROR,
						"missing IPV6ADDRESS\n");
					goto fail;
				}

				cp= skip_spaces(ecp+1);
				ecp= skip_ipv6address(cp);
				if (ecp == NULL)
				{
					atlas_log( ERROR,
						"missing IPv6 address\n");
					goto fail;
				}

				ipv6_address = cp;

				cp= skip_spaces(ecp+1);
				ecp= skip_literal(cp, "IPV6PREFIXLEN");
				if (ecp == NULL)
				{
					atlas_log( ERROR,
						"missing IPV6PREFIXLEN\n");
					goto fail;
				}

				cp= skip_spaces(ecp+1);
				ecp= skip_prefixlen(cp);
				if (ecp == NULL)
				{
					atlas_log( ERROR,
						"missing IPv6 prefixlen\n");
					goto fail;
				}

				prefixlen = cp;	

				cp= skip_spaces(ecp+1);
				ecp= skip_literal(cp, "IPV6GATEWAY");
				if (ecp == NULL)
				{
					atlas_log( ERROR,
						"missing IPV6GATEWAY\n");
					goto fail;
				}

				cp= skip_spaces(ecp+1);
				ecp= skip_ipv6address(cp);
				if (ecp == NULL)
				{
					atlas_log( ERROR,
						"missing IPv6 address\n");
					goto fail;
				}

				ipv6_gw = cp;

				f = fopen(atlas_netconfig_v6, "wt");
				if( f==NULL ) {
                                        atlas_log( ERROR, "Unable to create  %s\n", atlas_netconfig_v6 );
					goto fail;
                                }
	
			 	fprintf  (f, "/sbin/ifconfig %s 0.0.0.0\n",
					str_device);
			 	fprintf  (f, "/sbin/ifconfig %s %s/%s\n",
					str_device, ipv6_address, prefixlen);
			 	fprintf (f,
			"/sbin/route -A inet6 add default gw %s dev %s\n",
					ipv6_gw, str_device); 
#if 0
				// second file for static  network info
				fprintf (f, "echo \"STATIC_IPV6_LOCAL_ADDR %s/%s\" >    %s \n", ipv6_address, prefixlen);
				fprintf (f, "echo \"STATIC_IPV6_GW %s\" >>    %s \n",ipv6_gw );
#endif

				path= atlas_path(
					NETWORK_V6_STATIC_INFO_JSON_REL);
				fprintf(f, "echo '"
					DBQ(static-inet6-addresses) ": [ { "
					DBQ(inet6-addr) ": " DBQ(%s) ", "
					DBQ(prefix-length) ": %s, "
					DBQ(interface) ": " DBQ(%s) " } ], "
					DBQ(static-inet6-routes) ": [ { "
					DBQ(destination) ": " DBQ(::) ", "
					DBQ(prefix-length) " : 0, "
					DBQ(next-hop) ": " DBQ(%s) ", "
					DBQ(interface) ": " DBQ(%s) " } ]"
					"' > %s\n",
					ipv6_address, prefixlen, str_device,
					ipv6_gw, str_device,
					path);
				free(path); path= NULL;
			

				fclose(f);
				do_rm_v6_static_info= 0;

				/* Fall through */

dhcpv6_end:
				if (ecp+1 < line+len)
				{
					cp= skip_spaces(ecp+1);
					if (cp != line+len)
					{
						atlas_log(ERROR,
						"garbage at end of line\n");
						goto fail;
					}
				}
			}
			else if( strcmp(line,"DNS_SERVERS")==0 ) 
			{
				FILE *f, *f2;
				// FILE *f1;

				f = fopen(atlas_resolv_conf, "wt");
				if( f==NULL ) {
                                        atlas_log(ERROR,
						"Unable to create  %s\n",
						atlas_resolv_conf );
                                        return 1;
                                }

#if 0
				f1 = fopen(atlas_network_dns_static_info, "wt");
				if( f1==NULL ) {
                                        atlas_log(ERROR,
						"Unable to create  %s\n",
						atlas_network_dns_static_info);
					fclose(f);
                                        return 1;
                                }
#endif

				path= atlas_path(
					NETWORK_DNS_STATIC_INFO_JSON_REL);
				f2 = fopen(path, "wt");
				if( f2==NULL ) {
                                        atlas_log(ERROR,
						"Unable to create  %s\n",
						path);
					free(path); path= NULL;
					fclose(f);
                                        return 1;
                                }
				free(path); path= NULL;

				// Statically configured probe.
				//DNS_SERVERS 8.8.8.8 194.109.6.66

				cp= skip_spaces(ecp+1);
				ecp= skip_address(cp);
				if (ecp == NULL)
				{
					atlas_log( ERROR,
						"missing address\n");
					fclose(f);
					fclose(f2);
                                        return 1;
				}

				fprintf(f2, DBQ(static-dns) ": [ ");

				first= 1;
				for (;;)
				{
			 		fprintf (f, "nameserver %s\n", cp);
					fprintf(f2, "%s{ " DBQ(nameserver) ": "
						DBQ(%s) " }",
						first ? "" : ", ", cp);
					first= 0;

					if (ecp+1 >= line+len)
						break;
					cp= skip_spaces(ecp+1);
					if (*cp == '\0')
						break;

					ecp= skip_address(cp);
					if (ecp == NULL)
					{
						atlas_log( ERROR,
							"missing address\n");
						fclose(f);
						fclose(f2);
						return 1;
					}
				}
				fprintf(f2, " ]\n");

				fclose(f);
				fclose(f2);

				do_rm_dns_static_info= 0;
			}
			l++;
		}
		if(do_rm_v4_static_info)
		{
			// delete the static configuration 
			unlink(atlas_netconfig_v4);
			path= atlas_path(NETWORK_V4_STATIC_INFO_JSON_REL);
			unlink(path);
			free(path); path= NULL;
		}
		if(do_rm_v6_static_info)
		{
			// delete the static configuration 
			unlink(atlas_netconfig_v6);
			path= atlas_path(NETWORK_V6_STATIC_INFO_JSON_REL);
			unlink(path);
			free(path); path= NULL;
		}
		if (do_rm_dns_static_info)
		{
			// unlink(atlas_network_dns_static_info);
			unlink(atlas_resolv_conf);
			path= atlas_path(NETWORK_DNS_STATIC_INFO_JSON_REL);
			unlink(path);
			free(path); path= NULL;
		}
	}
	else if  (strcmp(line,"WAIT") == 0 ) 
	{
		cp= fgets( line, sizeof(line), read_from );
		if (cp == NULL)
		{
			if (feof(read_from))
			{
				atlas_log( ERROR, "Unexepcted EOF\n");
				goto fail;
			}

			atlas_log( ERROR, "Read error\n");
			goto fail;
		}
		cp= strchr(line, '\n');
		if (cp == NULL)
		{
			atlas_log( ERROR, "Line too long\n");
			goto fail;
		}
		*cp= '\0';
		len= strlen(line);

		cp= line;
		ecp= skip_literal(cp, "TIMEOUT");
		if (ecp == NULL)
		{
			atlas_log( ERROR, "missing keyword TIMEOUT\n");
			goto fail;
		}

		cp= skip_spaces(ecp+1);
		ecp= skip_seconds(cp);
		if (ecp == NULL)
		{
			atlas_log( ERROR, "missing seconds value\n");
			goto fail;
		}

		seconds= strtoul(cp, &check, 10);
		if (seconds == 0 || seconds == ULONG_MAX ||
			check[0] != '\0')
		{
			atlas_log( ERROR,
				"bad seconds value\n");
			goto fail;
		}

		if (ecp+1 < line+len)
		{
			cp= skip_spaces(ecp+1);
			if (cp != line+len)
			{
				atlas_log(ERROR,
				"garbage at end of line\n");
				goto fail;
			}
		}

		process_wait("REG_WAIT_UNTIL", seconds);
	}	
	else  {
		char *p = strchr(line,'\n');
		if( p!=NULL ) *p = '\0';
		atlas_log( ERROR, "OK expected, got \"%s\" instead\n", line );
		process_wait("REG_WAIT_UNTIL", ATLAS_DEFAULT_WAIT); /* we got error the only action from probe is wait. so force it*/
		ret = 1;
	}
	return ret;

fail:
	if (read_from != stdin)
		fclose(read_from);
	return 1;
}


void atlas_log( int level UNUSED_PARAM, const char *msg UNUSED_PARAM, ... )
{
/*
	if( atlas_log_level<=level )
	{
		va_list arg;
		va_start ( arg, msg );

		FILE *lf = fopen( atlas_log_file, "at" );
		if( lf==NULL )
			return; // not much we can do

		fprintf( lf, "%d\t%d\t", (int)time(NULL), level );
		vfprintf( lf, msg, arg );
		fclose(lf);

		va_end( arg );
	}
*/
}
