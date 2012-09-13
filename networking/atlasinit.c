/* RIPEAtlas
 * All the configurable variables - and some non configurables too
 * Usage1: ./init_resp_parse < init_messagefile
 * Usage2: ./init_resp_parse init_messagefile
 * $Id: $
 */


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
#define OPT_STRING "rcdsi:"
#define ATLAS_WAIT 0

enum 
{
	OPT_REG_INIT	= (1 << 0),  /* r */
	OPT_CNT_INIT	= (1 << 1),  /* c */
	OPT_CNT_HELLO	= (1 << 2),  /* d */
	OPT_SINCELAST   = (1 << 3),  /* s */
	OPT_P_TO_R_INIT = (1 << 4),  /* i */
};

/*********************************************************************
 * Set these constants to your liking
 */
static int read_wait (FILE *read_from, const char *type, int waittime);
static int reg_init_main( int argc, char *argv[] );
static int con_hello_main( int argc, char *argv[] );
static int con_init_main( int argc, char *argv[] );
static void since_last_main (int argc, char *argv[]);
static void print_token_ver (FILE * write_to, int flag_rereg);

const char atlas_log_file[]="./probe.log";
const int atlas_log_level=INFO;

const char atlas_contr_known_hosts[]="./known_hosts_controllers";
const char atlas_rereg_timestamp[]="./rereg_time.sh";
const char atlas_con_hello[]="./con_hello.txt";
const char atlas_con_session_id[]="./con_session_id.txt";
const char atlas_force_reg[] = "./force_reg.sh";
const char atlas_netconfig_v4[] = "./netconfig_v4.vol";
const char atlas_netconfig_v6[] = "./netconfig_v6.vol";
const char atlas_resolv_conf[] = "./resolv.conf.vol";
const char atlas_network_v4_info[] = "/home/atlas/status/network_v4_info.txt";
const char atlas_network_v4_static_info[] = "/home/atlas/status/network_v4_static_info.txt";
const char atlas_network_v6_static_info[] = "/home/atlas/status/network_v6_static_info.txt";
const char atlas_network_dns_static_info[] = "/home/atlas/status/network_dns_static_info.txt";

const int max_lines = 16; /* maximum lines we'll process */
const int min_rereg_time = 100; 
const int max_rereg_time = 28*24*3600; /* 28d */
const int default_rereg_time = 7*24*3600; /* 7d */
char *str_reason;

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
		opt = getopt32(argv, OPT_STRING, &str_reason);
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
	else if(opt & OPT_CNT_HELLO)
	{
		con_hello_main(argc, argv);
	}
	else if ( opt & OPT_CNT_INIT) 
	{
		con_init_main(argc, argv);
		
	}
	else if (opt & OPT_SINCELAST)
	{
		since_last_main(argc, argv);
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
FILE *fpv = fopen("/home/atlas/state/FIRMWARE_APPS_VERSION", "r");
	char *my_mac ;

bzero( line, ATLAS_BUF_SIZE );
fscanf (fp, "%s", line);
fscanf (fp, "%s", line);
fscanf (fp, "%s", line);
if(fpv)
	fscanf (fpv, "%f", &root_fs_ver);
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

static void since_last_main (int argc, char *argv[])
{
	FILE *thenfile;
	int then;
	time_t mytime;

        mytime = time(0);

        if ( argc == 1) {
                printf("%d\n", (int)mytime);
        }
        else {
                if ((thenfile = fopen(argv[0], "r")) == NULL) {
                        printf("%d\n", (int)mytime);
                }
                else {
                        fscanf(thenfile, "%d", &then);
                        printf("%d\n", (int)(mytime - then));
                }
        }
}

static int con_hello_main( int argc, char *argv[] )
{
	/* read response from P_TO_C_HELLO  */
	FILE *read_from = stdin;
	int ret = 0;
	long tmp_long;

	time_t mytime = time(0);
	time_t con_time;
	 if( argc > 1 ) {
                read_from = fopen( argv[0], "rt" );
                if( read_from==NULL ) {
                        atlas_log( ERROR, "Cannot read from file %s\n", argv[1] );
                        return 1;
                }
        }
	/* read OK */
        bzero( line, ATLAS_BUF_SIZE );
        fgets( line, MAX_READ, read_from );

        if( strncmp(line,"OK\n",3) == 0 ) {
        	int l=1;
		bzero( line, ATLAS_BUF_SIZE );
        	fgets( line, MAX_READ, read_from );
       		while( !feof(read_from) && l<=max_lines ) {
                	if( strncmp(line,"CONTROLLER_TIMESTAMP ", 21)==0 ) {
				int timediff2 ;

			 	sscanf( line+21, "%d", &tmp_long);
				con_time= tim_long;
				timediff2 = ( mytime - con_time )  *  ( mytime - con_time );
				printf ("Mytime %d controller time %d\n",(int)mytime , (int)con_time);
				if( timediff2 > 4 ) {
					struct timeval tval;

					atlas_log( INFO, "Time difference is %d seconds, set time ?\n", timediff2);
					printf  ("Set mytime \n");
					tval.tv_sec = con_time;
					tval.tv_usec = 0;
					settimeofday( &tval, NULL);
				}

			}
			bzero( line, ATLAS_BUF_SIZE );
        		fgets( line, MAX_READ, read_from );
        		l++;
		}
	}
	else  { 
		fprintf (stderr, "P_TO_C_HELLO response is unexptedte %s\n", line);
        }
	
	if (argc > 1 ) 
		fclose (read_from);
	return ret;
} 
static int con_init_main( int argc, char *argv[] )
{
	FILE *read_from = stdin;
	int ret = 0;

	int remote_port;
	 if( argc > 1 ) {
                read_from = fopen( argv[0], "rt" );
                if( read_from==NULL ) {
                        atlas_log( ERROR, "Cannot read from file %s\n", argv[1] );
                        return 1;
                }
        }
	/* read OK */
        bzero( line, ATLAS_BUF_SIZE );
        fgets( line, MAX_READ, read_from );

        if( strncmp(line,"OK\n",3) == 0 ) {
        	int l=1;
		bzero( line, ATLAS_BUF_SIZE );
        	fgets( line, MAX_READ, read_from );
       		while( !feof(read_from) && l<=max_lines ) {
                	if( strncmp(line,"REMOTE_PORT", 11)==0 ) {
			 	sscanf( line+11, "%d", &remote_port);
				printf ("REMOTE_PORT=%d\n", remote_port);
			}
			else if ( strncmp(line,"SESSION_ID", 10)==0 ) 
			{
				FILE *f = fopen( atlas_con_hello, "wt" );
			        FILE *f1  = fopen( atlas_con_session_id, "wt" );

				fprintf  (f, "P_TO_C_HELLO\nSESSION_ID %s", line+11);
				fprintf  (f1, "SESSION_ID %s\n", line+11);
				print_token_ver (f, 0 );
				fclose (f);
				fclose (f1);
	
			}
			bzero( line, ATLAS_BUF_SIZE );
        		fgets( line, MAX_READ, read_from );
        		l++;
		}
	}
	else if  (strncmp(line,"WAIT\n",5) == 0 ) 
	{
		read_wait(read_from, "CON_WAIT_TIMER", ATLAS_WAIT);
	}	
	else if  (strncmp(line,"REFUSED\n",8) == 0 )
	{
		FILE *f = fopen( atlas_force_reg, "wt" );

		unlink(atlas_con_hello);
		bzero( line, ATLAS_BUF_SIZE );
        	fgets( line, MAX_READ, read_from );
		fprintf (f,"REASON=%s\n", line+8);
		fclose(f);
		
	}
	else  {
		char *p = strchr(line,'\n');
                if( p!=NULL ) *p = '\0';
                atlas_log( ERROR, "OK expected, got \"%s\" instead\n", line );
		read_wait(read_from, "CON_WAIT_TIMER", ATLAS_DEFAULT_WAIT); /* we got error the only action from probe is wait. so force it*/
                ret = 1;
        }
	
	if (argc > 1 ) 
		fclose (read_from);
	return ret;

} 
static int read_wait (FILE *read_from, const char *type, int waittime)
{
	unsigned delay;
	time_t mytime = time(0);
	if(waittime < 1)
	{
		bzero( line, ATLAS_BUF_SIZE );
        	fgets( line, MAX_READ, read_from );
		if( strncmp(line,"TIMEOUT", 7)==0 ) {
        		sscanf( line+7, "%d", &delay);
		}
		else 
		{
			delay = ATLAS_DEFAULT_WAIT;
		}
	}
	else 
	{
		delay = waittime;
	}
	mytime = time(0);
	if(delay >  max_rereg_time ) {
               	atlas_log( ERROR, "Reregister time %d is too high\n", delay );
               	delay = max_rereg_time;
        }
	if(delay <  min_rereg_time ) {
               	atlas_log( ERROR, "Reregister time %d is too high\n", delay );
               	delay = min_rereg_time;
        }
	printf ("%s=%u\n", type, (uint)(mytime + delay));
	return (delay);
}

static int reg_init_main( int argc, char *argv[] )
{

	time_t mytime;
	FILE *read_from = stdin;

	char *token;
	const char *search = " ";
	const char *search_nl = " \n";
	int ret = 0;

	int reregister_time = default_rereg_time;
	mytime = time(NULL);

	if( argc > 1 ) {
		read_from = fopen( argv[0], "rt" );
		if( read_from==NULL ) {
			atlas_log( ERROR, "Cannot read from file %s\n", argv[1] );
			return 1;
		}
	}

	/* read OK */
	bzero( line, ATLAS_BUF_SIZE );
	fgets( line, MAX_READ, read_from );

	if( strncmp(line,"OK\n",3) == 0 ) {
		int l=1;
		int n_controller = 0;
		char *host_name;
		char *type;
		char *key;
		int do_rm_dns_static_info;

		bzero( line, ATLAS_BUF_SIZE );
		fgets( line, MAX_READ, read_from );

		do_rm_dns_static_info= 1;
		while( !feof(read_from) && l<=max_lines ) {
			if( strncmp(line,"CONTROLLER ", 11)==0 ) {
				FILE *f;
				char *ptr;

				n_controller++;
				/* TODO: one can check whether it's about the right length and syntax */

				ptr = strchr( line+11, ' ' );
				if( ptr==NULL ) {
					atlas_log( ERROR, "CONTROLLER line is suspicious (line %d)\n", l );
					return 1;
				}
				f = fopen( atlas_contr_known_hosts, "wt" );
				if( f==NULL ) {
		         		atlas_log( ERROR, "Unable to append to file %s\n", atlas_contr_known_hosts );
					return 1;
				}
				//fprintf( f, "%s\n", line+11 );
				token = strtok(line+11, search);
				/* host name */
				printf ("CONTROLLER_%d_HOST=%s\n", n_controller, token);
				fprintf( f, "%s ", token);
				host_name = token;

				token = strtok(NULL, search);
				printf ("CONTROLLER_%d_PORT=%s\n", n_controller, token);
				token = strtok(NULL, search);
				fprintf( f, "%s ", token);
				type = token; 
				token = strtok(NULL, search);
				fprintf( f, "%s\n", token);
				key = token;
				fprintf (f, "ipv4.%s %s %s\n", host_name, type, key);
				fprintf (f, "ipv6.%s %s %s\n", host_name, type, key);
				fclose(f);

			} 
			else if( strncmp(line,"REREGISTER ", 11)==0 ) 
			{
				sscanf( line+11, "%d", &reregister_time );
				read_wait(read_from, "REREG_TIMER", reregister_time);

			} 
			else if( strncmp(line,"REGSERVER_TIMESTAMP ", 20)==0 ) {
				int regserver_time;
				int timediff2 ;

				sscanf( line+20, "%d", &regserver_time );
				timediff2 = ( mytime - regserver_time )  *  ( mytime - regserver_time );
				if( timediff2 > 4 ) {
					struct timeval tval;

					atlas_log( INFO, "Time difference is %d seconds, what to do now?\n", (int)(mytime-regserver_time) );

					tval.tv_sec = regserver_time;
					tval.tv_usec = 0;
				 	settimeofday( &tval, NULL);
				}
			} 
			else if( strncmp(line,"FIRMWARE_KERNEL ", 16)==0 ) 
			{ 
				float root_fs_ver = 0;
				token = strtok (line+16, search);  // version
				sscanf (token, "%f", &root_fs_ver);
				root_fs_ver *= 1000.0;
				printf("FIRMWARE_KERNEL_VERSION=%d\n", (int)root_fs_ver);
				token = strtok(NULL, search);      // alg
				printf("FIRMWARE_KERNEL_CS_ALG=%s\n", token);

				token = strtok(NULL, search);      // comp hash 
				printf("FIRMWARE_KERNEL_CS_COMP=%s\n", token);

				token = strtok(NULL, search);      // uncomp hash

				printf("FIRMWARE_KERNEL_CS_UNCOMP=%s\n", token);
				token = strtok(NULL, search);      // url hash 
				printf( "FIRMWARE_KERNEL=%s\n", token) ;

			} 
			else if( strncmp(line,"FIRMWARE_APPS ", 14)==0 ) 
			{ 
				float root_fs_ver = 0;
				token = strtok (line+14, search);  // version
				sscanf (token, "%f", &root_fs_ver);
				root_fs_ver *= 1000.0;
				printf("FIRMWARE_APPS_VERSION=%d\n", (int)root_fs_ver); 
				token = strtok(NULL, search);      // alg
				printf("FIRMWARE_APPS_CS_ALG=%s\n", token);

				token = strtok(NULL, search);      // comp hash 
				printf("FIRMWARE_APPS_CS_COMP=%s\n", token);

				token = strtok(NULL, search);      // uncomp hash 

				printf("FIRMWARE_APPS_CS_UNCOMP=%s\n", token);
				token = strtok(NULL, search);      // url hash 
				printf( "FIRMWARE_APPS=%s\n", token) ;

			} 

			else if( strncmp(line,"DHCPV4 True ", 12)==0 ) 
			{
				// delete the static configuration 
				unlink(atlas_netconfig_v4);
			}
			else if( strncmp(line,"DHCPV4 False ", 13)==0 ) 
			{
				FILE *f = fopen(atlas_netconfig_v4, "wt");
				char *ipv4_address;
				char *netmask;
				char *broadcast; 
				char *ipv4_gw;

				if( f==NULL ) {
                                        atlas_log( ERROR, "Unable to create  %s\n", atlas_netconfig_v4 );
                                        return 1;
                                }
	
				// Statically configured probe.
//DHCPV4 False IPV4ADDRESS 10.0.0.151 IPV4NETMASK 255.255.255.0 IPV4NETWORK 10.0.0.0 IPV4BROADCAST 10.0.0.255 IPV4GATEWAY 10.0.0.137
				// fprintf (f, "%s\n", line);
				token = strtok(line+13, search); //IPV4ADDRESS 
				token = strtok(NULL, search);      // <address>
			 	fprintf (f, "/sbin/ifconfig eth0 0.0.0.0\n");
			 	fprintf (f, "/sbin/ifconfig eth0:1 %s ", token);
				ipv4_address = token;
				token = strtok(NULL, search);      // IPV4NETMASK
				token = strtok(NULL, search);      // 
			 	fprintf (f, "netmask %s ", token);
				netmask = token;	
				token = strtok(NULL, search);      // IPV4NETWORK
				token = strtok(NULL, search);      // 
				token = strtok(NULL, search);      // IPV4BROADCAST
				token = strtok(NULL, search);      // 
			 	fprintf (f, "broadcast %s \n", token); 
				broadcast = token;
				token = strtok(NULL, search);      // IPV4GATEWAY
				token = strtok(NULL, search);      // 
			 	fprintf (f, "/sbin/route add default gw %s\n", token); 
				ipv4_gw = token;
				ipv4_gw[(strlen(ipv4_gw) - 1)] = '\0';
		
				// put parts in the shell script to make network info file

				fprintf (f, "echo \"P_TO_C_NETWORK_UPDATE\" >  %s \n", atlas_network_v4_info );
				fprintf (f, "echo \"IPV4_LOCAL_ADDR %s\" >>    %s \n", ipv4_address, atlas_network_v4_info );
				fprintf (f, "echo \"IPV4_NETMASK %s\" >>    %s \n", netmask, atlas_network_v4_info );
				fprintf (f, "echo \"IPV4_BROADCAST %s\" >>    %s \n", broadcast, atlas_network_v4_info );
				fprintf (f, "echo \"IPV4_GW %s\" >>    %s \n",ipv4_gw , atlas_network_v4_info );
				fprintf (f, "echo \"DHCP False \" >>    %s \n", atlas_network_v4_info );
				
				
				// second file for static 
				fprintf (f, "echo \"STATIC_IPV4_LOCAL_ADDR %s\" >    %s \n", ipv4_address, atlas_network_v4_static_info );
				fprintf (f, "echo \"STATIC_IPV4_NETMASK %s\" >>    %s \n", netmask, atlas_network_v4_static_info );
				fprintf (f, "echo \"STATIC_IPV4_BROADCAST %s\" >>    %s \n", broadcast, atlas_network_v4_static_info );
				fprintf (f, "echo \"STATIC_IPV4_GW %s\" >>    %s \n",ipv4_gw , atlas_network_v4_static_info );
				// ping the gateway 
				fprintf (f, "ping -c 2 -q %s \n", ipv4_gw);
				fprintf (f, "IPV4_GW=%s; export $IPV4_GW\n", ipv4_gw);

				fclose(f);
			}
			//DHCPV6 False  IPV6ADDRESS <address> IPV6PREFIXLEN <prefix> IPV6GATEWAY <gateway>]| [DHCPV6 True ]
			else if( strncmp(line,"DHCPV6 True ", 12)==0 ) 
			{
				// delete the static configuration 
				unlink(atlas_netconfig_v6);
			}
			else if( strncmp(line,"DHCPV6 False ", 13)==0 ) 

			{
				FILE *f = fopen(atlas_netconfig_v6, "wt");
				char *ipv6_address;
				char *prefixlen;
				char *ipv6_gw;

				if( f==NULL ) {
                                        atlas_log( ERROR, "Unable to create  %s\n", atlas_netconfig_v6 );
                                        return 1;
                                }
	
				// Statically configured probe.

				//fprintf (f, "%s\n", line);
				token = strtok(line+13, search); //IPV6ADDRESS
				token = strtok(NULL, search);      // <address>
				ipv6_address = token;
				token = strtok(NULL, search);      // IPV6PREFIXLEN
				token = strtok(NULL, search);      // 
				prefixlen = token;	
			 	fprintf  (f, "/sbin/ifconfig eth0 0.0.0.0\n");
			 	fprintf  (f, "/sbin/ifconfig eth0 %s/%s\n", ipv6_address, prefixlen);

				token = strtok(NULL, search);      // IPV6GATEWAY
				token = strtok(NULL, search);      // 
				ipv6_gw = token;
				ipv6_gw[(strlen(ipv6_gw) - 1)] = '\0';
				///sbin/route -A inet6 add default gw fe80::13:0:0:1 dev eth0
			 	fprintf (f, "/sbin/route -A inet6 add default gw %s dev eth0\n", ipv6_gw); 
				// second file for static  network info
				fprintf (f, "echo \"STATIC_IPV6_LOCAL_ADDR %s/%s\" >    %s \n", ipv6_address, prefixlen, atlas_network_v6_static_info );
				fprintf (f, "echo \"STATIC_IPV6_GW %s\" >>    %s \n",ipv6_gw , atlas_network_v6_static_info );

				fclose(f);

			}
			else if( strncmp(line,"DNS_SERVERS ", 11)==0 ) 
			{
				FILE *f, *f1;

				f = fopen(atlas_resolv_conf, "wt");
				if( f==NULL ) {
                                        atlas_log(ERROR,
						"Unable to create  %s\n",
						atlas_resolv_conf );
                                        return 1;
                                }

				f1 = fopen(atlas_network_dns_static_info, "wt");
				if( f1==NULL ) {
                                        atlas_log(ERROR,
						"Unable to create  %s\n",
						atlas_network_dns_static_info);
					fclose(f);
                                        return 1;
                                }


				// Statically configured probe.
				//DNS_SERVERS 8.8.8.8 194.109.6.66
				// fprintf (f, "%s\n", line);
				token = strtok(line+11, search_nl); //
			 	fprintf (f1, "STATIC_DNS");
				while  (token != NULL) 
				{
			 		fprintf (f, "nameserver %s\n", token);
					fprintf (f1, " %s", token);
					token = strtok(NULL, search_nl);
				}
				fprintf (f1, "\n");

				fclose(f);
				fclose(f1);

				do_rm_dns_static_info= 0;
			}
			else if( strncmp(line,"FIRMWARE_KERNEL ", 16)==0 ) 
			{
			}
			bzero( line, ATLAS_BUF_SIZE );
			fgets( line, MAX_READ, read_from );
			l++;
		}
		if (do_rm_dns_static_info)
			unlink(atlas_network_dns_static_info);
	}
	else if  (strncmp(line,"WAIT\n",5) == 0 ) 
	{
		read_wait(read_from, "REG_WAIT_UNTIL", ATLAS_WAIT );
 
	}
	else  {
		char *p = strchr(line,'\n');
		if( p!=NULL ) *p = '\0';
		atlas_log( ERROR, "OK expected, got \"%s\" instead\n", line );
		read_wait(read_from, "REG_WAIT_UNTIL", ATLAS_DEFAULT_WAIT); /* we got error the only action from probe is wait. so force it*/
		ret = 1;
	}
	return ret;
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
