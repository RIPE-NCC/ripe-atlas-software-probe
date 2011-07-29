#include "libbb.h"
#include <syslog.h>
#include <unistd.h>
#define OPT_STRING "l:L"
#define ERROR 	1
#define INFO1  	10
#define INFO5  	15
#define DBG1  	32
#define DBG2  	11
#define MAX_READ 511

#ifdef ATLASDEBUG1
#define LOGERROR1(msg) atlaslog  msg
#else
#define LOGERROR1(msg) 
#endif

#define ATLASINFO1 1
#ifdef ATLASINFO1
#define INFO_1(msg) atlaslog msg
#define INFO_5(msg) atlaslog msg
#define ERROR_0(msg) atlaslog msg
#else
#define INFO_1(msg) 
#define INFO_5(msg) 
#define ERROR_0(msg)
#endif

#define ROOT_DIR /home/atlas
#define REG_INIT_VOL "/home/atlas/status/reginit.vol"

static int pid;
static int flag_rootfsupgrade;

static char c_ls_file[] = "/bin/ls"; 
static char *c_ls_argv[] = {"ls", "-l", "/",  NULL };
static int  c_ls_pid;
static int c_reginit_last_ran;

struct globals {
        unsigned LogLevel; /* = 4; */
        const char *LogFile;
};

#define G (*(struct globals*)&bb_common_bufsiz1)
#define LogLevel           (G.LogLevel               )
#define LogFile            (G.LogFile                )

#define INIT_G() do { \
  	LogLevel = 8; \
 } while (0) 


static void atlaslog( unsigned level, const char  *msg, ... );
static void ForkJob (pid_t *pid, const char *prog, const char *arg[], int wait_flag);
static void do_info(const char *file, int FAST_FUNC (*proc)(char *));
static void  rcS ( void );
static void reginit( void );
static int check_pid (const int pid, char *cmd, int len);

int atlasserial_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int atlasserial_main(int argc UNUSED_PARAM, char **argv)
{
        unsigned opt;
	INIT_G(); 
	opt = getopt32(argv, "l:L:",  &LogLevel, &LogFile);
	INFO_1((INFO1, "INFO-1 starting with log level %d \n", LogLevel ));
	fflush(stdout);
	rcS( );

	reginit();
	while(1) {
		do_info("/proc/buddyinfo",  NULL);
		sleep (7);
		reginit();
	}
	_exit(EXIT_SUCCESS);

}

static void reginit( void )
{
	FILE *state_fd;
	int pid;
	char c_reginit[] = "/home/atlas/bin/reginit.sh";
	char *c_reginit_argv[] = { "reginit", REG_INIT_VOL , (char *)0 };

	if ((state_fd = fopen(REG_INIT_VOL, "r")) == NULL) {
		c_reginit_last_ran = (int)time(NULL);
		ForkJob (&pid, c_reginit, c_reginit_argv, 0);
	}
	else 
	{
		if(fscanf(state_fd, "%d", &pid)  == EOF) 
		{
	 		INFO_5((INFO5, "INFO5 found empty reginit state file\n"));
			return;
		}
		//we have got a pid  check the process is running or not.
		if (check_pid (pid, "dbclient", 8) > 0)
		{
	 		INFO_5((INFO5, "INFO5 controller connection is up pid %d\n", pid));
		}
		else 
		{
			unlink(REG_INIT_VOL);
			c_reginit_last_ran = (int)time(NULL);
			ForkJob (&pid, c_reginit, c_reginit_argv, 0);
		}
	
	}
}

static void rcS (void) 
{
char c_mount_proc[] = "/bin/mount";
char *c_mount_proc_argv[] =  { "mount", "-t", "proc", "proc", "/proc", (char *)0 };

char *c_mount_devpts_argv[] = {"mount", "-t", "devpts",  "devpts", "/dev/pts", (char *)0};

char c_ifconfig_lo[] = "/sbin/ifconfig";
char *c_ifconfig_lo_argv[] = {"ifconfig","lo", "127.0.0.1", (char *)0 };

char c_route_lo[] = "/sbin/route";
char *c_route_lo_argv = {"route", "add", "-net", "127.0.0.0", "netmask", "255.0.0.0", "lo", (char *)0 };

char c_udhcpc[] = "/sbin/udhcpc";
char *c_udhcpc_argv[] = {"udhcpc", "-t", "9999", "-T", "3", (char *)0 };

char c_telnetd[] = "/sbin/telnetd";
char *c_telnetd_argv[] = {"telnetd", (char *)0 };
char c_ntpclient[] = "/bin/ntpclient";
char *c_settime_argv[] = {"ntpclient", "-s" , "-g",  "20000", "-h",  "tt01.ripe.net", (char *)0 };

char c_rootfsupgrade[] = "/etc/rootfsupgrade";
char *c_rootfsupgrade_argv = {"rootfsupgrade", (char *)0 };
	
	sethostname("probev1", 7); 
 	ForkJob (&pid, c_mount_proc,  c_mount_proc_argv, 1);
 	ForkJob (&pid, c_mount_proc,  c_mount_devpts_argv, 1);
	ForkJob (&pid, c_udhcpc, c_udhcpc_argv, 0);
 	ForkJob (&pid, c_ifconfig_lo,  c_ifconfig_lo_argv, 1);
//AA  Route command hangs. Need to figure this out.
// 	ForkJob (&pid, c_route_lo,  c_route_lo_argv, 1);
	ForkJob (&pid, c_telnetd, c_telnetd_argv, 0);
	sleep(2);
	ForkJob (&pid, c_ntpclient, c_settime_argv, 1);
 	//ForkJob (&c_ls_pid, c_ls_file,  c_ls_argv, 1);

	flag_rootfsupgrade = 0;
	FILE *upgrade_fd = fopen_or_warn_stdin("/home/atlas/state/FIRMWARE_APPS");
        if (upgrade_fd != NULL) {
		close (upgrade_fd);
		ForkJob (&pid, c_rootfsupgrade, c_rootfsupgrade_argv,1);
		flag_rootfsupgrade = 1;
        }
	close (upgrade_fd);
	unlink(REG_INIT_VOL);
}

static void atlaslog( unsigned level, const char  *msg, ... )
{
		if(level < LogLevel)
		return; 
	va_list arg;
	va_start ( arg, msg );

	FILE *lf = stdout;
	if( lf==NULL )
		return; // not much we can do
	fprintf( lf, "%d %d ", (int)time(NULL), level );
        vfprintf( lf, msg, arg );
        //fclose(lf);
	va_end( arg );
}

static void ForkJob (pid_t *pid, const char *prog, const char *arg[], int wait_flag)
{	
	int pid1;
	int status;
	 INFO_5((INFO5, "INFO5 starting child prog %s %s\n", prog, arg[1]));
	pid1 = vfork();
	if(pid1 ==  0)
	{
		/* CHILD */
		INFO_5((INFO5, "INFO5 IN the child exec %s %s\n", prog, arg[1]));
		if(wait_flag < 1 )
		//bb_signals((1 << SIGCHLD) + (1 << SIGPIPE), SIG_DFL);
	 	//status = execv(prog, arg);
		BB_EXECVP(prog, arg);
		if(status)
		INFO_5 ((INFO5, "ERROR Child failed to exec %s ret %d %d\n", prog, status, errno));
		_exit(EXIT_SUCCESS);
	}
	else if (pid1 < 0 )
	{
		ERROR_0 ((ERROR, "ERROR failed to exec %s\n", prog));
	} 
	else 
	{
		fflush(stdout);
	      INFO_5((INFO5, "INFO5 Parent continuing  child pid %d\n",(int)pid1));
		if(wait_flag > 0) 
		{
			waitpid(pid1, &status, WNOHANG);
			int i=0,max=30;
			while( i<max && !WIFEXITED(status) ) {
				sleep(1);
				INFO_5((INFO5,"Wait loop %d\n", i ));
				waitpid(pid1, &status, WNOHANG);
			} 
			if( i>=max )
				INFO_5((INFO5, "Timed out on waiting for pid %d\n", (int)pid1));
			else
				INFO_5((INFO5, "Child pid %d exited normally\n", (int)pid1));
		}
		else 
		{
				INFO_5((INFO5, "Child pid %d left alone\n", (int)pid1));
		}

		fflush(stdout);
	}
	return;
}

static void do_info(const char *file, int FAST_FUNC (*proc)(char *))
{
        int lnr;
        FILE *procinfo;
	char line[512];

        /* _stdin is just to save "r" param */
        procinfo = fopen_or_warn_stdin(file);
        if (procinfo == NULL) {
                return;
        }
        lnr = 0;        /* Why xmalloc_fgets_str? because it doesn't stop on NULs */
	do 
	{
		fgets( line, MAX_READ, procinfo );
                /* line 0 is skipped */
                //if( lnr && proc(line))
                 //       bb_error_msg("%s: bogus data on line %d", file, lnr + 1)
;
                lnr++;
		printf ("%s ", line);
		fgets( line, MAX_READ, procinfo );
        } while( !feof(procinfo)) ;
        fclose(procinfo);
}


static int check_pid (const int pid, char *cmd, int len)
{
	FILE *procinfo;
        char line[128];
	if(len > 127)
		return(-1);

	sprintf (line, "/proc/%d/cmdline", pid);
	if (procinfo == NULL) {
                return (-1);
        }
	fgets( line, len, procinfo );
 	if( strncmp(line, cmd,len) == 0 ) 
	{
		return (1);

	}	
	return (0);
}

