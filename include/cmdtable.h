/*
cmdtable.h

Commands for perd and ooqd 
*/

int condmv_main(int argc, char *argv[]);
int httppost_main(int argc, char *argv[]);
#if 0
int httpget_main(int argc, char *argv[]);
int nslookup_main(int argc, char *argv[]);
int ping6_main(int argc, char *argv[]);
int ping_main(int argc, char *argv[]);
int sslgetcert_main(int argc, char *argv[]);
int tdig_main(int argc, char *argv[]);
int traceroute_main(int argc, char *argv[]);
#endif
int wifimsm_main(int argc, char *argv[]);

static struct builtin 
{
	const char *cmd;
	int (*func)(int argc, char *argv[]);
} builtin_cmds[]=
{
	{ "condmv", condmv_main },
	{ "httppost", httppost_main },
#if 0
	{ "ping6", ping6_main },
	{ "ping", ping_main },
	{ "sslgetcert", sslgetcert_main },
	{ "traceroute", traceroute_main },
#endif
	{ "wifimsm", wifimsm_main },
	{ NULL, 0 }
};

