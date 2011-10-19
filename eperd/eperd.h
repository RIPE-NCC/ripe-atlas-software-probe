/*
eperd.h
*/

typedef struct CronLine CronLine;

struct globals {
	unsigned LogLevel; /* = 8; */
	const char *LogFile;
	const char *CDir; /* = CRONTABS; */
	CronLine *LineBase;
	CronLine *oldLine;
	struct event_base *EventBase;
};
extern struct globals G;
#define LogLevel           (G.LogLevel               )
#define LogFile            (G.LogFile                )
#define CDir               (G.CDir                   )
#define LineBase           (G.LineBase               )
#define FileBase           (G.FileBase               )
#define oldLine            (G.oldLine                )
#define EventBase          (G.EventBase              )

#define LVL5  "\x05"
#define LVL7  "\x07"
#define LVL8  "\x08"
#define LVL9  "\x09"
#define WARN9 "\x49"
#define DIE9  "\xc9"
/* level >= 20 is "error" */
#define ERR20 "\x14"

struct testops
{
	void *(*init)(int argc, char *argv[]);
	void (*start)(void *teststate);
	int (*delete)(void *teststate);
};

extern struct testops ping_ops;
extern struct testops condmv_ops;

void crondlog(const char *ctl, ...);
