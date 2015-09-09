/*
 * Copyright (c) 2013-2014 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * tcputil.c
 */

#include "libbb.h"
#include "eperd.h"
#include <event2/bufferevent.h>
#include <event2/dns.h>
#include <event2/event.h>

#include "tcputil.h"

static void dns_cb(int result, struct evutil_addrinfo *res, void *ctx);
static int create_bev(struct tu_env *env);
static void eventcb(struct bufferevent *bev, short events, void *ptr);

void tu_connect_to_name(struct tu_env *env, char *host, char *port,
	struct timeval *interval,
	struct evutil_addrinfo *hints,
	char *infname,
	void (*timeout_callback)(int unused, const short event, void *s),
	void (*reporterr)(struct tu_env *env, enum tu_err cause,
		const char *err),
	void (*reportcount)(struct tu_env *env, int count),
	void (*beforeconnect)(struct tu_env *env,
		struct sockaddr *addr, socklen_t addrlen),
	void (*connected)(struct tu_env *env, struct bufferevent *bev),
	void (*readcb)(struct bufferevent *bev, void *ptr),
	void (*writecb)(struct bufferevent *bev, void *ptr))
{
	env->interval= *interval;
	env->infname= infname;
	env->reporterr= reporterr;
	env->reportcount= reportcount;
	env->beforeconnect= beforeconnect;
	env->connected= connected;
	env->readcb= readcb;
	env->writecb= writecb;
	env->dns_res= NULL;
	env->bev= NULL;

	evtimer_assign(&env->timer, EventBase,
		timeout_callback, env);

	env->dnsip= 1;
	env->connecting= 0;
	(void) evdns_getaddrinfo(DnsBase, host, port, hints, dns_cb, env);
}

void tu_restart_connect(struct tu_env *env)
{
	int r;
	struct bufferevent *bev;

	/* Connect failed, try next address */
	if (env->dns_curr)	/* Just to be on the safe side */
	{
		env->dns_curr= env->dns_curr->ai_next;
	}
	while (env->dns_curr)
	{
		evtimer_add(&env->timer, &env->interval);

		r= atlas_check_addr(env->dns_curr->ai_addr,
			env->dns_curr->ai_addrlen);
		if (r == -1)
		{
			env->reporterr(env, TU_BAD_ADDR, "");
			return;
		}

		env->beforeconnect(env,
			env->dns_curr->ai_addr, env->dns_curr->ai_addrlen);

		/* Delete old bev */
		if (env->bev)
		{
			bufferevent_free(env->bev);
			env->bev= NULL;
		}

		/* And create a new one */
		r= create_bev(env);
		if (r == -1)
		{
			return;
		}
		bev= env->bev;

		if (bufferevent_socket_connect(bev,
			env->dns_curr->ai_addr,
			env->dns_curr->ai_addrlen) == 0)
		{
			/* Connecting, wait for callback */
			return;
		}

		/* Immediate error? */
		if (!env->dns_curr)
		{
			/* Callback cleaned up */
			return;
		}
		env->dns_curr= env->dns_curr->ai_next;
	}

	/* Something went wrong */
	bufferevent_free(env->bev);
	env->bev= NULL;
	if (env->dns_res)
	{
		evutil_freeaddrinfo(env->dns_res);
		env->dns_res= NULL;
		env->dns_curr= NULL;
	}
	env->reporterr(env, TU_OUT_OF_ADDRS, "");
}

void tu_cleanup(struct tu_env *env)
{
	if (env->dns_res)
	{
		evutil_freeaddrinfo(env->dns_res);
		env->dns_res= NULL;
		env->dns_curr= NULL;
	}
	if (env->bev)
	{
		bufferevent_free(env->bev);
		env->bev= NULL;
	}

	event_del(&env->timer);
}

static void dns_cb(int result, struct evutil_addrinfo *res, void *ctx)
{
	int r, count;
	struct tu_env *env;
	struct bufferevent *bev;
	struct evutil_addrinfo *cur;

	env= ctx;

	if (!env->dnsip)
	{
		crondlog(LVL7
			"dns_cb: in dns_cb but not doing dns at this time");
		if (res)
			evutil_freeaddrinfo(res);
		return;
	}

	env->dnsip= 0;

	if (result != 0)
	{
		env->reporterr(env, TU_DNS_ERR, evutil_gai_strerror(result));
		return;
	}

	env->dns_res= res;
	env->dns_curr= res;

	count= 0;
	for (cur= res; cur; cur= cur->ai_next)
		count++;

	env->reportcount(env, count);

	while (env->dns_curr)
	{
		evtimer_add(&env->timer, &env->interval);

		r= atlas_check_addr(env->dns_curr->ai_addr,
			env->dns_curr->ai_addrlen);
		if (r == -1)
		{
			env->reporterr(env, TU_BAD_ADDR, "");
			return;
		}

		env->beforeconnect(env,
			env->dns_curr->ai_addr, env->dns_curr->ai_addrlen);

		/* Delete old bev if any */
		if (env->bev)
		{
			bufferevent_free(env->bev);
			env->bev= NULL;
		}

		/* And create a new one */
		r= create_bev(env);
		if (r == -1)
		{
			return;
		}

		bev= env->bev;
		if (bufferevent_socket_connect(bev,
			env->dns_curr->ai_addr,
			env->dns_curr->ai_addrlen) == 0)
		{
			/* Connecting, wait for callback */
			return;
		}

		/* Immediate error? */
		printf("dns_cb: connect error\n");
		
		/* It is possible that the callback already freed dns_curr. */
		if (!env->dns_curr)
		{
			printf("dns_cb: callback ate dns_curr\n");
			if (env->dns_res)
				crondlog(DIE9 "dns_cb: dns_res not null");
			return;
		}
		env->dns_curr= env->dns_curr->ai_next;
	}

	/* Something went wrong */
	printf("dns_cb: Connect failed\n");
	bufferevent_free(env->bev);
	env->bev= NULL;
	evutil_freeaddrinfo(env->dns_res);
	env->dns_res= NULL;
	env->dns_curr= NULL;
	env->reporterr(env, TU_OUT_OF_ADDRS, "");
}

static int create_bev(struct tu_env *env)
{
	int af, fd;
	struct bufferevent *bev;

	af= env->dns_curr->ai_addr->sa_family;

	bev= bufferevent_socket_new(EventBase, -1,
		BEV_OPT_CLOSE_ON_FREE);
	if (!bev)
	{
		crondlog(DIE9 "bufferevent_socket_new failed");
	}
	if (env->infname)
	{
		fd= socket(af, SOCK_STREAM, 0);
		if (fd == -1)
		{
			env->reporterr(env, TU_SOCKET_ERR,
				"socket call failed");
			return -1;
		}

		if (bind_interface(fd, af, env->infname) == -1)
		{
			env->reporterr(env, TU_SOCKET_ERR,
				"bind_interface failed");
			close(fd);
			return -1;
		}
		bufferevent_setfd(bev, fd);
	}
	bufferevent_setcb(bev, env->readcb, env->writecb, eventcb, env);
	bufferevent_enable(bev, EV_WRITE);
	env->bev= bev;
	env->connecting= 1;

	return 0;
}

static void eventcb(struct bufferevent *bev, short events, void *ptr)
{
	struct tu_env *env;

	env= ptr;

	if (events & BEV_EVENT_READING)
	{
		env->reporterr(env, TU_READ_ERR, "");
		events &= ~BEV_EVENT_READING;
		return;
	}
	if (events & BEV_EVENT_ERROR)
	{
		if (env->connecting)
		{
			env->reporterr(env, TU_CONNECT_ERR,
				strerror(errno));
			return;
		}
		events &= ~BEV_EVENT_ERROR;
	}
	if (events & BEV_EVENT_CONNECTED)
	{
		events &= ~BEV_EVENT_CONNECTED;
		env->connecting= 0;
		bufferevent_enable(bev, EV_READ);

		env->connected(env, bev);
		env->writecb(bev, ptr);
	}
	if (events)
		printf("events = 0x%x\n", events);
}

