/*
 * Copyright (c) 2013-2014 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * tcputil.c
 */

#include "libbb.h"
#include "eperd.h"
#include <assert.h>
#include <event2/bufferevent.h>
#ifdef HAVE_OPENSSL_SSL_H
#include <event2/bufferevent_ssl.h>
#endif
#include <event2/dns.h>
#include <event2/event.h>

#include "tcputil.h"

const char *ssl_version= NULL;

static int ssl_initialized= 0;

static void dns_cb(int result, struct evutil_addrinfo *res, void *ctx);
static int create_bev(struct tu_env *env);
static void eventcb(struct bufferevent *bev, short events, void *ptr);

void tu_connect_to_name(struct tu_env *env, char *host,
	bool do_tls, bool do_http2, char *port,
	struct timeval *interval,
	struct evutil_addrinfo *hints,
	char *infname,
	const char *server_name, 
	const char *cert_name,
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
	int r;
	struct addrinfo *ai;
	struct addrinfo loc_hints;

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
	env->do_tls = do_tls;
	env->do_http2 = do_http2;
	env->server_name = server_name;
	env->cert_name = cert_name;

	evtimer_assign(&env->timer, EventBase,
		timeout_callback, env);

	/* Check if hostname is numeric or had to be resolved */
	env->host_is_literal= 0;
	memset(&loc_hints, '\0', sizeof(loc_hints));
	loc_hints.ai_flags= AI_NUMERICHOST;
	r= getaddrinfo(host, NULL, &loc_hints, &ai);
	if (r == 0)
	{
		/* Getaddrinfo succeded so hostname is an address literal */
		freeaddrinfo(ai);
		env->host_is_literal= 1;
	}

	env->dnsip= 1;
	env->connecting= 0;
	gettime_mono(&env->start_time);
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

void tu_fake_ttr(void *ctx, char *host)
{
	int r;
	struct tu_env *env;
	struct addrinfo *ai;
	struct timespec now, elapsed;
	double nsecs;
	struct addrinfo loc_hints;

	env= ctx;

	/* Check if hostname is numeric or had to be resolved */
	env->host_is_literal= 0;
	memset(&loc_hints, '\0', sizeof(loc_hints));
	loc_hints.ai_flags= AI_NUMERICHOST;
	r= getaddrinfo(host, NULL, &loc_hints, &ai);
	if (r == 0)
	{
		/* Getaddrinfo succeded so hostname is an address literal */
		freeaddrinfo(ai);
		env->host_is_literal= 1;
	}


	gettime_mono(&env->start_time);
	gettime_mono(&now);
	elapsed.tv_sec= now.tv_sec - env->start_time.tv_sec;
	if (now.tv_nsec < env->start_time.tv_sec)
	{
		elapsed.tv_sec--;
		now.tv_nsec += 1000000000;
	}
	elapsed.tv_nsec= now.tv_nsec - env->start_time.tv_nsec;
	nsecs= (elapsed.tv_sec * 1e9 + elapsed.tv_nsec);
	env->ttr= nsecs/1e6;
}

void tu_cleanup(struct tu_env *env)
{
	if (env->dns_res)
	{
		evutil_freeaddrinfo(env->dns_res);
		env->dns_res= NULL;
		env->dns_curr= NULL;
	}
	if (env->tls_ctx)
	{
		SSL_CTX_free(env->tls_ctx);
		env->tls_ctx= NULL;
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
	double nsecs;
	struct timespec now, elapsed;

	env= ctx;

	if (!env->dnsip)
	{
		crondlog(LVL7
			"dns_cb: in dns_cb but not doing dns at this time");
		if (res)
			evutil_freeaddrinfo(res);
		return;
	}

	gettime_mono(&now);
	elapsed.tv_sec= now.tv_sec - env->start_time.tv_sec;
	if (now.tv_nsec < env->start_time.tv_sec)
	{
		elapsed.tv_sec--;
		now.tv_nsec += 1000000000;
	}
	elapsed.tv_nsec= now.tv_nsec - env->start_time.tv_nsec;
	nsecs= (elapsed.tv_sec * 1e9 + elapsed.tv_nsec);
	env->ttr= nsecs/1e6;

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

		/* Immediate error, for example if there is no default route */
		
		/* It is possible that the callback already freed dns_curr. */
		if (!env->dns_curr)
		{
			printf("dns_cb: callback ate dns_curr\n");
			if (env->dns_res)
				crondlog(DIE9 "dns_cb: dns_res not null");
			return;
		}

#ifdef HAVE_OPENSSL_SSL_H
		err= bufferevent_get_openssl_error(bev);
		if (err)
		{
			ERR_error_string_n(err, errbuf, sizeof(errbuf));
			env->reporterr(env, TU_CONNECT_ERR, errbuf);
		}
		else
		{
			env->reporterr(env, TU_CONNECT_ERR, strerror(errno));
		}
#else
		env->reporterr(env, TU_CONNECT_ERR, strerror(errno));
#endif

		/* Check again... */
		if (!env->dns_curr)
		{
			printf("dns_cb: reporterr ate dns_curr\n");
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
	int af, fd, fl;
	struct bufferevent *bev;
	SSL *tls;
	X509_VERIFY_PARAM *vpm = NULL;

	af= env->dns_curr->ai_addr->sa_family;

	/* Consistency check. These fields need to be clear */
	assert(!env->tls_ctx);
#if ENABLE_FEATURE_EVHTTPGET_HTTPS
	if(env->do_tls || env->do_http2)
	{
		if (!ssl_initialized) {
			ssl_initialized= 1;
			RAND_poll();
			SSL_library_init(); /* call only once this is not reentrant. */
			ERR_load_crypto_strings();
			SSL_load_error_strings();
			OpenSSL_add_all_algorithms();

			/* SSLeay_version seems work everywhere.
			 * What about OpenSSL_version(OPENSSL_VERSION)?
			 */
			ssl_version= SSLeay_version(SSLEAY_VERSION);
		}
		/* fancy ssl options yet. just what is default in lib */
		if ((env->tls_ctx = SSL_CTX_new(SSLv23_client_method())) == NULL)
		{
			env->reporterr(env, TU_SSL_CTX_INIT_ERR,
				"SSL_CTX_new call failed");
			return -1;
		}
		if (env->do_http2)
		{
			/* SSL_CTX_set_alpn_protos gets an ALPN list
			 * in wire format. Each string is prefixed by
			 * a length byte.
			 */
			const unsigned char alpn_list[]=
				{ '\2', 'h', '2' };
			size_t alpn_len= sizeof(alpn_list);
			int r;

			r= SSL_CTX_set_alpn_protos(env->tls_ctx,
				alpn_list, alpn_len);
			if (r != 0)
			{
				env->reporterr(env, TU_SSL_CTX_INIT_ERR,
				"SSL_CTX_set_alpn_protos call failed");
                                return -1;
			}
			if (env->cert_name)
			{
				if (!SSL_CTX_set_default_verify_paths
					(env->tls_ctx))
				{
					env->reporterr(env,
						TU_SSL_CTX_INIT_ERR,
			"SSL_CTX_set_default_verify_paths call failed");
                                	return -1;
				}
				vpm= X509_VERIFY_PARAM_new();
				if (!X509_VERIFY_PARAM_set1_host(vpm,
					env->cert_name, 0))
				{
					env->reporterr(env,
						TU_SSL_CTX_INIT_ERR,
				"X509_VERIFY_PARAM_set1_host call failed");
					X509_VERIFY_PARAM_free(vpm);
					vpm= NULL;
                                	return -1;
				}
			}
		}
		if (vpm)
		{
			if (!SSL_CTX_set1_param(env->tls_ctx, vpm))
			{
				env->reporterr(env, TU_SSL_CTX_INIT_ERR,
				"SSL_CTX_set1_param call failed");
				X509_VERIFY_PARAM_free(vpm);
				vpm= NULL;
                                return -1;
			}
			X509_VERIFY_PARAM_free(vpm);
			vpm= NULL;
			SSL_CTX_set_verify(env->tls_ctx,
				SSL_VERIFY_PEER, 0);
		}
		if ((tls = SSL_new(env->tls_ctx)) == NULL) {
			env->reporterr(env, TU_SSL_OBJ_INIT_ERR,
				"SSL_new call failed");
				return -1;
		}
		if (env->server_name)
		{
			if (!SSL_set_tlsext_host_name(tls,
				env->server_name))
			{
				env->reporterr(env, TU_SSL_OBJ_INIT_ERR,
				"SSL_set_tlsext_host_name call failed");
				return -1;
			}
		}
#ifdef HAVE_OPENSSL_SSL_H
		bev = bufferevent_openssl_socket_new(EventBase, -1, tls,
				BUFFEREVENT_SSL_CONNECTING,
				BEV_OPT_CLOSE_ON_FREE);
		if (bev == NULL) 
		{
			env->reporterr(env, TU_SSL_INIT_ERR,
				"bufferevent_openssl_socket_new call failed");
			return -1;
		}
#else
		env->reporterr(env, TU_SSL_INIT_ERR,
			"OpenSSL support not available");
		return -1;
#endif
	} 
	else if 
#else 
	if
#endif
		((bev= bufferevent_socket_new(EventBase, -1,
			BEV_OPT_CLOSE_ON_FREE)) == NULL)
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

		/* Set socket to nonblocking */
                fl= fcntl(fd, F_GETFL);
                if (fl < 0) {
                        env->reporterr(env, TU_SOCKET_ERR, "fcntl F_GETFL");
			close(fd);
                        return -1;
                }
                if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) == -1) {
                        env->reporterr(env, TU_SOCKET_ERR, "fcntl F_SETFL");
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

	if (events & BEV_EVENT_ERROR)
	{
		if (env->connecting)
		{
#ifdef HAVE_OPENSSL_SSL_H
			err= bufferevent_get_openssl_error(bev);
			if (err)
			{
				ERR_error_string_n(err, errbuf, sizeof(errbuf));
				env->reporterr(env, TU_CONNECT_ERR, errbuf);
			}
			else
			{
				env->reporterr(env, TU_CONNECT_ERR,
					strerror(errno));
			}
#else
			env->reporterr(env, TU_CONNECT_ERR, strerror(errno));
#endif
			return;
		}
		events &= ~BEV_EVENT_ERROR;
	}
	if (events & BEV_EVENT_READING)
	{
		env->reporterr(env, TU_READ_ERR, "");
		events &= ~BEV_EVENT_READING;
		return;
	}
	if (events & BEV_EVENT_CONNECTED)
	{
		events &= ~BEV_EVENT_CONNECTED;
		env->connecting= 0;

		if (env->do_http2)
		{
#ifdef HAVE_OPENSSL_SSL_H
			/* Check if the server accepted the h2 ALPN */
			SSL_get0_alpn_selected(	
				bufferevent_openssl_get_ssl(bev),
				&data, &len);
			if (data == NULL)
			{
				env->reporterr(env, TU_CONNECT_ERR,
					"server does not offer 'h2' ALPN");
				return;
			}
			else if (len != 2 || memcmp("h2", data, len) != 0)
			{
				env->reporterr(env, TU_CONNECT_ERR,
					"server offers wrong ALPN");
				return;
			}
#else
			env->reporterr(env, TU_CONNECT_ERR,
				"HTTP/2 ALPN not available without OpenSSL");
			return;
#endif
		}

		bufferevent_enable(bev, EV_READ);

		env->connected(env, bev);
		env->writecb(bev, ptr);
	}
	if (events)
		printf("events = 0x%x\n", events);
}

