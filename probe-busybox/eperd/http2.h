/*
 * Copyright (c) 2021 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * http2.h
 */

#include <event2/event_struct.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <event2/bufferevent_ssl.h>

struct http2_env;

typedef void (*http2_reply_cb_t)(void *ref, unsigned status,
	u_char *data, size_t len);
typedef void (*http2_write_response_cb_t)(void *ref, void *data, size_t len);
typedef size_t (*http2_read_response_cb_t)(void *ref, void *data, size_t len);

struct http2_env *http2_init(void);
void http2_free(struct http2_env *env);
void http2_dns(struct http2_env *env, struct bufferevent *bev,
	const char *hostname, const char *port, const char *path,
	u_char *req, size_t reqlen);
int http2_dns_input(struct http2_env *env, struct bufferevent *bev,
	http2_reply_cb_t reply_cb, void *ref,
	http2_write_response_cb_t write_response_cb,
	http2_read_response_cb_t read_response_cb);
