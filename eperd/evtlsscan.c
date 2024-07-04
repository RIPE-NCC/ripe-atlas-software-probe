/*
 * Copyright (c) 2014 - 2016 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

//config:config EVTLSGETCERT
//config:       bool "evtlsgetcert"
//config:       default n
//config:       help
//config:               standalone version of event-driven TLS getcert

//config:config EVTLSSCAN
//config:       bool "evtlsscan"
//config:       default n
//config:       help
//config:               Scan TLS server with various TLS paramenters and summarize them.

//applet:IF_EVTLSSCAN(APPLET(evtlsscan, BB_DIR_ROOT, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_EVTLSSCAN) += evtlsscan.o

//usage:#define evtlsscan_trivial_usage
//usage:       "todo"
//usage:#define evtlsscan_full_usage "\n\n"
//usage:     "todo"

#include "json-macros.h"
#include "libbb.h"
#include "atlas_bb64.h"
#include "atlas_probe.h"
#include <netdb.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <math.h>
#include <assert.h>

#include "eperd.h"

#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/dns.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/bufferevent_ssl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "tls_hostname_validation.h"

#define SAFE_PREFIX ATLAS_DATA_NEW

#define DEFAULT_LINE_LENGTH 1024
#define DEFAULT_NOREPLY_TIMEOUT 5000
#define O_RETRY  200

#define STATUS_FREE 0
#define STATUS_START 1001

enum output_format {OUTPUT_FMT_NO_CERTS, OUTPUT_FMT_CERTS_ARRAY, OUTPUT_FMT_CERTS_FULL};

enum readstate { READ_FIRST, READ_STATUS, READ_HEADER, READ_BODY, READ_SIMPLE,
	READ_CHUNKED, READ_CHUNK_BODY, READ_CHUNK_END,
	READ_CHUNKED_TRAILER,
	READ_DONE };
enum writestate { WRITE_FIRST, WRITE_HEADER, WRITE_POST_HEADER,
	WRITE_POST_FILE, WRITE_POST_FOOTER, WRITE_DONE };

/* struct common for all quries */
struct tls_base {
	struct event_base *event_base;
};

static void crondlog_aa(const char *ctl, char *fmt, ...);

/* 
 * this user query one per user input aka pqry
 * Child query and Grand children are the actual queries 
 */
struct tls_state {
	char *host;
	int state;
	int q_serial;  /* on the instance, keep count of queries sent */
	int q_success;

	/* all children share same result structure with the  parent */
	struct buf err;
	struct buf result;

	struct evutil_addrinfo *addr; /* there is only one on the pqry */
	struct timeval start_time; /* start time of the parent query */
	struct event free_inst_ev; /* event to free the parent query */

	char *port; /* port as character string "443"*/
	char do_get;
	char do_head;
	char do_http10;
	char *user_agent;
	char *path;

	int dns_count; /* resolved addresses to pquery */

	int active; /* pending additional quries per user query */
	int retry;

	int opt_out_format;
	int opt_retry_max;
	int opt_ignore_cert;

	int opt_v4;
	int opt_v6;
	struct evutil_addrinfo hints;

	int opt_max_con; /* maximum concurrent queries per destination */
	int opt_max_bytes; /*  max size of output buffer */

	bool opt_all_tests;

	struct timeval timeout_tv; /* time out per child query in TV */
	int opt_timeout; /* user input in seconds */
	int opt_ssl_v3;
	int opt_tls_v1;
	int opt_tls_v11;
	int opt_tls_v12;
	char *out_filename;
	char *str_Atlas; /* option but without opt_ prefix. Historic */

	struct tls_qry *c; 
	struct event done_ev;
	void (*done)(void *state); /* call back when all queries are done */
};

struct cert_fp {
	unsigned char fp[EVP_MAX_MD_SIZE];
	struct cert_fp *next;
};

struct tls_qry {
	/* per instance variables. Unshared after duplicate */
	int serial;   /* serial number of this query. Start at zero on pqry */

	struct tls_state *ui; /* pqry instace */
	struct buf *result;  /* points to pqry.result */
	struct buf *cc;   /* certificate chain, shared by grand children, appended to the result */
 	struct buf *ciphers_s_buf; /*list of ciphers that succeded shared with children */
 	struct buf *ciphers_e_buf; /* ciphers that succeded */
 	struct buf *certs; /* ciphers that succeded */
	struct buf err;

	struct cert_fp *cfps;

	SSL_CTX *ssl_ctx;
	SSL *ssl;
	int sslv; 			/* version of child query from parent opt_ */
	const char *sslv_str; 		/* string for sslv */
	const char *cipher_q; 		/* for this child query, what we are going to query */
	const char *cipher_r; 		/* for this child query, what the response was */
	struct bufferevent *bev;
	struct evutil_addrinfo *addr_curr;

	struct timeval start_time;
	double triptime;
	double ttc;
	int retry;

	struct event timeout_ev;
	struct event free_child_ev;
	bool is_c; 	/* is children? same destination (IP) with different ssl option */
	int active_c; /* count of active children. delete parent when zero */ 
	struct tls_qry *p ; /* parent query to same IP with all ciphers */
	bool tls_incomplete;
	enum readstate readstate; 	/* httpget */
	enum writestate writestate; 	/* httpget */
	struct sockaddr_in6 loc_sin6;
	socklen_t loc_socklen;
	char addrstr[INET6_ADDRSTRLEN];
};

int tlsscan_delete (void *st);
void tlsscan_start (struct tls_state *pqry);
static void event_cb(struct bufferevent *bev, short events, void *ptr);
static void write_cb(struct bufferevent *bev, void *ptr);
static void http_read_cb(struct bufferevent *bev UNUSED_PARAM, void *ptr);
static void timeout_cb(int unused  UNUSED_PARAM, const short event UNUSED_PARAM, void *h);

static struct tls_base *tls_base = NULL;
static char line[(DEFAULT_LINE_LENGTH+1)];
static struct option longopts[]=
{
	{ "retry",  required_argument, NULL, O_RETRY },
        { "timeout", required_argument, NULL, 'T' },
	{ "port", required_argument, NULL, 'p'},
};

static void done_cb(int unused  UNUSED_PARAM, const short event UNUSED_PARAM, void *h) {
	struct tls_state *pqry = h;
	pqry->done(pqry);
}

/* free ephemeral data for the this instance of run; pqry */
static void free_pqry_inst_cb (int unused  UNUSED_PARAM, const short event UNUSED_PARAM, void *h)
{
	struct tls_state *pqry = h;
	if(pqry->err.size)
	{
		buf_cleanup(&pqry->err);
	}

	if (pqry->result.size > 0)
	{
		buf_cleanup(&pqry->result);
	}

	if (pqry->addr != NULL) {
		evutil_freeaddrinfo(pqry->addr);
		pqry->addr = NULL;
	}
}

static void free_child_cb(int unused  UNUSED_PARAM, const short event UNUSED_PARAM, void *h)
{

	struct tls_qry *qry = h;
	/* only free ephemeral data of the child query */
	if(qry->err.size)
	{
		buf_cleanup(&qry->err);
	}


	if (qry->bev != NULL && qry->tls_incomplete){
		bufferevent_free(qry->bev); /* this will call SSL_free;
					       SSL_free(qry->ssl); */
		qry->bev = NULL;
	}

	if(qry->ssl_ctx !=  NULL) {
		SSL_CTX_free(qry->ssl_ctx);
		qry->ssl_ctx = NULL;
	}
}

/* Initialize a struct timeval by converting milliseconds */
static void msecstotv(time_t msecs, struct timeval *tv)
{
	tv->tv_sec  = msecs / 1000;
	tv->tv_usec = msecs % 1000 * 1000;
}

static bool tls_inst_start (struct tls_qry *qry, const char *cipher_q)
{
	/* OpenSSL is initialized, SSL_library_init() should be called already */

	/* 
	 ssl_ctx are not shared between quries. It could but not sure how to 
	 set structures with specific versions and algorithms. Instead using
	 one ctx per query.
	 */

	switch(qry->sslv)
	{
		case SSL3_VERSION:
			qry->ssl_ctx = SSL_CTX_new(SSLv3_client_method());
			qry->sslv_str = SSL_TXT_SSLV3;
			break;
		case TLS1_VERSION:
			qry->ssl_ctx = SSL_CTX_new(TLSv1_client_method());
			qry->sslv_str = SSL_TXT_TLSV1;
			break;
		case TLS1_1_VERSION:
			qry->ssl_ctx = SSL_CTX_new(TLSv1_1_client_method());
			qry->sslv_str = SSL_TXT_TLSV1_1;
			break;
		case TLS1_2_VERSION:
			qry->ssl_ctx = SSL_CTX_new(TLSv1_2_client_method());
			qry->sslv_str = SSL_TXT_TLSV1_2;
			break;
		default:
			qry->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
			qry->sslv_str = "TLSv1/SSL2/SSL3";
			break;

	}

	qry->cipher_q =  cipher_q;

	/* Do we want to do any sort of vericiation the probe? */
	/* if we don't we might be hitting a proxy server in the way */
	// verify_ssl_cert(qry);


	/* this cipher per context . we are setting per connection */
	// SSL_CTX_set_cipher_list(qry->ssl_ctx, "ALL:COMPLEMENTOFALL");
	// SSL_CTX_set_cipher_list(qry->ssl_ctx, "HIGH");

	if (!qry->ssl_ctx) {
		crondlog_aa(LVL9, "SSL_CTX_new %s", __func__);
		return TRUE;
	}

	qry->ssl = SSL_new(qry->ssl_ctx);
	if (qry->ssl == NULL) {
		crondlog_aa(LVL9, "SSL_new() %s", __func__);
		return TRUE;
	}
	SSL_set_cipher_list(qry->ssl, cipher_q);

	/* Set hostname for SNI extension */
	SSL_set_tlsext_host_name(qry->ssl, qry->ui->host);

	msecstotv(DEFAULT_NOREPLY_TIMEOUT, &qry->ui->timeout_tv);
	evtimer_add(&qry->timeout_ev, &qry->ui->timeout_tv);

	qry->bev = bufferevent_openssl_socket_new(EventBase, -1, qry->ssl,
			BUFFEREVENT_SSL_CONNECTING,
			BEV_OPT_CLOSE_ON_FREE);

	//bufferevent_openssl_set_allow_dirty_shutdown(qry->bev, 1);
	bufferevent_setcb(qry->bev, http_read_cb, write_cb, event_cb, qry);

	{
		void *ptr = NULL;
		if (qry->addr_curr->ai_family == AF_INET) {
			ptr = &((struct sockaddr_in *) qry->addr_curr->ai_addr)->sin_addr;
		}
		else if (qry->addr_curr->ai_family == AF_INET6) {
			ptr = &((struct sockaddr_in6 *)
					qry->addr_curr->ai_addr)->sin6_addr;
		}
		inet_ntop (qry->addr_curr->ai_family, ptr, qry->addrstr, INET6_ADDRSTRLEN);
		crondlog_aa(LVL7, "connect to %s %s active = %d %s %s",
				qry->addrstr, qry->ui->host, qry->ui->active, qry->sslv_str, qry->cipher_q);
	}

	if (bufferevent_socket_connect(qry->bev,
				qry->addr_curr->ai_addr,
				qry->addr_curr->ai_addrlen)) {
		crondlog_aa(LVL8, "ERROR bufferevent_socket_connect to %s \"%s\""
				"ctive = %d %s %s - %s", qry->addrstr, qry->ui->host, 
				qry->ui->active, qry->sslv_str, qry->cipher_q,
				evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR())
				);

		// warnx("could not connect to %s : %s", qry->ui->host, evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		bufferevent_free(qry->bev);
		qry->bev = NULL;
		return TRUE;
	}
	else{
		gettimeofday(&qry->start_time, NULL);
		return FALSE;
	}
	return FALSE;
}
static void ssl_c_init(struct tls_qry *qry)
{
	int i;
	const char *p;
	SSL *ssl = SSL_new(qry->ssl_ctx); /* this is a local one */

	if (ssl == NULL)
		return;

	for (i=0; ; i++)
	{
		struct tls_qry *cqry = NULL; /* next child query */

		p = SSL_get_cipher_list(ssl,i);
		if (p == NULL) {
			crondlog_aa(LVL7, "%s dst %s active = %d" " active_c = %d %s %s %s created %d children",  __func__,
				qry->addrstr, qry->ui->active, qry->active_c, qry->sslv_str, p, qry->ui->host, i);
			break;
		}
		/* skip the one that server picked. We know that is supported */
		if (strlen(p) && strncmp(p, qry->cipher_r, strlen(p)) == 0)
			continue;

		qry->ui->active++;
		cqry = xzalloc(sizeof(struct tls_qry));

		if (cqry == NULL)
			break;

		qry->tls_incomplete = TRUE;
		cqry->ui = qry->ui;
		qry->ui->q_serial++;
		qry->active_c++;
		cqry->serial =  qry->ui->q_serial;

		cqry->addr_curr = qry->addr_curr;
		cqry->result = qry->result;
		evtimer_assign(&cqry->timeout_ev, EventBase, timeout_cb, cqry);
		evtimer_assign(&cqry->free_child_ev, EventBase, free_child_cb, cqry);
		cqry->sslv  = qry->sslv;
		crondlog_aa(LVL7, "%s dst %s active = %d" " active_c = %d %s %s %s",  __func__,
				qry->addrstr, qry->ui->active, qry->active_c, qry->sslv_str, p, qry->ui->host);
		cqry->is_c = TRUE;
		cqry->p = qry;
		cqry->cc = qry->cc;
		cqry->certs = qry->certs;
		cqry->cfps = qry->cfps;
		cqry->ciphers_s_buf = qry->ciphers_s_buf;
		cqry->cipher_q = p;
		tls_inst_start(cqry, p);
	}
	SSL_free(ssl);
}

static void atlas_cert_char_encode (struct buf *lbuf, BUF_MEM *bptr)
{
	int j;
	char *c = (char *)bptr->data;

	AS("\"cert\" : \"");
	for (j  = 0; j < bptr->length;  j++) {
		if (*c == '\n') {
			AS("\\n");
		}
		else {
			/* this could be more efficient ? */
			buf_add(lbuf, c, 1);
		}
		c++;
	}
	AS("\"");
}

static char * add_cert_and_fp(unsigned char *md, X509* cert, struct tls_qry *qry, int *id) {
	unsigned int n;
	struct cert_fp *cfp = qry->cfps;
	const EVP_MD *fdig = EVP_sha1();
	int i = 0; 


	if (X509_digest(cert,fdig,md,&n) == 0) 
	{
		return "error in X509_digest";
	}

	*id = -1;
	while ( cfp != NULL) {
		if (memcmp(md, cfp->fp, EVP_MAX_MD_SIZE) == 0) 
		{
			*id = i;
			break;
		}
		i++;
		cfp = cfp->next;
	} 

	/* this is a new certificate add to chain */ 

	if (*id == -1) {
		struct buf *lbuf = qry->cc;
		BIO *b64 = BIO_new (BIO_s_mem());
		BUF_MEM *bptr;
		int k;
		char c3[4];

		cfp = xzalloc(sizeof(struct cert_fp));
		cfp->next = qry->cfps;
		qry->cfps = cfp;
		memcpy(cfp->fp, md, EVP_MAX_MD_SIZE);

		*id = i;
		PEM_write_bio_X509(b64, cert);
		BIO_get_mem_ptr(b64, &bptr);

		if (lbuf->size == 0) {
			if (i == 0) {
				AS(", \"cert_chain\" : [");
			}
		}
		if ( i > 0 )
			AS(", ");
		AS("{");
		JD(id , i);
		atlas_cert_char_encode(lbuf, bptr);
		BIO_free(b64);

		AS(", \"fp\":\"");
		for (k=0; k<(int)n; k++)
		{
			snprintf(c3, sizeof(c3),"%02X%c",md[k],
					(k+1 == (int)n) ?'"':':');
			AS(c3);

		}
		AS("}");
	}
	return NULL;
}

static void add_cert_chain( STACK_OF(X509) *sk, struct tls_qry *qry) {
	int i;
	int cert_id = -1;

	for (i=0; i<sk_X509_num(sk); i++) {
		X509* cert =  sk_X509_value(sk,i);
		unsigned char md[EVP_MAX_MD_SIZE];
		char *err_s;

		memset(md, '\0', EVP_MAX_MD_SIZE);
		err_s = add_cert_and_fp(md, cert, qry, &cert_id);

		if(err_s  != NULL) {
			struct buf *lbuf = &qry->err;
			if(lbuf->size > 0) 
				AS (",");
			JS_NC(X509cert, err_s);
		}
	}
}

static void get_cert_chain(struct tls_qry *qry)
{
	int i;
	struct buf *lbuf = qry->cc; /* careful with lbuf it is used by JSON Macros */
	STACK_OF(X509) *sk = NULL;
	// X509 *peer = NULL;

	if(qry->ui->opt_out_format & OUTPUT_FMT_NO_CERTS)
		return;

	sk = SSL_get_peer_cert_chain(qry->ssl);
	if(sk == NULL) {
		lbuf = &qry->err;
		if(lbuf->size > 0) 
			AS (",");
		JS_NC(X509cert_chain, "no cert chain found after handshake");

	} else {
		add_cert_chain(sk, qry);
	}

	/*
	peer=SSL_get_peer_certificate(qry->ssl);
	if(peer !=  NULL) {

	}
	*/
}

static void add_certs_to_result (struct tls_qry *qry)
{
	int i;
	STACK_OF(X509) *sk;

	struct buf *lbuf = qry->result;

	if(!(qry->ui->opt_out_format & OUTPUT_FMT_NO_CERTS))
		return;

	if((sk = SSL_get_peer_cert_chain(qry->ssl)) == NULL)
		return;

	for (i=0; i<sk_X509_num(sk); i++) {
		X509* cert =  sk_X509_value(sk,i);
		BUF_MEM *bptr;
		BIO *b64 = BIO_new (BIO_s_mem());

		PEM_write_bio_X509(b64, cert);
		BIO_get_mem_ptr(b64, &bptr);

		if (bptr->length > 0) {
			if (i == 0) {
				AS(", \"certs\" : [");
			}
			if ( i > 0 )
				AS(", ");
			atlas_cert_char_encode(qry->result, bptr);
			AS("}");
		}
	}
	if ( i  > 0) {
		AS("]"); /* certs [] */
	}
}

static void fmt_ssl_time(struct tls_qry *qry)
{
	int lts =  -1 ; /*  get_timesync(); */ /* AA_FIXME */
	struct buf *lbuf = qry->result;

	JS1(time, %ld,  qry->start_time.tv_sec);
	JD(lts,lts);

}

static void fmt_ssl_host(struct tls_qry *qry, bool is_err)
{
	char addrstr[INET6_ADDRSTRLEN];
	struct buf *lbuf = qry->result;

	if ((qry->addr_curr != NULL) && (qry->addrstr[0] !=  '\0')) {
		if(strcmp(qry->addrstr, qry->ui->host)) {
			JS(dst_name, qry->ui->host);
		}
		JS(dst_addr , qry->addrstr);

		if(qry->loc_sin6.sin6_family) {
			getnameinfo((struct sockaddr *)&qry->loc_sin6,
					qry->loc_socklen, addrstr, INET6_ADDRSTRLEN,
					NULL, 0, NI_NUMERICHOST);
			if(strlen(addrstr))
				JS(src_addr, addrstr);
		}
		JD_NC(af, qry->addr_curr->ai_family == PF_INET6 ? 6 : 4);
	}
	else if (qry->ui->host) {
		JS_NC(dst_name, qry->ui->host);
	}
}

static void fmt_ssl_ui_result(struct tls_qry *qry)
{
	int lts =  -1 ; /*  get_timesync(); */ /* AA_FIXME */
	int fw = get_atlas_fw_version();
	struct buf *lbuf = &qry->ui->result;

	AS("RESULT { ");
	if(qry->ui->str_Atlas != NULL)
	{
		JS(id, qry->ui->str_Atlas);
	}
	JD(fw, fw);
	JD(dnscount, qry->ui->dns_count);
	JS1(time, %ld, qry->ui->start_time.tv_sec);
	JD(lts,lts); // fix me take lts when I create start time.
	if (qry->addr_curr == NULL) {
			JS_NC(dst_name, qry->ui->host);
	} else {
		AS("\"resultset\" : [");
	}
}

static void fmt_ssl_summary(struct tls_qry *qry, bool is_err)
{
	int size = qry->result->size ;
	struct buf *lbuf = qry->result;

	if (qry->addr_curr == NULL)
		return; 

	if (size == 0){
		AS ("{");
		fmt_ssl_time(qry);
		fmt_ssl_host(qry, is_err);

		if(qry->retry) {
			JD(retry, qry->retry);
		}
		if (qry->sslv_str != NULL) {
			AS (", ");
			JS_NC(version, qry->sslv_str);
		}

	}
	if ( !is_err && (qry->ssl_ctx != NULL) && (qry->ssl != NULL) &&
			(!qry->tls_incomplete)) {
		qry->ui->q_success++;
		lbuf = qry->ciphers_s_buf; /* note lbuf changed */
		if (qry->ciphers_s_buf->size == 0) {
			AS (", \"ciphers\": [");
		} else {
			AS(" ,");
		}

		AS ("\"");
		qry->cipher_r = SSL_CIPHER_get_name(SSL_get_current_cipher(qry->ssl));
		AS (qry->cipher_r);
		AS("\"");
		get_cert_chain(qry);

		if ((qry->is_c == FALSE) && (qry->ui->opt_all_tests == TRUE))  {
			/* this is a successful child. 
			 * create children with cipher algorithm varients 
			 */
			ssl_c_init(qry);
		}
	}
}

static void fmt_ssl_cert_full_resp(struct tls_qry *qry, bool is_err)
{

	struct buf *lbuf = qry->result;
	/* if it is a failed grand child qury nothing to print */
	if (qry->is_c && qry->tls_incomplete ){
		if(qry->err.size)
		{
			buf_cleanup(&qry->err);
		}
		return;
	}

	if (qry->result->size == 0){ /* initialze the first parts RESULT */
		fmt_ssl_ui_result(qry);
	}
	else {
		AS (",{");
	}

	if(qry->retry) {
		JD(retry, qry->retry);
	}

	fmt_ssl_time(qry);
	fmt_ssl_host(qry, is_err);

	if (qry->cipher_r != NULL) {
		AS (", ");
		JS_NC(ciphers, qry->cipher_r);
	}

	if (qry->sslv_str != NULL) {
		AS (", ");
		JS_NC(version, qry->sslv_str);
	}

	if ( !is_err && (qry->ssl_ctx != NULL) && (qry->ssl != NULL) &&
			(qry->tls_incomplete == FALSE)) {
		int i;
		qry->ui->q_success++;
		AS(",");
		JS_NC(cipher, SSL_CIPHER_get_name(SSL_get_current_cipher(qry->ssl)));

	 	add_certs_to_result(qry);

		if ((qry->is_c == FALSE) && (qry->ui->opt_all_tests == TRUE))  {
			/* this is a successful child. 
			 * create children with cipher algorithm varients 
			 */
			ssl_c_init(qry);
		}
	}

	if ((qry->err.size > 0) || (qry->ui->err.size > 0))
	{
		AS(", \"error\" : {");
		if (qry->err.size > 0) {
			buf_add(qry->result, qry->err.buf, qry->err.size);
		}
		if (qry->ui->err.size > 0) {
			buf_add(qry->result, qry->ui->err.buf, qry->ui->err.size);
		}
		AS("}");
	}
	AS (" }"); //result
}


static void write_results(struct tls_qry *qry)
{
	FILE *fh;
	struct buf *lbuf = &qry->ui->result;
	/* end of result only JSON closing brackets from here on */
	if (qry->addr_curr != NULL) {
		AS("]");  /* resultset : [{}..] */
	}

	AS (", ");
	JD(queries, qry->ui->q_serial);
	JD_NC(success, qry->ui->q_success);

	if (qry->ui->out_filename)
	{
		fh= fopen(qry->ui->out_filename, "a");
		if (!fh) {
			crondlog(LVL8 "unable to append to '%s'",
					qry->ui->out_filename);
		}
	}
	else
		fh = stdout;

	if (fh) {
		char *closing = " }\n"; /* RESULT { } . end of RESULT line */
		fwrite(qry->ui->result.buf, qry->ui->result.size, 1 , fh);
		/* adds the certs directly fh, not to results to save doubling string memory */
		fwrite(closing, strlen(closing), 1 , fh);

	}
	buf_cleanup(qry->result);

	if (qry->ui->out_filename)
		fclose(fh);

	qry->ui->state = STATUS_FREE;
	qry->retry = 0;
}

static void print_tls_resp(struct tls_qry *qry, bool is_err) {

	struct timeval asap = { 0, 1 };
	struct tls_state *pqry = qry->ui;
	int active_c = 0;

	if (qry->ui->active > 0)
		qry->ui->active--;

	if ((qry->p != NULL ) && (qry->p->active_c > 0)) {
		qry->p->active_c--; 
		active_c = qry->p->active_c;
	}

	if (qry->ui->opt_out_format & OUTPUT_FMT_CERTS_FULL) {
		fmt_ssl_cert_full_resp(qry, is_err);
	} else {
		fmt_ssl_summary(qry, is_err);
	}

	if (((qry->p == NULL ) && (qry->active_c == 0)) ||
			((qry->p != NULL ) && (qry->p->active_c == 0)))
	{
		struct buf *lbuf = &qry->ui->result;
		evtimer_add(&qry->free_child_ev, &asap);
		if (qry->ui->result.size == 0) { /* initialze the first parts RESULT */
			fmt_ssl_ui_result(qry);
		} else {
			buf_add(&qry->ui->result, ", ", 1);
		}

		if(qry->addr_curr != NULL) {
			buf_add(&qry->ui->result, qry->result->buf, qry->result->size);
			buf_cleanup(qry->result);
			if (qry->err.size > 0) {
				AS(", \"error\" : {");
				buf_add(&qry->ui->result, qry->err.buf, qry->err.size);
				AS("}");
				buf_cleanup(&qry->err);
			}
			
			if (qry->cc->size > 0) {
				buf_add(&qry->ui->result, qry->cc->buf, qry->cc->size);
				buf_cleanup(qry->cc);
			} 

			if (qry->ciphers_s_buf->size > 0) {
				buf_add(qry->ciphers_s_buf, "]", 1);
				buf_add(&qry->ui->result, qry->ciphers_s_buf->buf, qry->ciphers_s_buf->size);
				buf_cleanup(qry->ciphers_s_buf);
			}

			AS("}");
		}
		if (qry->ui->err.size > 0) {
			AS(", \"error\" : {");
			buf_add(&qry->ui->result, qry->ui->err.buf, qry->ui->err.size);
			AS("}");
			buf_cleanup(&qry->ui->err);
		}

	}

	if (qry->ui->active < 1) {
		write_results(qry);
		evtimer_add(&pqry->free_inst_ev, &asap);

		if (qry->ui->done) /* call the done function */
			evtimer_add(&qry->ui->done_ev, &asap);
	}
	else {
		crondlog_aa(LVL7, "%s no output yet, dst %s active = %d"
				" active_c = %d %s %s %s",  __func__,
				qry->addrstr, qry->ui->active, active_c, qry->sslv_str, qry->cipher_q, qry->ui->host);
	}
}

//#define FREE_NN(p) (if ((p) != NULL) {free((p)); (p) = NULL;})


int tlsscan_delete (void *st)
{
	struct tls_state *pqry = st;
	if (pqry == NULL)
		return 0;

	if (pqry->state )
		return 0;

	if(pqry->out_filename != NULL) 
	{
		free(pqry->out_filename);
		pqry->out_filename = NULL;
	}

	if( pqry->str_Atlas != NULL)
	{
		free(pqry->str_Atlas);
		pqry->str_Atlas = NULL;
	}

	if (pqry->host != NULL)
	{
		free(pqry->host);
		pqry->host = NULL;
	}

	if (pqry->port != NULL)
	{
		free(pqry->host);
		pqry->host = NULL;
	}
	return 1;
}

static void timeout_cb(int unused  UNUSED_PARAM, const short event
		UNUSED_PARAM, void *h)
{
	struct tls_qry *qry = (struct tls_qry *)h;

	if(qry->addr_curr == NULL) {
		crondlog_aa(LVL7, "%s %s",  __func__, qry->ui->host);
	} else {
		int active_c = 0;
		if (qry->p != NULL) 
			active_c = qry->active_c;

		crondlog_aa(LVL7, "%s no output yet, dst %s active = %d"
				" active_c = %d %s %s %s",  __func__,
				qry->addrstr, qry->ui->active, active_c, qry->sslv_str, qry->cipher_q, qry->ui->host);

		snprintf(line, DEFAULT_LINE_LENGTH, "%s \"timeout\" : %d", qry->err.size ? ", " : "", DEFAULT_NOREPLY_TIMEOUT);
		buf_add(&qry->err, line, strlen(line));
	}
	print_tls_resp(qry, TRUE);
}



/* See http://archives.seul.org/libevent/users/Jan-2013/msg00039.html */
static int cert_verify_callback(X509_STORE_CTX *x509_ctx, void *arg)
{
	char cert_str[256];
	const char *host = (const char *) arg;
	const char *res_str = "X509_verify_cert failed";
	HostnameValidationResult res = Error;

	/* This is the function that OpenSSL would call if we hadn't called
	 * SSL_CTX_set_cert_verify_callback().  Therefore, we are "wrapping"
	 * the default functionality, rather than replacing it. */
	int ok_so_far = 0;

	X509 *server_cert = NULL;

	/* AA  fixme
	if (qry->opt_ignore_cert) { */
		return 1;
		/*
	}
	*/

	ok_so_far = X509_verify_cert(x509_ctx);

	server_cert = X509_STORE_CTX_get_current_cert(x509_ctx);

	if (server_cert  == NULL)
		return 0;

	if (ok_so_far) {
		res = validate_hostname(host, server_cert);

		switch (res) {
		case MatchFound:
			res_str = "MatchFound";
			break;
		case MatchNotFound:
			res_str = "MatchNotFound";
			break;
		case NoSANPresent:
			res_str = "NoSANPresent";
			break;
		case MalformedCertificate:
			res_str = "MalformedCertificate";
			break;
		case Error:
			res_str = "Error";
			break;
		default:
			res_str = "WTF!";
			break;
		}
	}

	X509_NAME_oneline(X509_get_subject_name (server_cert),
			  cert_str, sizeof (cert_str));
	X509_free(server_cert);

	if (res == MatchFound) {
		printf("https server '%s' has this certificate, "
		       "which looks good to me:\n%s\n",
		       host, cert_str);
		return 1;
	}
	else {
		printf("Got '%s' for hostname '%s' and certificate:\n%s\n",
		       res_str, host, cert_str);
		return 1;
	}
}

static bool verify_ssl_cert (struct tls_qry *qry) {

	/* Attempt to use the system's trusted root certificates.
	 * (This path is only valid for Debian-based systems.) */
	 //if (1 != SSL_CTX_load_verify_locations(qry->ssl_ctx, "/etc/ssl/certs/ca-certificates.crt", NULL)) crondlog(LVL7,"SSL_CTX_load_verify_locations"); 

	/* Ask OpenSSL to verify the server certificate.  Note that this
	 * does NOT include verifying that the hostname is correct.
	 * So, by itself, this means anyone with any legitimate
	 * CA-issued certificate for any website, can impersonate any
	 * other website in the world.  This is not good.  See "The
	 * Most Dangerous Code in the World" article at
	 * https://crypto.stanford.edu/~dabo/pubs/abstracts/ssl-client-bugs.html
	 */

	SSL_CTX_set_verify(qry->ssl_ctx, SSL_VERIFY_PEER, NULL);

	/* This is how we solve the problem mentioned in the previous
	 * comment.  We "wrap" OpenSSL's validation routine in our
	 * own routine, which also validates the hostname by calling
	 * the code provided by iSECPartners.  Note that even though
	 * the "Everything You've Always Wanted to Know About
	 * Certificate Validation With OpenSSL (But Were Afraid to
	 * Ask)" paper from iSECPartners says very explicitly not to
	 * call SSL_CTX_set_cert_verify_callback (at the bottom of
	 * page 2), what we're doing here is safe because our
	 * cert_verify_callback() calls X509_verify_cert(), which is
	 * OpenSSL's built-in routine which would have been called if
	 * we hadn't set the callback.  Therefore, we're just
	 * "wrapping" OpenSSL's routine, not replacing it. */

	SSL_CTX_set_cert_verify_callback (qry->ssl_ctx, cert_verify_callback, (void *) qry->ui->host);
}



static void event_cb(struct bufferevent *bev, short events, void *ptr)
{
	struct tls_qry *qry = ptr;
	struct timeval rectime ;
	if (events & BEV_EVENT_ERROR)
	{
		crondlog_aa(LVL7, "BEV_EVENT_ERROR %s %s %s active = %d %s %s | %s",  __func__,
				qry->ui->host, qry->addrstr, qry->ui->active, qry->sslv_str, qry->cipher_q,
				evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));

		evtimer_del(&qry->timeout_ev);
		snprintf(line, DEFAULT_LINE_LENGTH, "%s \"connect\" : \"%s\"",
				qry->err.size ? ", " : "",
				evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		buf_add(&qry->err, line, strlen(line));
		print_tls_resp(qry, TRUE);
		qry->ssl = NULL; /* I think SSL object is cleaned up after the error ??? */
		return;
	}

	if (events & BEV_EVENT_CONNECTED)
	{
		int active_c = 0;
		if (qry->loc_socklen == 0) {
			qry->loc_socklen= sizeof(qry->loc_sin6);
			getsockname(bufferevent_getfd(bev), &qry->loc_sin6, &qry->loc_socklen);
		}

		gettimeofday(&rectime, NULL);

		qry->triptime = (rectime.tv_sec - qry->start_time.tv_sec)*1000 +
			(rectime.tv_usec - qry->start_time.tv_usec)/1e3;

		if (qry->p != NULL) {
			active_c = qry->p->active_c;
		}

		crondlog_aa(LVL7, "%s BEV_EVENT_CONNECTED active = %d active_c = %d %s %s %s %s",  __func__,
				qry->ui->active, active_c, qry->sslv_str, qry->cipher_q,  qry->addrstr, qry->ui->host);
		write_cb(qry->bev, qry);
		return;
	}
	else {
		printf (" called %s unknown event 0x%x\n", __func__, events);
	}
}

static void http_read_cb(struct bufferevent *bev UNUSED_PARAM, void *ptr)
{
	struct tls_qry  *qry = ptr;
	int active_c = 0;

	if (qry->p != NULL) 
		active_c = qry->p->active_c;

	crondlog_aa(LVL7, "%s BEV_EVENT_CONNECTED active = %d active_c = %d %s %s %s %s",  __func__,
				qry->ui->active, active_c, qry->sslv_str, qry->cipher_q,  qry->addrstr, qry->ui->host);
	evtimer_del(&qry->timeout_ev);
	qry->tls_incomplete = FALSE;
	print_tls_resp(qry, FALSE);
	bufferevent_free(qry->bev);
	qry->bev = NULL;
}
static void write_cb(struct bufferevent *bev, void *ptr)
{
	struct evbuffer *output;
	struct timeval endtime;
	struct tls_qry *qry = ptr;

	// printf("%s: start:\n", __func__);

	for(;;)
	{
		switch(qry->writestate)
		{
		case WRITE_FIRST:
			gettimeofday(&endtime, NULL);
			qry->ttc= (endtime.tv_sec-
				qry->start_time.tv_sec)*1e3 +
				(endtime.tv_usec - qry->start_time.tv_usec)/1e3;
			qry->writestate= WRITE_HEADER;
			continue;
		case WRITE_HEADER:
			output= bufferevent_get_output(bev); 
			evbuffer_add_printf(output, "%s %s HTTP/1.%c\r\n",
				qry->ui->do_get ? "GET" :
				qry->ui->do_head ? "HEAD" : "POST", qry->ui->path,
				qry->ui->do_http10 ? '0' : '1');
			evbuffer_add_printf(output, "Host: %s\r\n",
				qry->ui->host);
			evbuffer_add_printf(output, "Connection: close\r\n");
			evbuffer_add_printf(output, "User-Agent: %s\r\n",
				qry->ui->user_agent);
			evbuffer_add_printf(output, "\r\n");

			qry->writestate = WRITE_DONE;
			// printf("%s: done: \n", __func__);
			return;

		case WRITE_DONE:
			return;
		default:
			printf("writecb: unknown write state: %d\n",
				qry->writestate);
			return;
		}
	}
}

static void local_exit(void *state UNUSED_PARAM)
{

	struct timeval asap = { 0, 2 };
	event_base_loopexit (EventBase,  &asap);
	return;
}

/* called only once. Initialize tls_base variables here */
static void tls_base_new(struct event_base *event_base)
{
	tls_base = xzalloc(sizeof( struct tls_base));
}

static bool tls_arg_validate (int argc, char *argv[], struct tls_state *pqry )
{
	if (optind != argc-1)  {
		crondlog(LVL9 "ERROR no server IP address in input");
		tlsscan_delete(pqry);
		return TRUE;
	}
	else {
		pqry->host = strdup(argv[optind]);
	}
	if (pqry->opt_all_tests ) {
	//	pqry->opt_ssl_v3 = SSL3_VERSION;
	//	pqry->opt_tls_v1 =  TLS1_VERSION;
	//	pqry->opt_tls_v11 = TLS1_1_VERSION;
		pqry->opt_tls_v12 = TLS1_2_VERSION;
	}

	if ( pqry->opt_timeout > 0)
		pqry->timeout_tv.tv_sec = pqry->opt_timeout;

	if(pqry->port == NULL)
		pqry->port = strdup("443");

	return FALSE;
}

/* eperd call this to initialize */
static struct tls_state * tlsscan_init (int argc, char *argv[], void (*done)(void *state))
{
	int c;
	struct tls_state *pqry = NULL;
	LogFile = "/dev/tty";

	if (tls_base == NULL) {
		tls_base_new(EventBase);
		RAND_poll();
		SSL_library_init(); /* call only once this is not reentrant. */
		ERR_load_crypto_strings();
		SSL_load_error_strings();
		OpenSSL_add_all_algorithms();
	}

	if (tls_base == NULL) {
		crondlog(LVL8 "tls_base_new failed");
		return NULL;
	}

	/* initialize a query object */
	pqry = xzalloc(sizeof(struct tls_state));
	pqry->opt_retry_max = 0;
	pqry->port = "443";
	pqry->opt_ignore_cert = 0;
	buf_init(&pqry->err, -1);
	buf_init(&pqry->result, -1);
	pqry->do_http10= 0;
	pqry->do_get= 0;
	pqry->do_head= 1;
	pqry->user_agent= "httpget for atlas.ripe.net";
	pqry->path = "/";
	pqry->done = done;
	pqry->opt_all_tests = TRUE;
	pqry->timeout_tv.tv_sec = 5;
	pqry->opt_out_format = OUTPUT_FMT_CERTS_ARRAY;
//	pqry->opt_out_format = OUTPUT_FMT_CERTS_FULL;

	if (done != NULL)
		evtimer_assign(&pqry->done_ev, EventBase, done_cb, pqry);

	optind = 0;
	while (c= getopt_long(argc, argv, "46O:A?", longopts, NULL), c != -1) {
		switch (c) {
			case '4':
				pqry->opt_v4 = 1;
				break;

			case '6':
				pqry->opt_v6 = 1;
				break;

			case 'A':
				pqry->opt_all_tests = TRUE;
				break;

			case 'O':
                                pqry->out_filename = strdup(optarg);
                                break;

			case 'p':
				pqry->port = strdup(optarg);
				break;

			case 'T' :
				pqry->opt_timeout = strtoul(optarg, NULL, 10);
				if ((pqry->opt_timeout <= 0) | (pqry->opt_timeout > 3600)) {
                                        fprintf(stderr, "ERROR invalid timeout  "
                                                        "-T %s ??.  1 - 3600 seconds\n", optarg);
					tlsscan_delete(pqry);
                                        return (0);
                                }
				break;
		}
	}

	if (tls_arg_validate(argc, argv, pqry))
	{
		crondlog(LVL8 "tls_arg_validate failed");
		return NULL;
	}

	return pqry;
}
 
static bool tls_inst_init(struct tls_state *pqry, struct evutil_addrinfo *addr_curr, int sslv) 
{
	struct  tls_qry *qry = xzalloc(sizeof(struct tls_qry));

	qry->cc = xzalloc(sizeof(struct buf));
	qry->certs = xzalloc(sizeof(struct buf));
	qry->ciphers_s_buf = xzalloc(sizeof(struct buf));
	qry->result = xzalloc(sizeof(struct buf));
	qry->addr_curr = addr_curr;
	qry->ui = pqry;

	evtimer_assign(&qry->free_child_ev, EventBase, free_child_cb, qry);
	evtimer_assign(&qry->timeout_ev, EventBase, timeout_cb, qry);

	if (addr_curr == NULL) { /* there was dns error */
		struct timeval asap = { 0, 0};
		evtimer_add(&qry->timeout_ev, &asap);
		return FALSE;
	}

	pqry->active++;
	qry->ui->q_serial++;
	qry->serial =  qry->ui->q_serial;

	qry->sslv  = sslv;

	qry->tls_incomplete = TRUE;
	tls_inst_start(qry, "ALL:COMPLEMENTOFALL");

	return FALSE;
}

static void dns_cb(int result, struct evutil_addrinfo *res, void *ctx)
{
	struct tls_state *pqry = (struct tls_state *) ctx;
	struct evutil_addrinfo *cur = NULL;

	pqry->addr = res;
	pqry->dns_count =  0;

	if (result != 0)
	{
		snprintf(line, DEFAULT_LINE_LENGTH, "%s \"EVDNS\" : \"%s\"",
				pqry->err.size ? ", " : "",
				evutil_gai_strerror(result));
		buf_add(&pqry->err, line, strlen(line));
		pqry->addr = NULL;
		tls_inst_init(pqry, cur, 0); /* initialize qry and print error */
		return;
	}

	for (cur = res; cur != NULL; cur = cur->ai_next) {
		pqry->dns_count++;
		if (pqry->opt_all_tests) {
			// tls_inst_init(pqry, cur, pqry->opt_ssl_v3);
			// tls_inst_init(pqry, cur, pqry->opt_tls_v1);
			// tls_inst_init(pqry, cur, pqry->opt_tls_v11);
			tls_inst_init(pqry, cur, pqry->opt_tls_v12);
		}
		else  {
			tls_inst_init(pqry, cur, 0);
		}
	}
}

static void printErrorQuick (struct tls_state *pqry) 
{
	FILE *fh;

	/* careful not to use json macros they will write over real results */

	struct timeval now;
	if (pqry->out_filename)
	{
		fh= fopen(pqry->out_filename, "a");
		if (!fh){
			crondlog(LVL8 "unable to append to '%s'",
					pqry->out_filename);
			return;
		}
	}
	else
		fh = stdout;

	fprintf(fh, "RESULT { ");
	fprintf(fh, "\"fw\" : \"%d\",", get_atlas_fw_version());
	fprintf(fh, "\"id\" : 9203 ,");
	gettimeofday(&now, NULL);
	fprintf(fh, "\"time\" : %ld ,",  now.tv_sec);

	fprintf(fh, "\"error\" : [{ ");
	fprintf(fh, "\"query busy\": \"not starting a new one. previous one is not done yet\"}");
	if(pqry->str_Atlas)
	{
		fprintf(fh, ",{");
		fprintf(fh, "\"id\" : \"%s\"",  pqry->str_Atlas);
		fprintf(fh, ",\"start time\" : %ld",  pqry->start_time.tv_sec);
		if(pqry->retry) {
			fprintf(fh, ",\"retry\": %d",  pqry->retry);

		}
		if(pqry->opt_retry_max) {
			fprintf(fh, ",\"retry max\": %d",  pqry->opt_retry_max);
		}
		fprintf(fh, "}");
	}
	fprintf(fh,"]}");

	if (pqry->out_filename)
		fclose(fh);
}

void tlsscan_start (struct tls_state *pqry)
{
	switch(pqry->state)
	{
		case STATUS_FREE:
			pqry->state = STATUS_START;
			break;
		default:
			printErrorQuick(pqry);
			/* this query is still active. can't start another one */
			return;
	}

	gettimeofday(&pqry->start_time, NULL);

	pqry->hints.ai_family = AF_UNSPEC;

	if(pqry->opt_v6 && !pqry->opt_v4)
		pqry->hints.ai_family = AF_INET6;

	if(pqry->opt_v4 && !pqry->opt_v6)
		pqry->hints.ai_family = AF_INET;

	pqry->hints.ai_flags = 0;
	pqry->hints.ai_socktype = SOCK_STREAM;
	pqry->hints.ai_flags = 0;

	pqry->q_serial = 0;
	pqry->q_success = 0;
	pqry->active = 0;
	pqry->retry = 0;
	pqry->dns_count = 0;

	(void) evdns_getaddrinfo(DnsBase, pqry->host, "443", &pqry->hints,
			dns_cb, pqry);
	evtimer_assign(&pqry->free_inst_ev, EventBase, free_pqry_inst_cb, pqry);
}

int evtlsscan_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int evtlsscan_main(int argc, char **argv)
{
	struct tls_state *pqry = NULL; /* instance per host(user input) */

	EventBase = event_base_new();
	if (!EventBase)
	{
		crondlog(LVL9 "ERROR: critical event_base_new failed"); /* exits */
		return 1;
	}

	DnsBase = evdns_base_new(EventBase, 1);
	if (!DnsBase) {
		crondlog(DIE9 "ERROR: critical evdns_base_new failed"); /* exits */
		event_base_free (EventBase);
		return 1;
	}

	pqry = tlsscan_init(argc, argv, local_exit);

	if(pqry == NULL) {
		crondlog(DIE9 "ERROR: critical tlsscan_init failed"); /* exits */
		event_base_free (EventBase);
		return 1;
	}

	tlsscan_start(pqry);

	event_base_dispatch(EventBase);
	event_base_loopbreak (EventBase);

	if(EventBase)
		event_base_free(EventBase);

	return 0;
}

static void crondlog_aa(const char *ctl, char *fmt, ...)
{
	va_list va;
	char buff[1000];
	int level = (ctl[0] & 0x1f);

	va_start(va, fmt);
	vsnprintf(buff, 1000 - 1, fmt, va);
	printf("%s\n", buff);
}

struct testops tlsscan_ops = {tlsscan_init, tlsscan_start, tlsscan_delete};
