/*
 * Copyright (c) 2009 Rocco Carbone <ro...@tecsiel.it>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _EVENT2_PING_H_
#define _EVENT2_PING_H_

#ifdef __cplusplus
extern "C" {
#endif

/* For integer types. */
#include <event2/util.h>

/* Error codes */
#define PING_ERR_NONE      0
#define PING_ERR_TIMEOUT   1       /* Communication with the host timed out */
#define PING_ERR_DUP       2	   /* Duplicate packet */
#define PING_ERR_DONE      3	   /* Max number of packets to send has been
				    * reached.
				    */
#define PING_ERR_SENDTO    4       /* Sendto system call failed */
#define PING_ERR_SHUTDOWN 10       /* The request was canceled because the PING subsystem was shut down */
#define PING_ERR_CANCEL   12       /* The request was canceled via a call to evping_cancel_request */
#define PING_ERR_UNKNOWN  16       /* An unknown error occurred */


/**
 * The callback that contains the results from an ICMP Echo Request.
 * - result is either one of the error codes previuosly defined
 * - bytes is is either the number of bytes returned in the Echo Reply or -1 in the event of error
 * - sa contains to remote IP address
 * - socklen is the length if sa
 * - seq is sequence number
 * - ttl is IP time to live
 * - elapsed is a timeval holding the time spent in the request
 * - arg is the user data passed at the time the activity has been started
 */
typedef void (*evping_callback_type) (int result, int bytes,
	struct sockaddr *sa, socklen_t socklen,
	struct sockaddr *loc_sa, socklen_t loc_socklen,
	int seq, int ttl, struct timeval * elapsed, void * arg);


struct evping_base;
struct event_base;



/**
  Initialize the asynchronous PING library.

  This function initializes support for non-blocking ICMP Echo Request.

  @param event_base the event base to associate the ping client with
  @return 0 if successful, or -1 if an error occurred
  @see evping_base_free()
 */
struct evping_base * evping_base_new(struct event_base *event_base);


/**
  Shut down the asynchronous PING library and terminate all active requests.

  If the 'fail_requests' option is enabled, all active requests will return
  an empty result with the error flag set to PING_ERR_SHUTDOWN. Otherwise,
  the requests will be silently discarded.

  @param evping_base the evping base to free
  @param fail_requests if zero, active requests will be aborted; if non-zero,
		active requests will return PING_ERR_SHUTDOWN.
  @see evping_base_new()
 */
void evping_base_free(struct evping_base *base, int fail_requests);


/**
  Add a host.

  The address should be an IPv4 or IPv6 address.

  @param base the evping_base to which to add the host
  @param address an IP address in human readable format
  @return 0 if successful, or -1 if an error occurred
 */
struct evping_host *evping_base_host_add(struct evping_base *base,	
	sa_family_t af, const char *name);


/**
  Set callback for a host.

  @param host the evping_host to which to apply this operation
  @param callback a callback function to invoke when each request is completed/elapsed
  @param ptr an argument to pass to the callback function
 */

/**
  Send ICMP ECHO_REQUEST to a host.

  @param host the evping_host to which to apply this operation
 */
void evping_ping(struct evping_host *host, size_t size,
	evping_callback_type callback, void *ptr, void (*done)(void *state));

void evping_start(struct evping_host *host, int count);

void evping_delete(struct evping_host *host);

/**
  Get the number of added hosts.

  This returns the number of added hosts (that are the
  number of hosts being pinged).  This is useful for double-checking
  whether our calls to the various hosts configuration functions
  have been successful.

  @param base the evping_base to which to apply this operation
  @return the number of hosts configured for being pinged
  @see evping_base_hosts_add()
 */
int evping_base_count_hosts(struct evping_base *base);


/**
  Convert a PING error code to a string.

  @param err the PING error code
  @return a string containing an explanation of the error code
*/
const char *evping_err_to_string(int err);


/**
  Convert a timeval to microseconds

  @param tv contains a time
  @return the number of microseconds
*/
time_t tvtousecs (struct timeval *tv);


#ifdef __cplusplus
}
#endif

#endif  /* !_EVENT2_PING_H_ */
