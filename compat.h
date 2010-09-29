#ifndef MAV_COMPAT_H
#define MAV_COMPAT_H
/*
 * mod_auth_vas: VAS authentication module for Apache.
 * 
 *   Copyright 2007 Quest Software, Inc.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *   a. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   b. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *   c. Neither the name of Quest Software, Inc. nor the names of its
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT
 *   NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 *   FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 *   SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY
 *   DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 *   GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *   WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 *   THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * compat.h: various #defines, cross-compatibility macros and convenience
 *           macros.
 */

/* From the GCC 4.1 manual */
#if __STDC_VERSION__ < 19901L
# if __GNUC__ >= 2
#  define __func__ __FUNCTION__
# else
#  define __func__ "<unknown>"
# endif
#endif

/* To determine the version of Apache */
#include <httpd.h>
#include <http_config.h>

#if !defined(STANDARD20_MODULE_STUFF)
# define APXS1 1 /* Apache 1.3.x */
#endif

#if !HAVE_MOD_AUTH_H /* Apache < 2.2 */
typedef enum {
    AUTH_DENIED,
    AUTH_GRANTED,
    AUTH_USER_FOUND,
    AUTH_USER_NOT_FOUND,
    AUTH_GENERAL_ERROR
} authn_status;
#endif /* !HAVE_MOD_AUTH_H */

#define __APPNAME__ "mod_auth_vas"

/*
 * Apache2 compatibility wrappers around the Apache1 API.
 * This is pretty awful, but it allows this module to
 * compile and run under both versions of Apache.
 */
#if defined(APXS1)
# include "multithread.h"
# define AP_MODULE_DECLARE_DATA MODULE_VAR_EXPORT
# define apr_array_header_t	array_header
# define apr_base64_decode	ap_base64decode
# define apr_base64_decode_len	ap_base64decode_len
# define apr_base64_encode	ap_base64encode
# define apr_base64_encode_len	ap_base64encode_len
# define apr_cpystrn		ap_cpystrn
# define apr_interval_time_t	uint64_t
# define apr_status_t		int
# define apr_pcalloc		ap_pcalloc
# define apr_palloc		ap_palloc
# define apr_pool_cleanup_register ap_register_cleanup
# define apr_psprintf		ap_psprintf
# define apr_pstrcat		ap_pstrcat
# define apr_pstrdup		ap_pstrdup
# define apr_pool_t		pool
# define apr_ssize_t		ssize_t
# define apr_table_t		table
# define apr_table_clear	ap_clear_table
# define apr_table_do		ap_table_do
# define apr_table_add		ap_table_add
# define apr_table_addn		ap_table_addn
# define apr_table_get		ap_table_get
# define apr_table_make		ap_make_table
# define apr_table_set		ap_table_set
# define apr_table_setn		ap_table_setn
# define apr_thread_mutex_t	mutex
# define apr_thread_mutex_lock ap_acquire_mutex
# define apr_thread_mutex_unlock ap_release_mutex
# define apr_time_t		uint64_t
# define APR_USEC_PER_SEC	1000000ul
# define apr_time_now()		(((apr_time_t)time(NULL)) * APR_USEC_PER_SEC)
# define apr_time_from_sec(s)	((s) * APR_USEC_PER_SEC)
# define apr_time_sec(us)	((us) / APR_USEC_PER_SEC)
# define AP_INIT_FLAG(d,f,m,w,h)  {d,f,m,w,FLAG,h}
# define AP_INIT_TAKE1(d,f,m,w,h) {d,f,m,w,TAKE1,h}
# define AP_INIT_RAW_ARGS(d,f,m,w,h) {d,f,m,w,RAW_ARGS,h}
# define AP_METHOD_BIT		1
# define APR_OFFSETOF(t,f) 	(void *)XtOffsetOf(t,f)
/* Always allocate RUSER(r) from RUSER_POOL(r)
 * see http://httpd.apache.org/docs/1.3/misc/API.html#pools-used */
# define RUSER(r) 		(r)->connection->user
# define RUSER_POOL(r)		(r)->connection->pool
# define RAUTHTYPE(r) 		(r)->connection->ap_auth_type
# if __GNUC__
#  define LOG_RERROR(l,x,r,fmt,args...) \
	ap_log_rerror(APLOG_MARK,l|APLOG_NOERRNO,r, "[%s] %s", __APPNAME__, apr_psprintf(RUSER_POOL(r), fmt ,##args))
#  define LOG_ERROR(l,x,s,fmt,args...) do {\
        char _BUFFER[HUGE_STRING_LEN];\
        apr_snprintf(_BUFFER, sizeof _BUFFER, fmt, ##args);\
	ap_log_error(APLOG_MARK,l|APLOG_NOERRNO,s, "[%s] %s", __APPNAME__, _BUFFER);\
} while (0)
#  define LOG_RERROR_ERRNO(l,x,r,fmt,args...) \
	ap_log_rerror(APLOG_MARK,l,r, "[%s] %s", apr_psprintf(RUSER_POOL(r), fmt ,##args))
#  define LOG_P_ERROR(l,x,p,fmt,args...) \
	ap_log_printf(0, "[%s] %s", apr_psprintf(p, fmt, ##args))
# else /* C99 */
#  define LOG_RERROR(l,x,r, ...) \
	ap_log_rerror(APLOG_MARK,l|APLOG_NOERRNO,r, "[%s] %s", apr_psprintf(RUSER_POOL(r),__VA_ARGS__))
#  define LOG_ERROR(l,x,s, ...) do {\
	char _BUFFER[HUGE_STRING_LEN];\
        apr_snprintf(_BUFFER, sizeof _BUFFER, __VA_ARGS__);\
	ap_log_error(APLOG_MARK,l|APLOG_NOERRNO,s, "[%s] %s", _BUFFER);\
} while (0)
#  define LOG_RERROR_ERRNO(l,x,r, ...) \
	ap_log_rerror(APLOG_MARK,l,r, "[%s] %s", apr_psprintf(RUSER_POOL(r), __VA_ARGS__))
#  define LOG_P_ERROR(l,x,p, ...) \
	ap_log_printf(0, "[%s] %s", apr_psprintf(p, __VA_ARGS__))
# endif

# define APR_DECLARE(x) x
# define APR_DECLARE_NONSTD(x) x
# include "mav_apr_hash.h"

#define CLEANUP_RET_TYPE 	void
#define CLEANUP_RETURN		return

/* Proxy type (forward proxy) */
# define PROXYREQ_PROXY STD_PROXY

#else /* !APXS1 (Apache 2.0.x) */

# include <apr_strings.h>
# include <apr_tables.h>
# include <apr_base64.h>
# include <apr_general.h>
# include <apr_hash.h>
/* Always allocate RUSER(r) from RUSER_POOL(r) for the sake of Apache 1.3.
 * see http://httpd.apache.org/docs/1.3/misc/API.html#pools-used */
# define RUSER(r) (r)->user
# define RUSER_POOL(r) (r)->pool
# define RAUTHTYPE(r) (r)->ap_auth_type
# define SERVPOOL(s) (s)->process->pool

# if __GNUC__
#  define LOG_RERROR(l,x,r,fmt,args...) \
	ap_log_rerror(APLOG_MARK,l|APLOG_NOERRNO,x,r, "[%s] %s", __APPNAME__, apr_psprintf(RUSER_POOL(r), fmt ,##args))
#  define LOG_ERROR(l,x,s,fmt,args...) \
 	ap_log_error(APLOG_MARK,l|APLOG_NOERRNO,x,s, "[%s] %s", __APPNAME__, apr_psprintf(SERVPOOL(s), fmt, ##args))
#  define LOG_RERROR_ERRNO(l,x,r,fmt,args...) \
	ap_log_rerror(APLOG_MARK,l,x,r, "[%s] %s", __APPNAME__, apr_psprintf(RUSER_POOL(r), fmt ,##args))
#  define LOG_P_ERROR(l,x,p,fmt,args...) \
	ap_log_perror(APLOG_MARK,l,x,p, "[%s] %s", __APPNAME__, apr_psprintf(p, fmt ,##args))
# else /* C99 */
#  define LOG_RERROR(l,x,r,...) \
	ap_log_rerror(APLOG_MARK,l|APLOG_NOERRNO,x,r, "[%s] %s", __APPNAME__, apr_psprintf(RUSER_POOL(r), __VA_ARGS__))
#  define LOG_ERROR(l,x,s,...) \
	ap_log_error(APLOG_MARK,l|APLOG_NOERRNO,x,s, "[%s] %s", __APPNAME__, apr_psprintf(SERVPOOL(s), __VA_ARGS__))
#  define LOG_RERROR_ERRNO(l,x,r,...) \
	ap_log_rerror(APLOG_MARK,l,x,r, "[%s] %s", __APPNAME__, apr_psprintf(RUSER_POOL(r), __VA_ARGS__))
#  define LOG_P_ERROR(l,x,p,...) \
	ap_log_perror(APLOG_MARK,l,x,p, "[%s] %s", __APPNAME__, apr_psprintf(p, __VA_ARGS__))
# endif

#define CLEANUP_RET_TYPE 	apr_status_t
#define CLEANUP_RETURN		return OK

#endif /* Apache 2.0.x */

/*
 * Trace macros for verbose debugging.
 *  TRACE_P - trace using a memory pool
 *  TRACE_S - trace in a server context
 *  TRACE_R - trace in a request context
 *
 * Note: TRACE_P macro does not work for Apache 1 because
 *  ap_log_perror() is not implemented on that platform.
 */
#if defined(MODAUTHVAS_VERBOSE)
# if __GNUC__
#  define TRACE_S(s,f,a...)     LOG_ERROR(APLOG_DEBUG,OK,s,f,##a)
#  define TRACE_R(r,f,a...)	LOG_RERROR(APLOG_DEBUG,OK,r,f,##a)
# else /* C99 */
#  define TRACE_S(s,...)	LOG_ERROR(APLOG_DEBUG,OK,s,__VA_ARGS__)
#  define TRACE_R(r,...)	LOG_RERROR(APLOG_DEBUG,OK,r,__VA_ARGS__)
# endif
# if !defined(APXS1)
#  if __GNUC__
#   define TRACE_P(p,f,a...) ap_log_perror(APLOG_MARK,APLOG_DEBUG,OK,p,f ,##a)
#  else /* C99 */
#   define TRACE_P(p,...) ap_log_perror(APLOG_MARK,APLOG_DEBUG,OK,p,__VA_ARGS__)
#  endif
# else
#  if __GNUC__
#   define TRACE_P(p,f,a...)	LOG_ERROR(APLOG_DEBUG,OK,0,f ,##a)
#  else /* C99 */
#   define TRACE_P(p,...)	LOG_ERROR(APLOG_DEBUG,OK,0,__VA_ARGS__)
#  endif
# endif
#else
# if __GNUC__
#  define TRACE_P(p,f,a...) /* nothing */
#  define TRACE_S(s,f,a...) /* nothing */
#  define TRACE_R(r,f,a...) /* nothing */
# else /* C99 */
#  define TRACE_P(p,...) /* nothing */
#  define TRACE_S(s,...) /* nothing */
#  define TRACE_R(r,...) /* nothing */
# endif
#endif

/*
 * Diagnostic assertions that may degrade performance.
 * Note: When an assertion fails, it indicates a *logical bug*. Do 
 * not use this macro for checking external-supplied parameters or 
 * preconditions, or for dealing with expected/possible runtime errors.
 */
#if defined(MODAUTHVAS_DIAGNOSTIC)
# define ASSERT(x)	   ap_assert(x)
#else
# define ASSERT(x)	   (void)0
#endif

/*
 * Convenience macros for obtaining per-server and per-dir config info
 * from various configuration vectors.
 */
#define GET_SERVER_CONFIG(cv) \
    (auth_vas_server_config *)ap_get_module_config(cv, &auth_vas_module)
#define GET_DIR_CONFIG(cv) \
    (auth_vas_dir_config *)ap_get_module_config(cv, &auth_vas_module)

/*
 * Macros for keeping the VAS context in the request record notes.
 * NB Request notes may not always be available (eg apache 1.3 without EAPI).
 */
#if defined(APXS1) /* Apache 1.3.x */
# if defined(EAPI) /* extended API available */
#  include "ap_ctx.h"
#  define RNOTE_KEY "rc.quest.com/mod_auth_vas/request_note"
#  define GET_RNOTE(r) 						\
    (auth_vas_rnote *)((r)->ctx					\
	? ap_ctx_get((r)->ctx, RNOTE_KEY)			\
	: NULL)
#  define SET_RNOTE(r, note)					\
    do {							\
       if (!(r)->ctx)						\
	   (r)->ctx = ap_ctx_new((r)->pool);			\
       ap_ctx_set((r)->ctx, RNOTE_KEY, note);			\
    } while (0)
# else /* !EAPI */
 # warning "No EAPI support detected; diminished functionality"
#  define GET_RNOTE(r)		NULL
#  define SET_RNOTE(r, note)	/* */
# endif /* EAPI */
#else /* apache 2.0.x */
# define GET_RNOTE(r) 						\
    (auth_vas_rnote *)ap_get_module_config((r)->request_config, \
					       &auth_vas_module)
# define SET_RNOTE(r, note) 					\
    ap_set_module_config((r)->request_config, &auth_vas_module, note)
#endif /* apache 2.0.x */

#ifdef __GNUC__
# define MAV_UNUSED __attribute__((__unused__))
#else
# define MAV_UNUSED
#endif

#define streq(a,b) (strcmp((a),(b))==0)

#define IS_FORWARD_PROXY_REQUEST(r) ((r)->proxyreq == PROXYREQ_PROXY)

#endif /* MAV_COMPAT_H */
