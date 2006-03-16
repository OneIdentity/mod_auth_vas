/*
 * mod_auth_vas: VAS authentication module for Apache.
 * Copyright 2004-2005, Vintela, Inc.
 * $Vintela: mod_auth_vas.c,v 1.22 2005/04/26 04:00:58 davidl Exp $
 *
 *   Copyright (c) 2004, 2005 Vintela, Inc.
 *
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *   a. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *   b. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *   c. Neither the name of Vintela, Inc. nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission. THIS SOFTWARE IS PROVIDED
 *   BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS
 *   OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 *   BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 *   OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 *   OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *   BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *   WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 *   OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 *   EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 *  MODAUTHVAS_VERBOSE	- define this to get verbose debug level logging
 *  MODAUTHVAS_DIAGNOSTIC - define this to enable assertions
 */

#include <vas.h>
#include <vas_gss.h>

#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>

#if HAVE_UNIX_SUEXEC
# if APR_HAS_USER
#  include <unixd.h>
# else
#  warning "HAVE_UNIX_SUEXEC disabled without APR_HAS_USER"
#  undef HAVE_UNIX_SUEXEC
# endif
#endif

#if !defined(STANDARD20_MODULE_STUFF)
# define APXS1 /* Apache 1.3.x */
#endif

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
# define apr_status_t		int
# define apr_pcalloc		ap_pcalloc
# define apr_palloc		ap_palloc
# define apr_pool_cleanup_register ap_register_cleanup
# define apr_psprintf		ap_psprintf
# define apr_pstrdup		ap_pstrdup
# define apr_pool_t		pool
# define apr_table_add		ap_table_add
# define apr_table_get		ap_table_get
# define apr_table_set		ap_table_set
# define apr_thread_mutex_t	mutex
# define apr_thread_mutex_lock ap_acquire_mutex
# define apr_thread_mutex_unlock ap_release_mutex
# define AP_INIT_FLAG(d,f,m,w,h)  {d,f,m,w,FLAG,h}
# define AP_INIT_TAKE1(d,f,m,w,h) {d,f,m,w,TAKE1,h}
# define AP_METHOD_BIT		1
# define APR_OFFSETOF(t,f) 	(void *)XtOffsetOf(t,f)
# define RUSER(r) 		(r)->connection->user
# define RAUTHTYPE(r) 		(r)->connection->ap_auth_type
# define LOG_RERROR(l,x,r,fmt,args...) \
	ap_log_rerror(APLOG_MARK,l|APLOG_NOERRNO,r,fmt , ## args)
# define LOG_ERROR(l,x,s,fmt,args...) \
	ap_log_error(APLOG_MARK,l|APLOG_NOERRNO,s,fmt , ## args)

#define CLEANUP_RET_TYPE 	void
#define CLEANUP_RETURN		return

# else /* !APXS1 (Apache 2.0.x) */

# include <apr_strings.h>
# include <apr_tables.h>
# include <apr_base64.h>
# include <apr_general.h>
# define RUSER(r) (r)->user
# define RAUTHTYPE(r) (r)->ap_auth_type
# define LOG_RERROR(l,x,r,fmt,args...) \
	ap_log_rerror(APLOG_MARK,l|APLOG_NOERRNO,x,r,fmt , ## args)
# define LOG_ERROR(l,x,s,fmt,args...) \
	ap_log_error(APLOG_MARK,l|APLOG_NOERRNO,x,s,fmt , ## args)

#define CLEANUP_RET_TYPE 	apr_status_t
#define CLEANUP_RETURN		return OK

#endif /* Apache 2.0.x */

/*
 * Miscellaneous constants.
 */
#define VAS_AUTH_TYPE		    "VAS"
#define DEFAULT_SERVICE_PRINCIPAL   "HTTP/"
#define MODAUTHVAS_VERSION	    "3.1.2"

/* Flag values for directory configuration */
#define FLAG_UNSET	(-1)
#define FLAG_OFF	0
#define FLAG_ON		1
#define FLAG_MERGE(basef,newf) ((newf) == FLAG_UNSET ? (basef) : (newf))

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
# define TRACE_S(s,f,a...) LOG_ERROR(APLOG_DEBUG,OK,s,f ,##a)
# define TRACE_R(r,f,a...) LOG_RERROR(APLOG_DEBUG,OK,r,f ,##a)
# if defined(APXS1)
#  define TRACE_P(p,f,a...) /* Cannot log */
# else
#  define TRACE_P(p,f,a...) ap_log_perror(APLOG_MARK,APLOG_DEBUG,OK,p,f ,##a)
# endif
#else
# define TRACE_P(p,f,a...) /* nothing */
# define TRACE_S(s,f,a...) /* nothing */
# define TRACE_R(r,f,a...) /* nothing */
#endif

/*
 * Diagnostic assertions that may degrade performance
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
 * Macros for keeping the GSSAPI context in the connection record.
 */

#if defined(APXS1) /* Apache 1.3.x */
# if defined(EAPI)
#  include "ap_ctx.h"
#  define CONN_NOTE_KEY "rc.vintela.com/mod_auth_vas/conn_note"
#  define GET_CONN_NOTE(c) \
    (auth_vas_conn_note *)((c)->ctx			\
	? ap_ctx_get((c)->ctx, CONN_NOTE_KEY)		\
	: NULL)
#  define SET_CONN_NOTE(c, note)				\
    do {						\
       if (!(c)->ctx)					\
	   (c)->ctx = ap_ctx_new((c)->pool);		\
       ap_ctx_set((c)->ctx, CONN_NOTE_KEY, note);	\
    } while (0)
# else /* !EAPI */
#  define GET_CONN_NOTE(c)		NULL
#  define SET_CONN_NOTE(c, note)	/* */
# endif /* EAPI */
#else /* apache 2.0.x */
# define GET_CONN_NOTE(c) \
    (auth_vas_conn_note *)ap_get_module_config((c)->conn_config, \
					       &auth_vas_module)
# define SET_CONN_NOTE(c, note) \
    ap_set_module_config((c)->conn_config, &auth_vas_module, note)
#endif /* apache 2.0.x */

/*
 * Per-server configuration structure - exists for lifetime of server process.
 */
typedef struct {
    const char *service_principal;	/* VASServicePrincipal or NULL */
    char *default_realm;		/* AuthVasDefaultRealm (never NULL) */
    vas_t *vas;				/* Library context:
					 * call LOCK_VAS() before using */
} auth_vas_server_config;

/*
 * Per-directory configuration data - computed while traversing htaccess.
 */
typedef struct {
    int auth_basic;			/* VASAuthBasic [on|off] or UNSET */
} auth_vas_dir_config;

/*
 * Per-connection note data - exists for lifetime of connection.
 */
typedef struct {
    gss_ctx_id_t gss_ctx;		/* Negotiation context */
    gss_buffer_desc client;		/* exported mech name */
} auth_vas_conn_note;


/* Forward declaration for module structure: see bottom of this file. */
module AP_MODULE_DECLARE_DATA auth_vas_module;

/*
 * The per-process VAS mutex.
 *
 * This mutex is allocated during the child_init hook (as child
 * processes are created.) Threads must acquire a lock on
 * the mutex before using a vas context since libvas is not
 * thread-safe.
 *
 * If a VAS operation takes too long, threads will suffer.
 * NOTE: This should really be moved into libvas; or the libvas
 * API should be made thread-safe.
 */
static apr_thread_mutex_t *auth_vas_libvas_mutex;

/* Intra-process lock around the VAS library. */
#if defined(MODAUTHVAS_DIAGNOSTIC)
# define LOCK_VAS()   auth_vas_lock()
# define UNLOCK_VAS() auth_vas_unlock()
static void auth_vas_lock(void);
static void auth_vas_unlock(void);

static void auth_vas_lock() {
	apr_status_t error;
	ASSERT(auth_vas_libvas_mutex != NULL);
	error = apr_thread_mutex_lock(auth_vas_libvas_mutex);
	ASSERT(error == OK);
}
static void auth_vas_unlock() {
	apr_status_t error;
	ASSERT(auth_vas_libvas_mutex != NULL);
	error = apr_thread_mutex_unlock(auth_vas_libvas_mutex);
	ASSERT(error == OK);
}
#else
# define LOCK_VAS()   (void)apr_thread_mutex_lock(auth_vas_libvas_mutex)
# define UNLOCK_VAS() (void)apr_thread_mutex_unlock(auth_vas_libvas_mutex)
#endif

/* Sets a string slot in the server config */
static const char *
server_set_string_slot(cmd_parms *cmd, void *ignored, const char *arg)
{
	return ap_set_string_slot(cmd, 
	    (char *)GET_SERVER_CONFIG(cmd->server->module_config), (char *)arg);
}

/*
 * Configuration commands table for this module.
 */
#define CMD_USEBASIC	"AuthVasUseBasic"
#define CMD_SPN		"AuthVasServicePrincipal"
#define CMD_REALM	"AuthVasDefaultRealm"
static const command_rec auth_vas_cmds[] =
{
    AP_INIT_FLAG(CMD_USEBASIC, ap_set_flag_slot,
		APR_OFFSETOF(auth_vas_dir_config, auth_basic),
		ACCESS_CONF | OR_AUTHCFG,
		"Basic Authentication using Active Directory"),
    AP_INIT_TAKE1(CMD_SPN, server_set_string_slot,
		APR_OFFSETOF(auth_vas_server_config, service_principal),
		RSRC_CONF,
		"Service Principal Name for the server"),
    AP_INIT_TAKE1(CMD_REALM, server_set_string_slot,
		APR_OFFSETOF(auth_vas_server_config, default_realm),
		RSRC_CONF,
		"Default realm for authorization"),
    { NULL }
};

/*
 * A static string containing the compile options, that can be revealed
 * by strings(1)
 */
static char module_info[] = 
#if defined(AP_DEBUG)
	" AP_DEBUG"
#endif
#if defined(APXS1)
	" AP1"
#else
	" AP2"
#endif
#if defined(EAPI)
	" EAPI"
#endif
#if defined(MODAUTHVAS_VERBOSE)
	" VERBOSE"
#endif
#if defined(MODAUTHVAS_DIAGNOSTIC)
	" DIAGNOSTIC"
#endif
#if HAVE_UNIX_SUEXEC
	" SUEXEC"
#endif
	;

#if defined(APXS1)
/* Compatibility functions not found in Apache 1.3.x */
/**
 * Duplicates a string of given size.
 *   @param pool memory pool to allocate from
 *   @param s pointer to beginning of string
 *   @param n length of string to duplicate
 *   @return a nul-terminated string allocated in the pool,
 *	     containing the first n bytes of s.
 */
static char *
apr_pstrmemdup(struct pool *pool, const char *s, int n)
{
    char *cp;

    ASSERT(pool != NULL);
    ASSERT(n == 0 || s != NULL);
    ASSERT(n >= 0);
    cp = ap_palloc(pool, n + 1);
    if (cp != NULL) {
	memcpy(cp, s, n);
	cp[n] = '\0';
    }
    return cp;
}

/**
 * A no-op cleanup function.
 *  @param data cleanup context
 */
static CLEANUP_RET_TYPE
apr_pool_cleanup_null(void *data)
{
    	/* nothing */
}
#endif

/**
 * Checks that the VAS server context is initialized and available.
 * Returns true if the context was initialised,
 * otherwise logs an error and returns false.
 * Callers should not attempt to LOCK or UNLOCK the VAS context if this
 * function returns false.
 *   @param s A server configuration structure.
 */
static int
server_ctx_is_valid(server_rec *s)
{
    auth_vas_server_config *sc;

    ASSERT(s != NULL);
    sc = GET_SERVER_CONFIG(s->module_config);
    ASSERT(sc != NULL);
    return sc->vas != NULL;
}

/**
 * Checks if the previously authenticated user matches a particular name.
 * The check is partially case-sensitive. 
 * (XXX Should it be completely case insensitive?)
 *   @param r The authenticated request
 *   @param name The name of the user to check
 *   @return OK if the user has the same name, otherwise HTTP_...
 */
static int
match_user(request_rec *r, const char *name)
{
    const auth_vas_server_config *sc;
    const char *p;

    ASSERT(r != NULL);
    ASSERT(name != NULL);
    ASSERT(RUSER(r) != NULL);

    TRACE_R(r, "match_user: name=%s RUSER=%s", name, RUSER(r));

    sc = GET_SERVER_CONFIG(r->server->module_config);
    ASSERT(sc != NULL);

    if (strcmp(RUSER(r), name) == 0)
	return OK;

    /* Return OK if RUSER(r) == name + '@' + sc->default_realm */
    if (sc->default_realm && (p = strchr(RUSER(r), '@')) != NULL) {
	int namelen = strlen(name);
	int userlen = p - RUSER(r);

	ASSERT(RUSER(r)[userlen] == '@');
	if (namelen == userlen &&
	    strncmp(RUSER(r), name, namelen) == 0 &&
	    strcasecmp(RUSER(r) + namelen + 1, sc->default_realm) == 0)
	{
		TRACE_R(r, "match_user: RUSER=%s name=%s realm=%s",
			 name, RUSER(r), sc->default_realm);
		return OK;
	}
    }
    return HTTP_FORBIDDEN;
}


/**
 * Checks if the authenticated user belongs to a particular group.
 * Assumes the server config has been initialised.
 *   @param r The authenticated request
 *   @param name The name of the group to check
 *   @return OK if group contains user, otherwise HTTP_...
 */
static int
match_group(request_rec *r, const char *name)
{
    int error;
    const auth_vas_server_config *sc;

    ASSERT(r != NULL);
    ASSERT(name != NULL);
    ASSERT(RUSER(r) != NULL);

    sc = GET_SERVER_CONFIG(r->server->module_config);
    ASSERT(sc != NULL);
    ASSERT(sc->vas != NULL);

    LOCK_VAS();
    error = vas_group_contains_user(sc->vas, name, RUSER(r));
    if (error == -1) {
	LOG_RERROR(APLOG_ERR, 0, r,
	   "vas_group_contains_user(%s): %s", name,
	   vas_error_str(sc->vas));
    }
    UNLOCK_VAS();

    return error == 1 ? OK : HTTP_FORBIDDEN;
}

/**
 * Checks if the given user belongs to the given container.
 * Assumes the server config has been initialised.
 *   @param r The authenticated request
 *   @param name The name of the container to check
 *   @return OK if container contains user, otherwise HTTP_...
 */
static int
match_container(request_rec *r, const char *name)
{
    int error;
    const auth_vas_server_config *sc;

    ASSERT(r != NULL);
    ASSERT(name != NULL);
    ASSERT(RUSER(r) != NULL);

    sc = GET_SERVER_CONFIG(r->server->module_config);
    ASSERT(sc != NULL);
    ASSERT(sc->vas != NULL);

    LOCK_VAS();
    error = vas_ou_contains_user(sc->vas, name, RUSER(r));
    if (error == -1) {
	LOG_RERROR(APLOG_ERR, 0, r,
	   "vas_ou_contains_user(%s): %s", name,
	   vas_error_str(sc->vas));
    }
    UNLOCK_VAS();

    return error == 1 ? OK : HTTP_FORBIDDEN;
}

/**
 * Checks that the user is valid.
 *   @param r The authenticated request
 *   @param ignored Ignored argument existing only to fit match signature
 *   @return OK if the user is valid.
 */
static int
match_valid_user(request_rec *r, const char *ignored)
{
    /* XXX should check to see if the user has been disabled */
    if (RUSER(r) != NULL)
	return OK;
    else
	return HTTP_FORBIDDEN;
}

/*
 * A match table used during authorization phase.
 * Translates 'require' types into matcher functions.
 */
static const struct match {
    const char *name;
    int (*func)(request_rec *r, const char *arg);
    int has_args;
} matchtab[] = {
    { "user",	    match_user,	      1 },
    { "group",	    match_group,      1 },
    { "container",  match_container,  1 },
    { "valid-user", match_valid_user, 0 },
    { NULL }
};

/**
 * Returns true if the configure authentication type for the
 * request should be understood by this module.
 *   @param r The request being authenticated
 */
static int
is_our_auth_type(const request_rec *r)
{
    const auth_vas_dir_config *dc;

    if (RAUTHTYPE(r) == NULL)
	return 0;

    if (strcmp(RAUTHTYPE(r), VAS_AUTH_TYPE) == 0)
	return 1;

    dc = GET_DIR_CONFIG(r->per_dir_config);
    ASSERT(dc != NULL);

    if (dc->auth_basic == FLAG_ON &&
	strcmp(RAUTHTYPE(r), "Basic") == 0)
	return 1;

    return 0;
}

/**
 * Authorization phase hook.
 * This hook is called after check_user_id, to determine if
 * the previously authenticated user is permitted to access the
 * resource.
 *
 * The general contract appears to be:
 *   - only look at require lines with the right method (GET/POST/etc)
 *   - ignore lines we don't understand
 *   - arguments to a require line are generally disjunctions
 *   - as soon as a require line can be satisfied, return OK
 *   - if there were no 'valid' lines, return DECLINED
 *   @param r The request being authenticated
 *   @return OK if the client could be authenticated, or HTTP_FORBIDDEN
 * if it couldn't.
 */
static int
auth_vas_auth_checker(request_rec *r)
{
    const apr_array_header_t *requires;
    int			      i;
    const struct match	     *match;
    int			      rval = 0;
    int			      valid_lines = 0;
    char		     *arg;

    ASSERT(r != NULL);
    TRACE_R(r, "auth_vas_auth_checker: user=%s authtype=%s",
	RUSER(r), RAUTHTYPE(r));

    /* Ignore authz requests for non-VAS authentication */
    if (!is_our_auth_type(r))
	return DECLINED;

    if (!server_ctx_is_valid(r->server)) {
	LOG_RERROR(APLOG_ERR, 0, r,
	      "auth_vas_auth_checker: no VAS context for server; FORBIDDEN");
	return HTTP_FORBIDDEN;
    }

    requires = ap_requires(r);

    ASSERT(requires != NULL);
    TRACE_R(r, "requires->nelts = %d", requires->nelts);

    for (i = 0; i < requires->nelts; i++)
    {
	const char *line, *type;
	require_line *req = &((require_line *)requires->elts)[i];

	/* Ignore Require lines inside an inactive <Limit> container */
	if ((req->method_mask & AP_METHOD_BIT << r->method_number) == 0)
	    continue;

	/* Extract the first word after 'Require' */
	line = req->requirement;
	type = ap_getword_white(r->pool, &line);
	ASSERT(type != NULL);

	valid_lines++;

	/* Find the macthing function to use for the requirement type */
	for (match = matchtab; match->name; match++)
	    if (strcmp(type, match->name) == 0)
		break;
	if (!match->name) {
	    LOG_RERROR(APLOG_ERR, 0, r,
		"auth_vas_auth_checker: Unknown requirement '%s'" , type);
	    continue;
	}

	if (match->has_args) {
	    if (!*line) {
		LOG_RERROR(APLOG_WARNING, 0, r,
		    "Missing arguments to 'Require %s'; ignoring", type);
		continue;
	    }
	    /* Apply the match function for each argument after the type */
	    while (*line) {
		arg = ap_getword_conf(r->pool, &line);
		ASSERT(arg != NULL);
		/* TRACE_R(r, "require %s \"%s\"", type, arg); */

		ASSERT(match != NULL);
		ASSERT(match->func != NULL);
		rval = (*match->func)(r, arg);
		TRACE_R(r, "require %s \"%s\" -> %s", type, arg,
			    rval == OK ? "OK" : "FAIL");
		if (rval == OK)
		    return OK;
	    }
	} else {
	    /* Apply the match function with a NULL argument */
	    if (*line) {
		LOG_RERROR(APLOG_WARNING, 0, r,
		    "Ignoring unexpected arguments to 'Require %s'", type);
	    }
	    rval = (*match->func)(r, NULL);
	    TRACE_R(r, "require %s  -> %s", type, rval == OK ? "OK" : "FAIL");
	    if (rval == OK)
		return OK;
	}

    }
    if (!valid_lines) {
	LOG_RERROR(APLOG_WARNING, 0, r,
		"No lines apply; consider 'Require valid-user'");
	return DECLINED;
    }

    LOG_RERROR(APLOG_ERR, 0, r,
		  "auth_vas_auth_checker: Denied access to "
		  " user '%s' for uri '%s'", RUSER(r), r->uri);
    return HTTP_FORBIDDEN;
}

/**
 * Authenticate a user using a plaintext password.
 *   @param r the request
 *   @param user the user's name
 *   @param password the password to authenticate against
 *   @return OK if credentials could be obtained for that user to use
 *	      this service
 */
static int
do_basic_accept(request_rec *r, const char *user, const char *password)
{
    int error;
    int rval;
    vas_t *vas = NULL;
    auth_vas_server_config *sc = GET_SERVER_CONFIG(r->server->module_config);

    TRACE_R(r, "do_basic_accept: user='%s' password='%s'", user, password );

    LOCK_VAS();

    error = vas_alloc(&vas, user);
    if (error) {
	rval = HTTP_INTERNAL_SERVER_ERROR;
	LOG_RERROR(APLOG_ERR, 0, r,
		"vas_alloc: error=%d", error);
	goto done;
    }
    ASSERT(vas != NULL);

    error = vas_opt_set(vas, VAS_OPT_KRB5_USE_MEMCACHE, "1");
    if (error) {
	LOG_RERROR(APLOG_ERR, 0, r,
		"vas_opt_set: %s", vas_error_str(vas));
    }

    /* Check that the given password is correct */
    error = vas_authenticate(vas, password);
    if (error) {
	rval = HTTP_UNAUTHORIZED;
	LOG_RERROR(APLOG_ERR, 0, r,
		"vas_authenticate(user=%s): %s", user, vas_error_str(vas));
	goto done;
    }

    /* Check that the user can use this service */
    error = vas_user_login(vas, sc->service_principal, 0 /* do_shell_checks */);
    if (error) {
	rval = HTTP_UNAUTHORIZED;
	LOG_RERROR(APLOG_ERR, 0, r,
		"vas_user_login(user=%s, spn=%s): %s",
		user, sc->service_principal, vas_error_str(vas));
	goto done;
    }

    rval = OK;

 done:
    /* Release resources */
    if (vas)
	vas_free(vas);
    UNLOCK_VAS();

    return rval;
}

/**
 * Logs a GSSAPI error to the Apache log, expanding the major status
 * code.
 *   @param file caller's file name (provided by APLOG_MARK)
 *   @param line caller's line number (provided by APLOG_MARK)
 *   @param level error leve (e.g. APLOG_ERROR)
 *   @param result Apache error number (usually 0)
 *   @param r request context of error
 *   @param pfx string printed before message, a la perror()
 *   @param gsserr major error number returned by the GSSAPI call
 *   @param gsserr_minor minor error number set by the failing GSSAPI call
 */
static void
log_gss_error(const char *file, int line, int level, apr_status_t result,
	      request_rec *r, const char *pfx, OM_uint32 gsserr,
	      OM_uint32 gsserr_minor)
{
    OM_uint32 seq = 0;
    OM_uint32 more, minor_status;

    /* Use the GSSAPI to obtain the error message text */
    do {
	gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;
	more = gss_display_status(&minor_status, gsserr,
	    GSS_C_GSS_CODE, GSS_C_NO_OID, &seq, &buf);
	LOG_RERROR(level, result, r, "%s: %.*s", \
	    pfx, buf.length, (char *)buf.value);
	gss_release_buffer(&minor_status, &buf);
    } while (more);

    /* And the mechanism-specific error */
    do {
	gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;
	more = gss_display_status(&minor_status, gsserr_minor,
	    GSS_C_MECH_CODE, GSS_C_NO_OID, &seq, &buf);
	LOG_RERROR(level, result, r, "%s: %.*s", \
	    pfx, buf.length, (char *)buf.value);
	gss_release_buffer(&minor_status, &buf);
    } while (more);

}

/**
 * Cleans up an auth_vas_conn_note.
 * This function is called when a connection pool is released.
 * It is attached to the pool during do_gss_spnego_accept().
 * It releases GSS storage associated with the connection, if any.
 */
static CLEANUP_RET_TYPE
auth_vas_cleanup_connection(void *data)
{
    OM_uint32 gsserr, minor;
    conn_rec *connection = (conn_rec *)data;
    auth_vas_conn_note *cn;

    TRACE_P(connection->pool, "auth_vas_cleanup_connection");
    cn = GET_CONN_NOTE(connection);
    if (cn != NULL && cn->gss_ctx != GSS_C_NO_CONTEXT) {
	gsserr = gss_delete_sec_context(&minor, &cn->gss_ctx, NULL);
	if (gsserr != GSS_S_COMPLETE)
	    LOG_ERROR(APLOG_ERR, 0, connection->base_server,
		"gss_delete_sec_context: error %d", gsserr);
	if (cn->client.value)
	    gss_release_buffer(&minor, &cn->client);
	SET_CONN_NOTE(connection, NULL);
    }
    CLEANUP_RETURN;
}

/**
 * Performs one acceptance step in the SPNEGO protocol using
 * a BASE64-encoded token in auth_line.
 *   @return OK if SPNEGO has completed and RUSER(r) has been set.
 *		Otherwise returns an error.
 */
static int
do_gss_spnego_accept(request_rec *r, const char *auth_line)
{
    OM_uint32	    gsserr;
    int		    result;
    const char	   *auth_param;
    unsigned char  *out_token = NULL;
    size_t	    out_token_size = 0;
    char	   *in_token;
    int		    in_token_size;
    const auth_vas_server_config *sc;
    auth_vas_conn_note *cn;

    ASSERT(r != NULL);
    ASSERT(auth_line != NULL);

    TRACE_R(r, "do_gss_spnego_accept: line='%.16s...'", auth_line);

    /* Get the parameter after "Authorization" */
    auth_param = ap_getword_white(r->pool, &auth_line);
    if (auth_param == NULL) {
	LOG_RERROR(APLOG_NOTICE, 0, r,
	   "auth_vas: Client sent empty Negotiate auth-data parameter");
	return DECLINED;
    }

    sc = GET_SERVER_CONFIG(r->server->module_config);

    /* Store negotiation context in the connection record */
    cn = GET_CONN_NOTE(r->connection);
    if (cn == NULL) {
	TRACE_R(r, "auth_vas_conn_note: init GSS context for connection");
	cn = (auth_vas_conn_note *)apr_palloc(r->connection->pool, sizeof *cn);
	cn->gss_ctx = GSS_C_NO_CONTEXT;
	cn->client.value = NULL;
	SET_CONN_NOTE(r->connection, cn);
	/* Release the GSS structure when the connection closes */
	apr_pool_cleanup_register(r->connection->pool, r->connection,
		auth_vas_cleanup_connection, apr_pool_cleanup_null);
    } else {
	TRACE_R(r, "auth_vas_conn_note: using existing GSS context");
    }

    /* Decode the BASE64 GSSAPI token */
    /* (Use APR's decoder because VAS's decoder uses realloc) */
    TRACE_R(r, "decoding input token");
    in_token_size = apr_base64_decode_len(auth_param);
    in_token = (char *)apr_palloc(r->pool, in_token_size);
    apr_base64_decode(in_token, auth_param);

    LOCK_VAS();

    /* Accept token */
    TRACE_R(r, "calling vas_gss_spnego_accept token_size=%d",in_token_size);
    gsserr = vas_gss_spnego_accept(sc->vas, &cn->gss_ctx, NULL,
	VAS_GSS_SPNEGO_ENCODING_DER, in_token, in_token_size,
	&out_token, &out_token_size, NULL);

    /* Handle completed GSSAPI negotiation */
    if (gsserr == GSS_S_COMPLETE) {
	OM_uint32	minor_status, err;
	gss_name_t	client_name;
	gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;

	/* Get the client's name */
	err = gss_inquire_context(&minor_status, cn->gss_ctx, &client_name,
		NULL, NULL, NULL, NULL, NULL, NULL);
	if (err != GSS_S_COMPLETE) {
	    result = HTTP_UNAUTHORIZED;
	    log_gss_error(APLOG_MARK, APLOG_NOTICE, 0, r,
		    "gss_inquire_context", err, minor_status);
	    goto done;
	}

	/* Keep a copy of the client's MN in the connection note */
	err = gss_export_name(&minor_status, client_name, &cn->client);
	if (err != GSS_S_COMPLETE) {
	    result = HTTP_UNAUTHORIZED;
	    log_gss_error(APLOG_MARK, APLOG_NOTICE, 0, r,
		    "gss_export_name", err, minor_status);
	}

	/* Convert the client's name into a visible string */
	err = gss_display_name(&minor_status, client_name, &buf, NULL);
	if (err != GSS_S_COMPLETE) {
	    result = HTTP_UNAUTHORIZED;
	    log_gss_error(APLOG_MARK, APLOG_NOTICE, 0, r,
		    "gss_display_name", err, minor_status);
	    goto done;
	}

	/* Copy out the authenticated user's name */
	RUSER(r) = apr_pstrmemdup(r->pool, buf.value, buf.length);
	gss_release_buffer(&minor_status, &buf);
	if (RUSER(r) == NULL) {
	    LOG_RERROR(APLOG_ERR, APR_ENOMEM, r, "apr_pstrmemdup");
	    result = HTTP_INTERNAL_SERVER_ERROR;
	    goto done;
	}

	TRACE_R(r, "authenticated user: '%s'", RUSER(r));

	/* Authentication has succeeded at this point */
	RAUTHTYPE(r) = (char *)VAS_AUTH_TYPE;
	result = OK;
    } else {
	/* Any other result means we send back an Unauthorized result */
	TRACE_R(r, "vas_gss_spnego_accept did not complete; UNAUTHORIZED");
	result = HTTP_UNAUTHORIZED;
    }

 done:
    UNLOCK_VAS();

    /* If there is an out token we need to return it in the header */
    if (out_token && result != OK) {
	int	b64_out_token_size; /* token size after encoding */
	char   *auth_out;		/* "Negotiate <token>" string */
	size_t	auth_out_size;

#define NEGOTIATE_TEXT "Negotiate "
#define NEGOTIATE_SIZE	10 /* strlen("Negotiate ") */

	b64_out_token_size = apr_base64_encode_len(out_token_size);

	/* Allocate space for the header value */
	auth_out_size = b64_out_token_size + NEGOTIATE_SIZE + 1;
	auth_out = apr_palloc(r->pool, auth_out_size);
	if (auth_out == NULL) {
	    LOG_RERROR(APLOG_ERR, APR_ENOMEM, r, "apr_palloc");
	    result = HTTP_INTERNAL_SERVER_ERROR;
	    goto cleanup;
	}

	/* Construct the header value string */
	strcpy(auth_out, NEGOTIATE_TEXT);
	apr_base64_encode(auth_out + NEGOTIATE_SIZE, out_token,
		out_token_size);
	auth_out[NEGOTIATE_SIZE + b64_out_token_size] = '\0';

	/* Add to the outgoing header set */
	apr_table_set(r->err_headers_out, "WWW-Authenticate", auth_out);
	/* add_basic_auth_headers(r); */
    }

    /* Detect NTLMSSP attempts */
    if (gsserr == GSS_S_DEFECTIVE_TOKEN &&
	in_token_size >= 7 &&
	memcmp(in_token, "NTLMSSP", 7) == 0)
    {
	LOG_RERROR(APLOG_ERR, 0, r,
	    "Client used unsupported NTLMSSP authentication");
    }
    else if (GSS_ERROR(gsserr))
    {
	/* Log failures */
	LOCK_VAS();
	LOG_RERROR(APLOG_ERR, 0, r,
	    "vas_gss_spnego_accept: %s", vas_error_str(sc->vas));
	UNLOCK_VAS();
    }

    if (out_token)
	free(out_token);

 cleanup:
    return result;
}


/**
 * Initialises the VAS context for a server.
 * Assumes that the server configuration files have been
 * parsed to fill in the server config records.
 * Sets the vas context to NULL if the service principal
 * name cannot be translated into a server key.
 * This function is called before the VAS mutex has
 * initialised, and should not call VAS_LOCK/VAS_UNLOCK
 *
 *   @param s the server being initialised for VAS
 *   @param p memory pool associated with server instance
 */
static void
auth_vas_server_init(apr_pool_t *p, server_rec *s)
{
    int error;
    char *name = NULL;
    auth_vas_server_config *sc = GET_SERVER_CONFIG(s->module_config);

    if (sc == NULL) {
	LOG_ERROR(APLOG_ERR, 0, s,
	    "auth_vas_server_init: no server config");
	return;
    }

    TRACE_S(s, "auth_vas_server_init(host=%s)", s->server_hostname);

    if (sc->vas != NULL) {
	TRACE_S(s, "auth_vas_server_init: already initialised");
	return;
    }

    TRACE_S(s, "auth_vas_server_init: spn='%s'", sc->service_principal);

    error = vas_alloc(&sc->vas, sc->service_principal);
    if (error) {
	LOG_ERROR(APLOG_ERR, 0, s,
	    "vas_alloc: error = %d", error);
	return;
    }

    error = vas_authenticate(sc->vas, NULL);
    if (error) {
	vas_info_identity(sc->vas, NULL, &name);
	LOG_ERROR(APLOG_ERR, 0, s,
	    "Could not authenticate VAS context for "
	    "service principal '%s': %s",
	    name, vas_error_str(sc->vas));
	if (name != NULL)
	    free(name);
	vas_free(sc->vas);
	sc->vas = NULL;
	return;
    }

    vas_info_identity(sc->vas, NULL, &name);
    TRACE_S(s, "auth_vas_server_init: authenticated as '%s'", name);
    if (name != NULL)
	free(name);

    /* Determine the default realm for comparing principals with */
    error = vas_info_joined_domain(sc->vas, &sc->default_realm, NULL);
    if (error) {
	LOG_ERROR(APLOG_ERR, 0, s,
	    "vas_info_joined_domain: %s", vas_error_str(sc->vas));
	sc->default_realm = NULL;
    } else {
	TRACE_S(s, "auth_vas_server_init: default realm is '%s'",
	    sc->default_realm);
    }
}

/**
 * Appends the Basic auth header, if enabled
 */
static void
add_basic_auth_headers(request_rec *r)
{
    const auth_vas_dir_config *dc;
    const auth_vas_server_config *sc;
    char *s;

    ASSERT(r != NULL);
    dc = GET_DIR_CONFIG(r->per_dir_config);
    ASSERT(dc != NULL);
    sc = GET_SERVER_CONFIG(r->server->module_config);
    ASSERT(sc != NULL);

    if (dc->auth_basic == FLAG_ON) {
	s = apr_psprintf(r->pool, "Basic realm=\"%s\"", sc->default_realm);
	ASSERT(s != NULL);
	apr_table_add(r->err_headers_out, "WWW-Authenticate", s);
    }
}

/**
 * Appends the headers
 *   WWW-Authenticate: Negotiate
 *   WWW-Authenticate: Basic realm="realm"	 (if enabled)
 * to the request's error response headers.
 */
static void
add_auth_headers(request_rec *r)
{
    ASSERT(r != NULL);

    apr_table_add(r->err_headers_out, "WWW-Authenticate", "Negotiate");
    add_basic_auth_headers(r);
}

/**
 * Authentication phase.
 * This hook is called after the generic access_checker hook,
 * but before auth_checker. It analyses the request headers
 * and sets the RUSER(r) and RAUTHTYPE(r) fields, but only if
 * the user is authenticated.
 *
 *  @param r request context
 *  @return OK if spnego or basic authentication succeeded,
 *	    HTTP_INTERNAL_SERVER_ERROR if VAS is not available,
 *	    DECLINED if AuthType did not specify VAS,
 *	    HTTP_UNAUTHORIZED if
 */
static int
auth_vas_check_user_id(request_rec *r)
{
    const apr_array_header_t *requires;
    const char		     *auth_type = NULL;
    const char		     *auth_line = NULL;
    const char		     *type = NULL;
    char		     *credentials = NULL;
    const char		     *user = NULL;
    const char		     *password = NULL;
    int			      result, obSize;
    auth_vas_dir_config	     *dc = GET_DIR_CONFIG(r->per_dir_config);

    /* Pull the auth type from .htaccess or <Directory> */
    type = ap_auth_type(r);
    TRACE_R(r, "auth_vas_check_user_id: auth_type=%s", type);

    /*
     * Ignore requests that aren't for VAS.
     * XXX - should handle BASIC here as well?
     */
    if (type == NULL || strcasecmp(type, VAS_AUTH_TYPE) != 0) {
	LOG_RERROR(APLOG_ERR, 0, r,
		       "auth type %s != %s, not handling this request",
		       type ? type : "(null)", VAS_AUTH_TYPE);
	return DECLINED;
    }

    if (!server_ctx_is_valid(r->server)) {
	LOG_RERROR(APLOG_ERR, 0, r,
	      "auth_vas_check_user_id: no VAS context");
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Determine if its an ANY or ALL match on requirements */
    requires = ap_requires(r);

    /* Pick out the client's Authorization header(s) */
    auth_line = apr_table_get(r->headers_in, "Authorization");
    if (!auth_line)
    {
	/* There were no Authorization headers: Deny access now,
	 * but offer possible means of negotiation via WWW-Authenticate */
	TRACE_R(r, "sending initial negotiate headers");
	add_auth_headers(r);
	return HTTP_UNAUTHORIZED;
    }

    auth_type = ap_getword_white(r->pool, &auth_line);
    TRACE_R(r, "Got: 'Authorization: %s [...]'", auth_type);

    /* Handle "Authorization: Negotiate ..." */
    if (strcasecmp(auth_type, "Negotiate") == 0)
    {
	result = do_gss_spnego_accept(r, auth_line);
	if (result != OK) {
	    /*
	     * The realm string shows up in the password prompting box (if
	     * you add it after basic). This will cause the prompt for
	     * user name and password to show up.
	     *
	     * TODO: if the user sent back NTLMSSP then it will fail but
	     * it already caused the username and password box to show up.
	     * So to the user it will appear as if they must type in their
	     * username and password twice.  And indeed they must.  The
	     * first is for the NTLM info.  The second is for the basic info.
	     * We should just get first credentials right out of the NTLM
	     * token.
	     *
	     * The workaround is to get users to change IE to
	     * do turn on 'Integrated Windows Authentication' in the
	     * Internet Options->Advanced tab. This is the default in
	     * contemporary releases of IE.
	     */
	    add_basic_auth_headers(r);
	}
	return result;
    }

    /* Handle "Authorization: Basic ..." */
    else if (strcasecmp(auth_type, "Basic") == 0 && auth_line != NULL)
    {
	char *colon = NULL;

	if (dc->auth_basic != FLAG_ON) {
	    LOG_RERROR(APLOG_ERR, 0, r,
	       "Basic authentication denied (%s off)", CMD_USEBASIC);
	    return HTTP_UNAUTHORIZED;
	}

	/*
	 * Decode the BASE64 token.
	 * I've chosen to use APR's decoder here because
	 * the VAS library's decoder has the potential call
	 * to realloc(credentials).
	 */
	obSize = apr_base64_decode_len( auth_line );
	credentials = apr_palloc(r->pool, obSize + 1);
	apr_base64_decode(credentials, auth_line);
	credentials[obSize] = '\0';

	TRACE_R(r, "apr_base64_decode returned %u btyes", obSize);

	/* Basic auth token is of the form "user:password" */
	if ((colon = strchr(credentials, ':')) == NULL)
	{
	    LOG_RERROR(APLOG_ERR, 0, r,
		   "Error parsing credentials, no ':' separator");
	    return HTTP_UNAUTHORIZED;
	}

	*colon = '\0';
	user = credentials;
	password = colon + 1;

	/* Attempt to authenticate using username and password */
	if ((result = do_basic_accept(r, user, password)) == OK) {
	     RAUTHTYPE(r) = "Basic";
	     RUSER(r) = apr_pstrdup(r->pool, user);
	     ASSERT(RUSER(r) != NULL);
	}
	return result;
    }

    /* Handle "Authorization: [other]" */
    else
    {
	/* We don't understand. Deny access. */
	add_auth_headers(r);
	return HTTP_UNAUTHORIZED;
    }
}

#if HAVE_UNIX_SUEXEC
/**
 * Provides uid/gif of a VAS authenticated user, for when suEXEC is enabled.
 * @param r curent request
 * @return pointer to an identity structure
 */
static ap_unix_identity_t *
auth_vas_suexec(const request_rec *r)
{
    ap_unix_identity_t *id;

    if (!is_our_auth_type(r) || RUSER(r) == NULL)
	return NULL;

    if ((id = apr_palloc(r->pool, sizeof (ap_unix_identity_t))) == NULL)
	return NULL;

    /* This will hit vas_nss where Kerberos principals are understood */
    if (apr_uid_get(&id->uid, &id->gid, RUSER(r), r->pool) != APR_SUCCESS)
	return NULL;

    TRACE_R(r, "auth_vas_suexec: RUSER=%s uid=%d gid=%d", RUSER(r),
	    (int)id->uid, (int)id->gid);

    id->userdir = 0;

    return id;
}
#endif /* HAVE_UNIX_SUEXEC */

/**
 * Creates and initialises a directory configuration structure.
 * This function is called when a &lt;Directory&gt; configuration
 * entry is encountered during the path walk.
 *   @param p memory pool to create configuration record from
 *   @param dirspec (unreliable)
 *   @return allocated storage for this module's per-directory config data
 */
static void *
auth_vas_create_dir_config(apr_pool_t *p, char *dirspec)
{
    auth_vas_dir_config *dc;

    dc = (auth_vas_dir_config *)apr_pcalloc(p, sizeof *dc);
    TRACE_P(p, "auth_vas_create_dir_config()");
    if (dc != NULL) {
	dc->auth_basic = FLAG_UNSET;
    }
    return (void *)dc;
}

/**
 * Merges a parent directory configuration with a base directory config.
 * Each field of a freshly allocated merged config is computed from
 * the base_conf and new_conf structures.
 *   @param p memory pool from which to allocate new merged config structure
 *   @param base_conf the parent directory's config structure
 *   @param new_conf the directory config being processed
 *   @return the resulting, merged config structure
 */
static void *
auth_vas_merge_dir_config(apr_pool_t *p, void *base_conf, void *new_conf)
{
    auth_vas_dir_config *base_dc = (auth_vas_dir_config *)base_conf;
    auth_vas_dir_config *new_dc = (auth_vas_dir_config *)new_conf;
    auth_vas_dir_config *merged_dc;

    merged_dc = (auth_vas_dir_config *)apr_pcalloc(p, sizeof *merged_dc);
    TRACE_P(p, "auth_vas_merge_dir_config()");
    if (merged_dc != NULL) {
	merged_dc->auth_basic = FLAG_MERGE(base_dc->auth_basic,
		new_dc->auth_basic);
    }
    return (void *)merged_dc;
}

/**
 * Creates and initialises a server configuration structure.
 * This function is called for each virtual host server at startup.
 *   @param p memory pool to create configuration record from
 *   @param s pointer to server being configured
 *   @return allocated storage for this module's per-directory config data
 */
static void *
auth_vas_create_server_config(apr_pool_t *p, server_rec *s)
{
    auth_vas_server_config *sc;

    sc = (auth_vas_server_config *)apr_pcalloc(p, sizeof *sc);
    if (sc != NULL) {
	sc->service_principal = DEFAULT_SERVICE_PRINCIPAL;
	sc->vas = NULL;
    }
    TRACE_S(s, "auth_vas_create_server_config()");
    return (void *)sc;
}

/**
 * Called after all module config structures have been constructed,
 * and all modules have been loaded. This function is often called twice
 * (since module dependencies may cause a re-scan/re-load).
 *   @param p memory pool to create config records from
 *   @param plog memory pool for use with logging
 *   @param ptemp memory pool for temporary storage
 *   @param s the server being configured
 */
static int
auth_vas_post_config(apr_pool_t *p, apr_pool_t *plog,
	apr_pool_t *ptemp, server_rec *s)
{
    server_rec *sp;

#if !defined(APXS1)
    ap_add_version_component(p, "mod_auth_vas/" MODAUTHVAS_VERSION);
#endif

    TRACE_P(plog, "auth_vas_post_config() %s %s", MODAUTHVAS_VERSION,
	    module_info);

    /* Create a VAS context for each virtual host */
    for (sp = s; sp; sp = sp->next)
	auth_vas_server_init(p, sp);

    return OK;
}

/**
 * Initialise per-process mutexes.
 * This function is called when the server forks a new process.
 * We initialise the process-wide VAS mutex used to
 * control exclusive access to the thread-unsafe VAS
 * library.
 */
#if !defined(APXS1)
  static void
  auth_vas_child_init(apr_pool_t *p, server_rec *s)
  {
    int r;
    r = apr_thread_mutex_create(&auth_vas_libvas_mutex,
	    APR_THREAD_MUTEX_UNNESTED, p);

    if (r != OK) {
	LOG_ERROR(APLOG_ERR, r, s, "apr_thread_mutex_create");
	auth_vas_libvas_mutex = NULL;
    }
  }
#else /* APXS1 */
  static void
  auth_vas_child_init(server_rec *s, pool *p)
  {
    auth_vas_libvas_mutex = ap_create_mutex("auth_vas_libvas_mutex");
    if (auth_vas_libvas_mutex == NULL)
	LOG_ERROR(APLOG_ERR, 0, s, "ap_create_mutex: failed");
  }
#endif /* APXS1 */

/*
 * Module linkage structures.
 * Apache uses this at load time to discover the module entry points.
 */

#if !defined(APXS1)
/**
 * Registers this module's hook functions into Apache runtime hook lists.
 * This function is called immediately after our shared library image
 * has been loaded into memory.
 */
static void
auth_vas_register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(auth_vas_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(auth_vas_child_init, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_auth_checker(auth_vas_auth_checker, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_check_user_id(auth_vas_check_user_id, NULL, NULL, APR_HOOK_MIDDLE);

#if HAVE_UNIX_SUEXEC
    ap_hook_get_suexec_identity(auth_vas_suexec, NULL, NULL, APR_HOOK_FIRST);
#endif

    TRACE_P(p, "hooks registered");
}

/*
 * The public module interface for APXS 2.
 */
module AP_MODULE_DECLARE_DATA auth_vas_module =
{
    STANDARD20_MODULE_STUFF,
    auth_vas_create_dir_config,		/* create_dir_config */
    auth_vas_merge_dir_config,		/* merge_dir_config */
    auth_vas_create_server_config,	/* create_server_config */
    NULL,				/* merge_server_config */
    auth_vas_cmds,			/* cmds */
    auth_vas_register_hooks		/* register_hooks */
};

extern module mod_auth_vas_module __attribute__((alias("auth_vas_module")));

#else /* APXS1 */

/*
 * Initialises the module.
 * This function is called by Apache when this module has been loaded.
 */
static void
auth_vas_init(server_rec *s, pool *p)
{
    auth_vas_post_config(p, p, p, s);
}

/*
 * The public module interface for APXS 1.
 * Before APXS2, each hook has its own slot in the module export table.
 */
module MODULE_VAR_EXPORT auth_vas_module =
{
    STANDARD_MODULE_STUFF,
    auth_vas_init,			/* init */
    auth_vas_create_dir_config,		/* create_dir_config */
    auth_vas_merge_dir_config,		/* merge_dir_config */
    auth_vas_create_server_config,	/* create_server_config */
    NULL,				/* merge_server_config */

    auth_vas_cmds,			/* cmds */
    NULL,				/* handlers */
    NULL,				/* translate_handler */
    auth_vas_check_user_id,		/* ap_check_user_id */
    auth_vas_auth_checker,		/* auth_checker */
    NULL,				/* access_checker */
    NULL,				/* type_checker */
    NULL,				/* fixer_upper */
    NULL,				/* logger */
    NULL,				/* header_parser */

    auth_vas_child_init,		/* child_init */
    NULL,				/* child_exit */
    NULL				/* post_read_request */
#if defined(EAPI)
   ,NULL,				/* add_module */
    NULL,				/* remove_module */
    NULL,				/* rewrite_command */
    NULL,				/* new_connection */
    NULL				/* close_connection */
#endif /* EAPI */
};

#endif /* apxs 1 */
