/*
 * mod_auth_vas: VAS authentication module for Apache.
 * 
 * $Id$
 *
 *   (c) 2006 Quest Software, Inc.
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
 *      from this software without specific prior written permission. THIS
 *      SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *      "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT
 *      NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 *      FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 *      SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY
 *      DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *      DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 *      GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *      INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *      WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *      NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 *      THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
#  warning "Disabling HAVE_UNIX_SUEXEC because APR user support not available"
#  undef HAVE_UNIX_SUEXEC
# endif
#endif

#if !defined(STANDARD20_MODULE_STUFF)
# define APXS1 1 /* Apache 1.3.x */
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

/* Flag values for directory configuration */
#define FLAG_UNSET	(-1)
#define FLAG_OFF	0
#define FLAG_ON		1
#define FLAG_MERGE(basef,newf) ((newf) == FLAG_UNSET ? (basef) : (newf))
#define TEST_FLAG_DEFAULT(f,def)  ((f) == FLAG_UNSET ? (def) : (f))

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
 * Macros for keeping the VAS context in the request record notes.
 * NB Request ontes may not always be available (eg apache 1.3 without EAPI).
 */
#if defined(APXS1) /* Apache 1.3.x */
# if defined(EAPI) /* extended API available */
#  include "ap_ctx.h"
#  define RNOTE_KEY "rc.vintela.com/mod_auth_vas/request_note"
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

/*
 * Per-server configuration structure - exists for lifetime of server process.
 */
typedef struct {
    vas_ctx_t   *vas_ctx;           /* The global VAS context - needs locking */
    vas_id_t    *vas_serverid;      /* The server ID context */
    const char *service_principal;  /* VASServicePrincipal or NULL */
    char *default_realm;            /* AuthVasDefaultRealm (never NULL) */
} auth_vas_server_config;

/*
 * Per-directory configuration data - computed while traversing htaccess.
 */
typedef struct {
    int auth_negotiate;			/* AuthVasUseNegotiate (default on) */
    int auth_basic;			/* AuthVasUseBasic (default off) */
    int auth_authoritative;		/* AuthVasAuthoritative (default on) */
} auth_vas_dir_config;

/* Returns the field flag, or def if dc is NULL or dc->field is FLAG_UNSET */
#define USING_AUTH_DEFAULT(dc, field, def) \
		((dc) ? TEST_FLAG_DEFAULT((dc)->field, def) : def)

/* Macros to safely test the per-directory flags, applying defaults. */
#define USING_AUTH_NEGOTIATE(dc) \
		USING_AUTH_DEFAULT(dc, auth_negotiate, FLAG_ON)
#define USING_AUTH_BASIC(dc) \
		USING_AUTH_DEFAULT(dc, auth_basic, FLAG_OFF)
#define USING_AUTH_AUTHORITATIVE(dc) \
		USING_AUTH_DEFAULT(dc, auth_authoritative, FLAG_ON)

/*
 * Per-request note data - exists for lifetime of request only.
 */
typedef struct {
    vas_id_t *vas_userid;		/* The user's identity */
    char *vas_pname;			/* The user's principal name */
    vas_auth_t*vas_authctx;		/* the VAS authentication context */
    gss_ctx_id_t gss_ctx;		/* Negotiation context */
    gss_buffer_desc client;		/* exported mech name */
} auth_vas_rnote;


/* Forward declaration for module structure: see bottom of this file. */
module AP_MODULE_DECLARE_DATA auth_vas_module;

/* Prototypes */
static const char *server_set_string_slot(cmd_parms *cmd, void *ignored, 
	const char *arg);
static int server_ctx_is_valid(server_rec *s);
static int match_user(request_rec *r, const char *name, int);
static int match_group(request_rec *r, const char *nam, int);
static int dn_in_container(const char *dn, const char *container);
static int match_container(request_rec *r, const char *container, int);
static int match_valid_user(request_rec *r, const char *ignored, int);
static int is_our_auth_type(const request_rec *r);
static int auth_vas_auth_checker(request_rec *r);
static int do_basic_accept(request_rec *r, const char *user, 
	const char *password);
static void log_gss_error(const char *file, int line, int level, 
	apr_status_t result, request_rec *r, const char *pfx, 
	OM_uint32 gsserr, OM_uint32 gsserr_minor);
static void rnote_init(auth_vas_rnote *rn);
static void rnote_fini(request_rec *r, auth_vas_rnote *rn);
static CLEANUP_RET_TYPE auth_vas_cleanup_request(void *data);
static int rnote_get(auth_vas_server_config *sc, request_rec *r, 
	const char *user, auth_vas_rnote **rn_ptr);
static int do_gss_spnego_accept(request_rec *r, const char *auth_line);
static void auth_vas_server_init(apr_pool_t *p, server_rec *s);
static void add_basic_auth_headers(request_rec *r);
static void add_auth_headers(request_rec *r);
static int auth_vas_check_user_id(request_rec *r);
#if HAVE_UNIX_SUEXEC
static ap_unix_identity_t *auth_vas_suexec(const request_rec *r);
#endif
static void *auth_vas_create_dir_config(apr_pool_t *p, char *dirspec);
static void *auth_vas_merge_dir_config(apr_pool_t *p, void *base_conf, 
	void *new_conf);
static CLEANUP_RET_TYPE auth_vas_server_config_destroy(void *data);
static void *auth_vas_create_server_config(apr_pool_t *p, server_rec *s);
static int auth_vas_post_config(apr_pool_t *p, apr_pool_t *plog, 
	apr_pool_t *ptemp, server_rec *s);
#if !defined(APXS1)
static void auth_vas_child_init(apr_pool_t *p, server_rec *s);
static void auth_vas_register_hooks(apr_pool_t *p);
#else
static void auth_vas_child_init(server_rec *s, pool *p);
static void auth_vas_init(server_rec *s, pool *p);
#endif

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
    	/* NB The casts to (char *) are to stop warnings under Apache 1.3.x */
	return ap_set_string_slot(cmd, 
	    (char *)GET_SERVER_CONFIG(cmd->server->module_config), 
	    (char *)arg);
}

/*
 * Configuration commands table for this module.
 */
#define CMD_USENEGOTIATE	"AuthVasUseNegotiate"
#define CMD_USEBASIC		"AuthVasUseBasic"
#define CMD_AUTHORITATIVE	"AuthVasAuthoritative"
#define CMD_SPN			"AuthVasServicePrincipal"
#define CMD_REALM		"AuthVasDefaultRealm"
static const command_rec auth_vas_cmds[] =
{
    AP_INIT_FLAG(CMD_USENEGOTIATE, ap_set_flag_slot,
		APR_OFFSETOF(auth_vas_dir_config, auth_negotiate),
		ACCESS_CONF | OR_AUTHCFG,
		"Kerberos SPNEGO authentication using Active Directory"),
    AP_INIT_FLAG(CMD_USEBASIC, ap_set_flag_slot,
		APR_OFFSETOF(auth_vas_dir_config, auth_basic),
		ACCESS_CONF | OR_AUTHCFG,
		"Basic Authentication using Active Directory"),
    AP_INIT_FLAG(CMD_AUTHORITATIVE, ap_set_flag_slot,
		APR_OFFSETOF(auth_vas_dir_config, auth_authoritative),
		ACCESS_CONF | OR_AUTHCFG,
		"Authenticate authoritatively ('Off' allows fall-through to other authentication modules)"),
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
    return sc->vas_ctx != NULL;
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
match_user(request_rec *r, const char *name, int log_level)
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
match_group(request_rec *r, const char *name, int log_level)
{
    vas_err_t                 vaserr;
    int                       rval;
    auth_vas_server_config   *sc;
    auth_vas_rnote           *rnote;

    ASSERT(r != NULL);
    ASSERT(name != NULL);
    ASSERT(RUSER(r) != NULL);

    sc = GET_SERVER_CONFIG(r->server->module_config);
    ASSERT(sc != NULL);
    ASSERT(sc->vas_ctx != NULL);

    if ((rval = rnote_get(sc, r, RUSER(r), &rnote)))
        return rval;

    /* Make sure that we have a valid VAS authentication context.
     * If it's not there, then we'll just fail since there is
     * no available group information. */
    if (rnote->vas_authctx == NULL) {
        LOG_RERROR(log_level, 0, r,
                   "match_group(): no available auth context for %s",
                   rnote->vas_pname);
        rval = HTTP_FORBIDDEN;
    }
        

    LOCK_VAS();

#define VASVER ((VAS_API_VERSION_MAJOR * 10000) + \
    	        (VAS_API_VERSION_MINOR * 100)   + \
    	        VAS_API_VERSION_MICRO)
#if VASVER < 40100
#define vas_auth_check_client_membership(c,i,a,n) \
    	vas_auth_is_client_member(c,a,n)
#endif

    vaserr = vas_auth_check_client_membership(sc->vas_ctx,
                                              sc->vas_serverid,
                                              rnote->vas_authctx,
                                              name);
    switch (vaserr) {
        case VAS_ERR_SUCCESS: /* user is member of group */
            rval = OK;
            break;
            
        case VAS_ERR_NOT_FOUND: /* user not member of group */
            rval = HTTP_FORBIDDEN;
            LOG_RERROR(log_level, 0, r,
                       "match_group(): %s not member of %s",
                       rnote->vas_pname,
                       name);
            break;
            
        case VAS_ERR_EXISTS: /* configured group not found */
            rval = HTTP_FORBIDDEN;
            LOG_RERROR(log_level, 0, r,
                       "match_group(): group %s does not exist",
                       name);
            break;
            
        default: /* other type of error */
            rval = HTTP_INTERNAL_SERVER_ERROR;
            LOG_RERROR(log_level, 0, r,
                       "match_group(): fatal vas error: %s",
                       vas_err_get_string(sc->vas_ctx, 1));
            break;
    }
    UNLOCK_VAS();

    return rval;
}

/**
 * Checks if the given dn matches "*,container".
 * Assumes the dn and container have been normalised to contain
 * no spaces, escapes or double quotes. Container comparison is
 * performed case-insensitively. Strict inclusion is tested.
 * @return true if dn is in the container
 */
static int
dn_in_container(const char *dn, const char *container)
{
    int offset;
   
    offset = strlen(dn) - strlen(container);
    return offset > 0 &&
	   dn[offset - 1] == ',' && 
	   strcasecmp(dn + offset, container) == 0;
}

/**
 * Checks if the given user belongs to the given container.
 * Assumes the server config has been initialised.
 *   @param r The authenticated request
 *   @param name The name of the container to check
 *   @return OK if container contains user, otherwise HTTP_...
 */
static int
match_container(request_rec *r, const char *container, int log_level)
{
    int                       rval = 0;
    int                       do_unlock = 0;
    vas_err_t                 vaserr;
    auth_vas_server_config    *sc = NULL;
    auth_vas_rnote            *rnote = NULL;
    vas_user_t                *vasuser = NULL;
    char                      *dn = NULL;

    ASSERT(r != NULL);
    ASSERT(container != NULL);
    ASSERT(RUSER(r) != NULL);

    sc = GET_SERVER_CONFIG(r->server->module_config);
    ASSERT(sc != NULL);
    ASSERT(sc->vas_ctx != NULL);
    
    if ((rval = rnote_get(sc, r, RUSER(r), &rnote)))
        return rval;

    LOCK_VAS();
    do_unlock = 1;

    if ((vaserr = vas_user_init(sc->vas_ctx, sc->vas_serverid,
		    rnote->vas_pname, 0, &vasuser)) != VAS_ERR_SUCCESS)
    {
        LOG_RERROR(log_level, 0, r,
	       	"match_container(): fatal vas error for user_init: %d, %s",
	       	vaserr, vas_err_get_string(sc->vas_ctx, 1));
        rval = HTTP_FORBIDDEN;
        goto done;
    }

    if ((vaserr = vas_user_get_dn(sc->vas_ctx, sc->vas_serverid, vasuser,
		    &dn )) != VAS_ERR_SUCCESS ) 
    {
	LOG_RERROR(log_level, 0, r,
	       	"match_container(): fatal vas error for user_get_dn: %d, %s",
	       	vaserr, vas_err_get_string(sc->vas_ctx, 1));
        rval = HTTP_FORBIDDEN;
        goto done;
    }
    UNLOCK_VAS();
    do_unlock = 0;

    ASSERT(dn != NULL);
    if (dn_in_container(dn, container)) 
        rval = OK;
    else {
        LOG_RERROR(APLOG_DEBUG, 0, r,
	       	"match_container(): user dn %s not in container %s",
	       	dn, container);
        rval = HTTP_FORBIDDEN;
    }


done:
    if (vasuser) vas_user_free(sc->vas_ctx, vasuser);
    if (dn)      free(dn);

    if (do_unlock)
        UNLOCK_VAS();

    return rval;
}

/**
 * Checks that the user is valid.
 *   @param r The authenticated request
 *   @param ignored Ignored argument existing only to fit match signature
 *   @return OK if the user is valid.
 */
static int
match_valid_user(request_rec *r, const char *ignored, int log_level)
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
    int (*func)(request_rec *r, const char *arg, int log_level);
    int has_args;
} matchtab[] = {
    { "user",	    match_user,	      1 },
    { "group",	    match_group,      1 },
    { "container",  match_container,  1 },
    { "valid-user", match_valid_user, 0 },
    { NULL }
};

/**
 * Returns true if the configured authentication type for the
 * request is understood by this module.
 *   @param r The request being authenticated
 *   @return true if the AuthType is "VAS", or the
 *           AuthType is "Basic" and AuthVasUseBasic is on.
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

    if (USING_AUTH_BASIC(dc) &&
	strcmp(RAUTHTYPE(r), "Basic") == 0)
	return 1;

    return 0;
}

/**
 * Authorization phase hook.
 * This hook is called after check_user_id hook, to determine if
 * the now-authenticated user is permitted access the
 * resource.
 *
 * The general contract appears to be:
 *   - only look at require lines with the right method (GET/POST/etc)
 *   - ignore lines we don't understand
 *   - arguments to a require line are generally disjunctions
 *   - as soon as a require line can be satisfied, return OK
 *   - if there were no 'valid' lines, return DECLINED
 *   @param r The request being authenticated
 *   @return OK if the client user is authorized access, or HTTP_FORBIDDEN
 *           if it isn't.
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
    auth_vas_dir_config	     *dc;

    ASSERT(r != NULL);
    dc = GET_DIR_CONFIG(r->per_dir_config);
    TRACE_R(r, "auth_vas_auth_checker: user=%s authtype=%s",
	RUSER(r), RAUTHTYPE(r));

    /* Ignore authz requests for non-VAS authentication */
    if (!is_our_auth_type(r))
	return DECLINED;

    if (!server_ctx_is_valid(r->server)) {
	if (!USING_AUTH_AUTHORITATIVE(dc))
	    return DECLINED;
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
                rval = (*match->func)(r, arg,
                    USING_AUTH_AUTHORITATIVE(dc) ? APLOG_ERR : APLOG_DEBUG);
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
	    rval = (*match->func)(r, NULL,
                USING_AUTH_AUTHORITATIVE(dc) ? APLOG_ERR : APLOG_DEBUG);
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

    if (!USING_AUTH_AUTHORITATIVE(dc)) 
	return DECLINED;

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
 *   @return OK if credentials could be obtained for the user 
 *           with the given password to access this HTTP service
 */
static int
do_basic_accept(request_rec *r, const char *user, const char *password)
{
    int                     status = HTTP_UNAUTHORIZED;
    int                     ret;
    vas_err_t               vaserr;
    auth_vas_server_config *sc = GET_SERVER_CONFIG(r->server->module_config);
    auth_vas_rnote         *rn;

    TRACE_R(r, "do_basic_accept: user='%s' password=...", user);

    /* get the note record with the user's id */
    if ((ret = rnote_get(sc, r, user, &rn))) {
	status = ret;
	goto done;
    }

    /* Check that the given password is correct */
    LOCK_VAS();
    vaserr = vas_id_establish_cred_password(sc->vas_ctx, rn->vas_userid,
	    VAS_ID_FLAG_USE_MEMORY_CCACHE, password);
    if (vaserr != VAS_ERR_SUCCESS) {
	LOG_RERROR(APLOG_ERR, 0, r,
                   "vas_id_establish_cred_password(user=%s): error= %s",
                   user, vas_err_get_string(sc->vas_ctx, 1));
	goto done;
    }

    /* authenticate the user against our service, and store off the auth context
     * into the connection note so that we can reuse that later for authz
     * checks */
    vaserr = vas_auth(sc->vas_ctx, rn->vas_userid, sc->vas_serverid,
		&rn->vas_authctx);
    if (vaserr != VAS_ERR_SUCCESS) {
	LOG_RERROR(APLOG_ERR, 0, r,
                   "vas_auth(user=%s): %s",
                   user,
                   vas_err_get_string(sc->vas_ctx, 1));
	goto done;
    }

    status = OK;

 done:
    /* Release resources */
    UNLOCK_VAS();

    return status;
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
	LOG_RERROR(level, result, r, "%s: %.*s",
	       	pfx, (int)buf.length, (char*)buf.value);
	gss_release_buffer(&minor_status, &buf);
    } while (more);

    /* And the mechanism-specific error */
    do {
	gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;
	more = gss_display_status(&minor_status, gsserr_minor,
	       	GSS_C_MECH_CODE, GSS_C_NO_OID, &seq, &buf);
	LOG_RERROR(level, result, r, "%s: %.*s",
	       	pfx, (int)buf.length, (char*)buf.value);
	gss_release_buffer(&minor_status, &buf);
    } while (more);

}

/** Initialises an new rnote to an empty state. */
static void
rnote_init(auth_vas_rnote *rn)
{
    rn->vas_userid   = NULL;
    rn->vas_pname    = NULL;
    rn->vas_authctx  = NULL;
    rn->gss_ctx = GSS_C_NO_CONTEXT;
    rn->client.value = NULL;
}

/** Releases storage associated with the rnote. */
static void
rnote_fini(request_rec *r, auth_vas_rnote *rn)
{
    auth_vas_server_config  *sc;

    if (rn->gss_ctx != GSS_C_NO_CONTEXT) {
        OM_uint32 gsserr, minor;
        
	gsserr = gss_delete_sec_context(&minor, &rn->gss_ctx, NULL);
	if (gsserr != GSS_S_COMPLETE)
	    LOG_RERROR(APLOG_ERR, 0, r,
		"gss_delete_sec_context: error %d", gsserr);
	if (rn->client.value)
	    gss_release_buffer(&minor, &rn->client);
    }
    
    sc = GET_SERVER_CONFIG(r->server->module_config);
    
    if (rn->vas_userid)
        vas_id_free(sc->vas_ctx, rn->vas_userid);

    if (rn->vas_pname)
        free(rn->vas_pname);
    
    if (rn->vas_authctx)
        vas_auth_free(sc->vas_ctx, rn->vas_authctx);
}

/** This function is called when the request pool is being released.
 * It is passed a auth_vas_rnote pointer we need to cleanup. */
static CLEANUP_RET_TYPE
auth_vas_cleanup_request(void *data)
{
    request_rec *r = (request_rec *)data;
    auth_vas_rnote *rn;

    /* XXX Really shouldn't draw from the pool while cleaning it up! */
    TRACE_P(r->pool, "auth_vas_cleanup_request");
    rn = GET_RNOTE(r);
    if (rn != NULL) {
	rnote_fini(r, rn);
	SET_RNOTE(r, NULL);
    }
    CLEANUP_RETURN;
}

/**
 * @return 0 on success, or an HTTP error code on failure
 */
static int
rnote_get(auth_vas_server_config* sc, request_rec *r, const char *user,
       	  auth_vas_rnote **rn_ptr)
{
    int             rval = 0; 
    auth_vas_rnote  *rn = NULL;
    vas_err_t       vaserr = VAS_ERR_SUCCESS;
    
    rn = GET_RNOTE(r);
    if (rn == NULL) {
        TRACE_R(r, "rnote_get: creating rnote");
        rn = (auth_vas_rnote *)apr_palloc(r->connection->pool, sizeof *rn);

        /* initialize the rnote and set it on the record */
        rnote_init(rn);
        SET_RNOTE(r, rn);
        
        /* Arrange to release the RNOTE data when the request completes */
        apr_pool_cleanup_register(r->pool, r, auth_vas_cleanup_request,
	       	apr_pool_cleanup_null);
    } else {
        TRACE_R(r, "rnote_get: reusing existing rnote");
    }

    /* initialize the userid if there's a username passed in, and we haven't
     * yet. */
    if (user && rn->vas_userid == NULL) {
        vaserr = vas_id_alloc(sc->vas_ctx, user, &rn->vas_userid);
        if (vaserr == VAS_ERR_SUCCESS) {
            vaserr = vas_id_get_name(sc->vas_ctx, rn->vas_userid,
		    &rn->vas_pname, NULL);
        }
    }

    if (vaserr != VAS_ERR_SUCCESS) {
        /* free the rnote and set it to NULL */
        rnote_fini(r, rn);
        rn = NULL;
        
        rval = HTTP_INTERNAL_SERVER_ERROR;
    }
    
    *rn_ptr = rn;
    return rval;
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
    OM_uint32               gsserr;
    int                     result;
    const char             *auth_param;
    gss_buffer_desc         out_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc         in_token = GSS_C_EMPTY_BUFFER;
    auth_vas_server_config *sc;
    auth_vas_rnote         *rn;
    gss_name_t              client_name = NULL;

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
    if ((result = rnote_get(sc, r, NULL, &rn)))
        goto cleanup;

    /* setup the input token */
    in_token.length = strlen(auth_param);
    in_token.value = (void *)auth_param;

    LOCK_VAS();

    vas_gss_initialize(sc->vas_ctx, sc->vas_serverid);

    /* Accept token - have the VAS api handle the base64 stuff for us */
    TRACE_R(r, "calling vas_gss_spnego_accept, base64 token_size=%d",
            (int) in_token.length);
    gsserr = vas_gss_spnego_accept(sc->vas_ctx, sc->vas_serverid,
	    &rn->vas_authctx, &rn->gss_ctx, NULL,
	    VAS_GSS_SPNEGO_ENCODING_BASE64, &in_token, &out_token, NULL);

    /* Handle completed GSSAPI negotiation */
    if (gsserr == GSS_S_COMPLETE) {
	OM_uint32       minor_status, err;
	gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;

	/* Get the client's name */
	err = gss_inquire_context(&minor_status, rn->gss_ctx, &client_name,
		NULL, NULL, NULL, NULL, NULL, NULL);
	if (err != GSS_S_COMPLETE) {
	    result = HTTP_UNAUTHORIZED;
	    log_gss_error(APLOG_MARK, APLOG_NOTICE, 0, r,
		    "gss_inquire_context", err, minor_status);
	    goto done;
	}

	/* Keep a copy of the client's MN in the connection note */
	err = gss_export_name(&minor_status, client_name, &rn->client);
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
#if defined(APXS1)
	/* http://httpd.apache.org/docs/misc/API.html */
	RUSER(r) = apr_pstrmemdup(r->connection->pool, buf.value, buf.length);
#else
	RUSER(r) = apr_pstrmemdup(r->pool, buf.value, buf.length);
#endif
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
    } else if (gsserr == GSS_S_CONTINUE_NEEDED) {
	TRACE_R(r, "waiting for more tokens from client");
	result = HTTP_UNAUTHORIZED;
    } else {
	/* Any other result means we send back an Unauthorized result */
	LOG_RERROR(APLOG_ERR, 0, r,
                   "vas_gss_spnego_accept: %s",
                   vas_err_get_string(sc->vas_ctx, 1));
	result = HTTP_UNAUTHORIZED;
    }

 done:
    vas_gss_deinitialize(sc->vas_ctx);
    UNLOCK_VAS();

    /* If there is an out token we need to return it in the header -
     * it's already base64 encoded */
    if (out_token.value && result != OK) {
	char   *auth_out;		/* "Negotiate <token>" string */
	size_t	auth_out_size;

#define NEGOTIATE_TEXT "Negotiate "
#define NEGOTIATE_SIZE	10 /* strlen("Negotiate ") */

	/* Allocate space for the header value */
        auth_out_size = out_token.length + NEGOTIATE_SIZE + 1;
	auth_out = apr_palloc(r->pool, auth_out_size);
	if (auth_out == NULL) {
	    LOG_RERROR(APLOG_ERR, APR_ENOMEM, r, "apr_palloc");
	    result = HTTP_INTERNAL_SERVER_ERROR;
	    goto cleanup;
	}

	/* Construct the header value string */
	strcpy(auth_out, NEGOTIATE_TEXT);
        strcat(auth_out, out_token.value);
        auth_out[NEGOTIATE_SIZE + out_token.length] = '\0';

	/* Add to the outgoing header set */
	apr_table_set(r->err_headers_out, "WWW-Authenticate", auth_out);
	/* add_basic_auth_headers(r); */
    }

    /* Detect NTLMSSP attempts */
    if (gsserr == GSS_S_DEFECTIVE_TOKEN &&
        in_token.length >= 7 &&
        memcmp(in_token.value, "NTLMSSP", 7) == 0)
    {
	LOG_RERROR(APLOG_ERR, 0, r,
	    "Client used unsupported NTLMSSP authentication");
    }
    else if (GSS_ERROR(gsserr))
    {
	/* Log failures */
	LOCK_VAS();
	LOG_RERROR(APLOG_ERR, 0, r,
                   "vas_gss_spnego_accept: %s",
                   vas_err_get_string(sc->vas_ctx, 1));
	UNLOCK_VAS();
    }

 cleanup:
    gss_release_buffer(&gsserr, &out_token);
    if (client_name)
        gss_release_name(NULL, &client_name);

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
    vas_err_t               vaserr;
    auth_vas_server_config *sc;
   
    TRACE_S(s, "auth_vas_server_init(host=%s)", s->server_hostname);

    sc = GET_SERVER_CONFIG(s->module_config);
    TRACE_S(s, "sc=%x", (void *)sc);

    if (sc == NULL) {
	LOG_ERROR(APLOG_ERR, 0, s,
	    "auth_vas_server_init: no server config");
	return;
    }

    if (sc->vas_ctx != NULL) {
	TRACE_S(s, "auth_vas_server_init: already initialised");
	return;
    }

    TRACE_S(s, "auth_vas_server_init: spn='%s'", sc->service_principal);

    /* Obtain a new VAS context for the web server */
    vaserr = vas_ctx_alloc(&sc->vas_ctx);
    if (vaserr != VAS_ERR_SUCCESS) {
        LOG_ERROR(APLOG_ERR, vaserr, s, 
		"vas_ctx_alloc() failed, err = %d",
	       	vaserr);
	return;
    }

    vas_info_joined_domain(sc->vas_ctx, &sc->default_realm, NULL);
    
    /* Create the vas_id for the server */
    vaserr = vas_id_alloc(sc->vas_ctx, 
                          sc->service_principal, 
                          &sc->vas_serverid);
    if (vaserr != VAS_ERR_SUCCESS) {
	LOG_ERROR(APLOG_ERR, 0, s,
                  "vas_id_alloc() failed on %s, err = %s",
                  sc->service_principal,
                  vas_err_get_string(sc->vas_ctx, 1));
    }

    /* Establish our credentials using the service keytab */
    vaserr = vas_id_establish_cred_keytab(sc->vas_ctx, 
                                          sc->vas_serverid, 
                                          VAS_ID_FLAG_USE_MEMORY_CCACHE |
                                          VAS_ID_FLAG_KEEP_COPY_OF_CRED,
                                          NULL);
    if (vaserr != VAS_ERR_SUCCESS) {
	LOG_ERROR(APLOG_ERR, 0, s,
                  "vas_id_establish_cred_keytab() failed, err = %s",
                  vas_err_get_string(sc->vas_ctx, 1));
    } else {
        TRACE_S(s, "successfully authenticated as %s", sc->service_principal);
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

    if (USING_AUTH_BASIC(dc)) {
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
	if (!USING_AUTH_AUTHORITATIVE(dc))
	    return DECLINED;
	LOG_RERROR(APLOG_ERR, 0, r,
	      "auth_vas_check_user_id: no VAS context");
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Determine if its an ANY or ALL match on requirements */
    requires = ap_requires(r);

    /* Pick out the client request's Authorization header(s) */
    auth_line = apr_table_get(r->headers_in, "Authorization");
    if (!auth_line)
    {
	if (USING_AUTH_NEGOTIATE(dc)) {
	    /* There were no Authorization headers: Deny access now,
	     * but offer possible means of negotiation via WWW-Authenticate */
	    TRACE_R(r, "sending initial negotiate headers");
	    add_auth_headers(r);
	} else if (USING_AUTH_BASIC(dc)) {
	    TRACE_R(r, "sending initial basic headers");
	    add_basic_auth_headers(r);
	} else {
	    LOG_RERROR(APLOG_WARNING, 0, r,
		"%s off and %s off; no authentication possible",
		CMD_USENEGOTIATE, CMD_USEBASIC);
	}
	/* Note that in the absence of Authorization headers there is no way
	 * that any other auth module will be able to authenticate either, so
	 * there's no need to return DECLINED if not authoritative. */
	return HTTP_UNAUTHORIZED;
    }

    auth_type = ap_getword_white(r->pool, &auth_line);
    TRACE_R(r, "Got: 'Authorization: %s [...]'", auth_type);

    /* Handle "Authorization: Negotiate ..." */
    if (strcasecmp(auth_type, "Negotiate") == 0)
    {
	if (!USING_AUTH_NEGOTIATE(dc)) {
	    if (!USING_AUTH_AUTHORITATIVE(dc))
		return DECLINED;
	    LOG_RERROR(APLOG_ERR, 0, r,
		"Negotiate authentication denied (%s off)", CMD_USENEGOTIATE);
	    return HTTP_UNAUTHORIZED;
	}
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
	return (result == OK || USING_AUTH_AUTHORITATIVE(dc)) ? 
	    result : DECLINED;
    }

    /* Handle "Authorization: Basic ..." */
    else if (strcasecmp(auth_type, "Basic") == 0 && auth_line != NULL)
    {
	char *colon = NULL;

	if (!USING_AUTH_BASIC(dc)) {
	    if (!USING_AUTH_AUTHORITATIVE(dc))
		return DECLINED;
	    LOG_RERROR(APLOG_ERR, 0, r,
                       "Basic authentication denied (%s off)",
                       CMD_USEBASIC);
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
	    /* N.B. If the basic auth header can't be parsed, there's no point
	     * declining if not authoritative. */
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
	return (result == OK || USING_AUTH_AUTHORITATIVE(dc)) ?
	    result : DECLINED;
    }

    /* Handle "Authorization: [other]" */
    else
    {
	/* We don't understand. Deny access. */
	add_auth_headers(r);
	return USING_AUTH_AUTHORITATIVE(dc) ? HTTP_UNAUTHORIZED : DECLINED;
    }
}

#if HAVE_UNIX_SUEXEC
/**
 * Provides uid/gid of a VAS authenticated user, for when suEXEC is enabled.
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
	dc->auth_negotiate = FLAG_UNSET;
	dc->auth_authoritative = FLAG_UNSET;
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
	merged_dc->auth_negotiate = FLAG_MERGE(base_dc->auth_negotiate,
		new_dc->auth_negotiate);
	merged_dc->auth_authoritative = FLAG_MERGE(base_dc->auth_authoritative,
		new_dc->auth_authoritative);
    }
    return (void *)merged_dc;
}

/** Passed a auth_vas_server_config pointer */
static CLEANUP_RET_TYPE
auth_vas_server_config_destroy(void *data)
{
    auth_vas_server_config *sc = (auth_vas_server_config *)data;
    
    if (sc != NULL) {
        
        if (sc->default_realm != NULL) {
            free(sc->default_realm);
            sc->default_realm = NULL;
        }
        
        if (sc->vas_serverid != NULL) {
            vas_id_free(sc->vas_ctx, sc->vas_serverid);
            sc->vas_serverid = NULL;
        }        
        
        if (sc->vas_ctx) {
            vas_ctx_free(sc->vas_ctx);
            sc->vas_ctx = NULL;            
        }
    }

    CLEANUP_RETURN;
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
	/* XXX Shouldn't we default to "HTTP/" + s->server_hostname ? */
	sc->service_principal = DEFAULT_SERVICE_PRINCIPAL;
    }
    
    /* register our server config cleanup function */
    apr_pool_cleanup_register(p, sc, auth_vas_server_config_destroy,
	    apr_pool_cleanup_null);
    
    TRACE_S(s, "auth_vas_create_server_config()");
    return (void *)sc;
}

/**
 * Performs post-configuration initialisation.
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
    for (sp = s; sp; sp = sp->next) {
	auth_vas_server_init(p, sp);
    }

    return OK;
}

/**
 * Initialises per-process mutexes.
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
    else
	LOG_ERROR(APLOG_DEBUG, r, s, "created mutex");
  }
#endif /* APXS1 */

/*
 * Module linkage structures.
 * Apache uses this at load time to discover the module entry points.
 */

#if !defined(APXS1)
/**
 * Registers this module's hook functions into Apache2 runtime hook lists.
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
 * This Apache2 module's public interface
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
 * The Apache1 module's public interface.
 * Each hook has its own slot in the module export table.
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
