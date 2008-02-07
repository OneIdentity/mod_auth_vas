/*
 * mod_auth_vas: VAS authentication module for Apache.
 * 
 * $Id$
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
 */

/*
 *  MODAUTHVAS_VERBOSE	- define this to get verbose debug level logging
 *  MODAUTHVAS_DIAGNOSTIC - define this to enable assertions
 */

#include <string.h>

#include <vas.h>
#include <vas_gss.h>
#include <gssapi_krb5.h>
#include <pwd.h>

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

#include "compat.h"
#include "cache.h"
#include "user.h"

/** Macro for returning a value from the match functions via a cleanup label
 * (called finish) to make the code read more easily. */
#define RETURN(r) do { \
    result = (r); \
    goto finish; \
} while (0)

/*
 * Per-server configuration structure - exists for lifetime of server process.
 */
typedef struct {
    vas_ctx_t   *vas_ctx;           /* The global VAS context - needs locking */
    vas_id_t	*vas_serverid;      /* The server identity */
    auth_vas_cache	*cache;     /* See cache.h */
    const char *server_principal;   /* AuthVasServerPrincipal or NULL */
    char *default_realm;            /* AuthVasDefaultRealm (never NULL) */
    char *cache_size;               /* Configured cache size */
    char *cache_time;               /* Configured cache lifetime */
} auth_vas_server_config;

/*
 * Per-directory configuration data - computed while traversing htaccess.
 * The int types should only be accessed using the USING_*() macros defined
 * below. This is because they might be uninitialised.
 */
typedef struct {
    int auth_negotiate;			/**< AuthVasUseNegotiate (default on) */
    apr_table_t *negotiate_subnets;     /**< AuthVasUseNegotiate (list of subnets, or NULL for all) */
    int auth_basic;			/**< AuthVasUseBasic (default off) */
    int auth_authoritative;		/**< AuthVasAuthoritative (default on) */
    int export_delegated;		/**< AuthVasExportDelegated (default off) */
    int localize_remote_user;		/**< AuthVasLocalizeRemoteUser (default off) */
    char *remote_user_map;		/**< AuthVasRemoteUserMap (NULL if unset) */
    char *remote_user_map_args;		/**< Argument to AuthVasRemoteUserMap (NULL if none) */
    int use_suexec;			/**< AuthVasSuexecAsRemoteUser (default off) */
    char *ntlm_error_document;		/**< AuthVasNTLMErrorDocument (default built-in) */
} auth_vas_dir_config;

/* Default behaviour if a flag is not set */
#define DEFAULT_USING_AUTH_NEGOTIATE            FLAG_ON
#define DEFAULT_USING_AUTH_BASIC                FLAG_OFF
#define DEFAULT_USING_AUTH_AUTHORITATIVE        FLAG_ON
#define DEFAULT_USING_EXPORT_DELEGATED          FLAG_OFF
#define DEFAULT_USING_LOCALIZE_REMOTE_USER      FLAG_OFF
#define DEFAULT_USING_SUEXEC                    FLAG_OFF

/* Returns the field flag, or def if dc is NULL or dc->field is FLAG_UNSET */
#define USING_AUTH_DEFAULT(dc, field, def) \
		((dc) ? TEST_FLAG_DEFAULT((dc)->field, def) : def)

/* Macros to safely test the per-directory flags, applying defaults. */
#define USING_AUTH_BASIC(dc) \
    USING_AUTH_DEFAULT(dc, auth_basic,         DEFAULT_USING_AUTH_BASIC)
#define USING_AUTH_AUTHORITATIVE(dc) \
    USING_AUTH_DEFAULT(dc, auth_authoritative, DEFAULT_USING_AUTH_AUTHORITATIVE)
#define USING_EXPORT_DELEGATED(dc) \
    USING_AUTH_DEFAULT(dc, export_delegated,   DEFAULT_USING_EXPORT_DELEGATED)
#define USING_LOCALIZE_REMOTE_USER(dc) \
    USING_AUTH_DEFAULT(dc, localize_remote_user, \
					    DEFAULT_USING_LOCALIZE_REMOTE_USER)
#define USING_SUEXEC(dc) \
    USING_AUTH_DEFAULT(dc, use_suexec,         DEFAULT_USING_SUEXEC)
/** Indicates that Negotiate auth is enabled for _some_ hosts, not
 * necessarily all. Use is_negotiate_enabled_for_client() to check the current
 * client. */
#define USING_AUTH_NEGOTIATE(dc) \
    USING_AUTH_DEFAULT(dc, auth_negotiate,     DEFAULT_USING_AUTH_NEGOTIATE)
    
/*
 * Miscellaneous constants.
 */
#define VAS_AUTH_TYPE		    "VAS"
#define DEFAULT_SERVER_PRINCIPAL    "HTTP/"

/* Flag values for directory configuration */
#define FLAG_UNSET	(-1)
#define FLAG_OFF	0
#define FLAG_ON		1
#define FLAG_MERGE(basef,newf) ((newf) == FLAG_UNSET ? (basef) : (newf))
#define TEST_FLAG_DEFAULT(f,def)  ((f) == FLAG_UNSET ? (def) : (f))

/*
 * Per-request note data - exists for lifetime of request only.
 */
typedef struct {
    auth_vas_user *user;		/* User information (shared) */
    /* TODO: Set  the vas_user_obj when the auth_vas_user is set. */
    /* TODO: Make the vas_user_obj part of the auth_vas_user */
    vas_user_t *vas_user_obj;		/* The remote user object (lazy initialisation - possibly NULL) */
    gss_ctx_id_t gss_ctx;		/* Negotiation context */
    gss_buffer_desc client;		/* Exported mech name */
    gss_cred_id_t deleg_cred;		/* Delegated credential */
    krb5_ccache deleg_ccache;		/* Exported cred cache */
} auth_vas_rnote;


/* Forward declaration for module structure: see bottom of this file. */
module AP_MODULE_DECLARE_DATA auth_vas_module;

/* Prototypes */
static const char *server_set_string_slot(cmd_parms *cmd, void *ignored, 
	const char *arg);
static const char *set_remote_user_map_conf(cmd_parms *cmd, void *struct_ptr,
	const char *args);
static const char *set_negotiate_conf(cmd_parms *cmd, void *struct_ptr,
	const char *args);
static int server_ctx_is_valid(server_rec *s);
static int match_user(request_rec *r, const char *name, int);
static int match_group(request_rec *r, const char *nam, int);
static int match_unix_group(request_rec *r, const char *nam, int);
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
	auth_vas_rnote **rn_ptr);
static int do_gss_spnego_accept(request_rec *r, const char *auth_line);
static void auth_vas_server_init(apr_pool_t *p, server_rec *s);
static void add_basic_auth_headers(request_rec *r);
static void add_auth_headers(request_rec *r);
static int auth_vas_check_user_id(request_rec *r);
#if HAVE_UNIX_SUEXEC
static ap_unix_identity_t *auth_vas_suexec(const request_rec *r);
#endif
static void export_cc(request_rec *r);
static int auth_vas_fixup(request_rec *r);
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
static void set_remote_user(request_rec *r);
static void set_remote_user_attr(request_rec *r, const char *line);
static void localize_remote_user(request_rec *r, const char *line);
static void localize_remote_user_strcmp(request_rec *r);
static int initialize_user(request_rec *request, const char *username);

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
 *
 * LOCK_VAS() returns either 0 (OK) on success or HTTP_*. 
 * In diagnostic mode, errors will be logged.
 */
static apr_thread_mutex_t *auth_vas_libvas_mutex;

/* Intra-process lock around the VAS library. */
#if defined(MODAUTHVAS_DIAGNOSTIC)
# define LOCK_VAS(r)   auth_vas_lock(r)
# define UNLOCK_VAS(r) auth_vas_unlock(r)
static apr_status_t auth_vas_lock(request_rec *r);
static void auth_vas_unlock(request_rec *r);

static apr_status_t auth_vas_lock(request_rec *r) {
    	apr_status_t error;

	ASSERT(auth_vas_libvas_mutex != NULL);
	error = apr_thread_mutex_lock(auth_vas_libvas_mutex);
	if (error)
	    LOG_RERROR(APLOG_ERR, error, r, "apr_thread_mutex_lock");
	return error;
}

static void auth_vas_unlock(request_rec *r) {
    	apr_status_t error;

	ASSERT(auth_vas_libvas_mutex != NULL);
	error = apr_thread_mutex_unlock(auth_vas_libvas_mutex);
	if (error)
	    LOG_RERROR(APLOG_WARNING, error, r, "apr_thread_mutex_unlock");
}
#else
# define LOCK_VAS(r)   apr_thread_mutex_lock(auth_vas_libvas_mutex)
# define UNLOCK_VAS(r) (void)apr_thread_mutex_unlock(auth_vas_libvas_mutex)
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
#define CMD_EXPORTDELEG		"AuthVasExportDelegated"
#define CMD_LOCALIZEREMOTEUSER	"AuthVasLocalizeRemoteUser" /**< Deprecated */
#define CMD_REMOTEUSERMAP	"AuthVasRemoteUserMap"
#define CMD_SPN			"AuthVasServerPrincipal"
#define CMD_OLDSPN		"AuthVasServicePrincipal" /**< Deprecated */
#define CMD_REALM		"AuthVasDefaultRealm"
#define CMD_USESUEXEC		"AuthVasSuexecAsRemoteUser"
#define CMD_NTLMERRORDOCUMENT	"AuthVasNTLMErrorDocument"
#define CMD_CACHESIZE		"AuthVasCacheSize"
#define CMD_CACHEEXPIRE		"AuthVasCacheExpire"

static const command_rec auth_vas_cmds[] =
{
    AP_INIT_RAW_ARGS(CMD_USENEGOTIATE, set_negotiate_conf,
		APR_OFFSETOF(auth_vas_dir_config, negotiate_subnets),
		ACCESS_CONF | OR_AUTHCFG,
		"Kerberos SPNEGO authentication using Active Directory (On, Off or list of subnets)"),
    AP_INIT_FLAG(CMD_USEBASIC, ap_set_flag_slot,
		APR_OFFSETOF(auth_vas_dir_config, auth_basic),
		ACCESS_CONF | OR_AUTHCFG,
		"Basic Authentication using Active Directory"),
    AP_INIT_FLAG(CMD_AUTHORITATIVE, ap_set_flag_slot,
		APR_OFFSETOF(auth_vas_dir_config, auth_authoritative),
		ACCESS_CONF | OR_AUTHCFG,
		"Authenticate authoritatively ('Off' allows fall-through to other authentication modules)"),
    AP_INIT_FLAG(CMD_EXPORTDELEG, ap_set_flag_slot,
		APR_OFFSETOF(auth_vas_dir_config, export_delegated),
		ACCESS_CONF | OR_AUTHCFG,
		"Write delegated credentials to a file, setting KRB5CCNAME"),
    AP_INIT_FLAG(CMD_LOCALIZEREMOTEUSER, ap_set_flag_slot,
		APR_OFFSETOF(auth_vas_dir_config, localize_remote_user),
		ACCESS_CONF | OR_AUTHCFG,
		"Set REMOTE_USER to a local username instead of a UPN (deprecated in favor of "CMD_REMOTEUSERMAP")"),
    AP_INIT_FLAG(CMD_USESUEXEC, ap_set_flag_slot,
		APR_OFFSETOF(auth_vas_dir_config, use_suexec),
		ACCESS_CONF | OR_AUTHCFG,
		"Execute CGI scripts as the authenticated remote user (if suEXEC is active)"),
    AP_INIT_RAW_ARGS(CMD_REMOTEUSERMAP, set_remote_user_map_conf,
		APR_OFFSETOF(auth_vas_dir_config, remote_user_map),
		ACCESS_CONF | OR_AUTHCFG,
		"How to map the remote user identity to the REMOTE_USER environment variable"),
    AP_INIT_TAKE1(CMD_NTLMERRORDOCUMENT, ap_set_string_slot,
		APR_OFFSETOF(auth_vas_dir_config, ntlm_error_document),
		ACCESS_CONF | OR_AUTHCFG,
		"Error page or string to provide when a client attempts unsupported NTLM authentication"),
    AP_INIT_TAKE1(CMD_SPN, server_set_string_slot,
		APR_OFFSETOF(auth_vas_server_config, server_principal),
		RSRC_CONF,
		"User Principal Name (LDAP userPrincipalName) for the server"),
    AP_INIT_TAKE1(CMD_OLDSPN, server_set_string_slot,
		APR_OFFSETOF(auth_vas_server_config, server_principal),
		RSRC_CONF,
		"User Principal Name (LDAP userPrincipalName) for the server (deprecated in favor of "CMD_SPN")"),
    AP_INIT_TAKE1(CMD_REALM, server_set_string_slot,
		APR_OFFSETOF(auth_vas_server_config, default_realm),
		RSRC_CONF,
		"Default realm for authorization"),
    AP_INIT_TAKE1(CMD_CACHESIZE, server_set_string_slot,
		APR_OFFSETOF(auth_vas_server_config, cache_size),
		RSRC_CONF,
		"Cache size (number of objects)"),
    AP_INIT_TAKE1(CMD_CACHEEXPIRE, server_set_string_slot,
		APR_OFFSETOF(auth_vas_server_config, cache_time),
		RSRC_CONF,
		"Cache object lifetime (expiry)"),
    { NULL }
};

/*
 * A static string containing the compile options, that can be revealed
 * by strings(1)
 */
static char module_info[] MAV_UNUSED =
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
 * Ensure the vas_user_obj is set.
 * Callers must hold the VAS lock.
 * This function will log an error message if a failure occurs and an error
 * cause is available.
 *
 * @return OK (0) on success, or an HTTP error code (nonzero) on error.
 */
static int
set_user_obj(request_rec *r)
{
    vas_err_t vaserr;

    auth_vas_server_config *sc = NULL;
    auth_vas_rnote *rn = NULL;

    ASSERT(r != NULL);

    sc = GET_SERVER_CONFIG(r->server->module_config);
    ASSERT(sc != NULL);
    ASSERT(sc->vas_ctx != NULL);

    TRACE_R(r, "%s", __func__);

    rn = GET_RNOTE(r);
    if (!rn)
	return HTTP_INTERNAL_SERVER_ERROR;

    if (rn->vas_user_obj)
	return 0; /* Already set */

    /* Use RUSER(r) because any other name is susceptible to failure
     * when username-attr-name is not userPrincipalName. */
    vaserr = auth_vas_user_get_vas_user(rn->user, &rn->vas_user_obj);

    if (vaserr) {
	rn->vas_user_obj = NULL;

	LOG_RERROR(APLOG_ERR, 0, r,
		"%s: Failed to get user object for %.100s: %s",
		__func__,
		RUSER(r), vas_err_get_string(sc->vas_ctx, 1));

	if (vaserr == VAS_ERR_NOT_FOUND) /* No such user */
	    return HTTP_UNAUTHORIZED;

	return HTTP_INTERNAL_SERVER_ERROR;
    }

    return 0; /* success */
}

/**
 * Checks if the previously authenticated user matches a particular name.
 * Name comparison is done by libvas.
 *   @param r The authenticated request
 *   @param name The name of the user to check
 *   @return OK if the user has the same name, otherwise HTTP_...
 */
static int
match_user(request_rec *r, const char *name, int log_level)
{
    int                       err; /*< Temporary storage */
    int                       result; /*< This function's return code */
    int                       user_matches = 0;
    auth_vas_server_config   *sc;
    auth_vas_rnote           *rnote;
    vas_user_t *required_user = NULL;

    ASSERT(r != NULL);
    ASSERT(name != NULL);
    ASSERT(RUSER(r) != NULL);

    TRACE_R(r, "%s: name=%s RUSER=%s", __func__, name, RUSER(r));

    sc = GET_SERVER_CONFIG(r->server->module_config);
    ASSERT(sc != NULL);
    ASSERT(sc->vas_ctx != NULL);

    if ((err = LOCK_VAS(r))) {
	LOG_RERROR(APLOG_ERR, 0, r,
                   "%s: unable to acquire lock", __func__);
	return err;
    }
    /* Use RETURN() from here on */

    if ((err = rnote_get(sc, r, &rnote)))
	RETURN(err);

    if ((err = set_user_obj(r)))
	RETURN(err);

    /* Convert the required user name into a user obj */
    if (vas_user_init(sc->vas_ctx, sc->vas_serverid, name, 0, 
		&required_user) != VAS_ERR_SUCCESS) {
	LOG_RERROR(log_level, 0, r,
		   "vas_user_init(%.100s): %s", name,
		   vas_err_get_string(sc->vas_ctx, 1));

	RETURN(HTTP_INTERNAL_SERVER_ERROR); /* Server misconfiguration */
    }

    if (vas_user_compare(sc->vas_ctx, rnote->vas_user_obj, required_user) == VAS_ERR_SUCCESS) {
	user_matches = 1;
	TRACE_R(r, "%s: user matches", __func__);
    } else {
	TRACE_R(r, "%s: user does not match", __func__);
    }

#if defined(MODAUTHVAS_VERBOSE)
    { 
	char *adn = NULL;
	char *bdn = NULL;
	(void)vas_user_get_dn(sc->vas_ctx, sc->vas_serverid, required_user, &adn);
	(void)vas_user_get_dn(sc->vas_ctx, sc->vas_serverid, rnote->vas_user_obj, &bdn);
	TRACE_R(r, "%s: <%s> <%s> %s", __func__, adn?adn:"ERROR",
		bdn?bdn:"ERROR", user_matches ? "match" : "no-match");
	if (adn) free(adn);
	if (bdn) free(bdn);
    }
#endif

    if (user_matches)
	RETURN(OK);
    else
	RETURN(HTTP_FORBIDDEN);

finish:
    if (required_user)
	vas_user_free(sc->vas_ctx, required_user);

    UNLOCK_VAS(r);

    return result;
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
    int                       result;
    int                       err; /*< temp storage */
    auth_vas_server_config   *sc;
    auth_vas_rnote           *rnote;

    ASSERT(r != NULL);
    ASSERT(name != NULL);
    ASSERT(RUSER(r) != NULL);

    sc = GET_SERVER_CONFIG(r->server->module_config);
    ASSERT(sc != NULL);
    ASSERT(sc->vas_ctx != NULL);

    if ((err = LOCK_VAS(r))) {
	LOG_RERROR(APLOG_ERR, 0, r,
                   "%s: unable to acquire lock", __func__);
	return err;
    }
    /* Use RETURN() from here on */

    if ((err = rnote_get(sc, r, &rnote)))
	RETURN(err);

#if 0 /* This is to be removed, but we do have a customer report saying they
	 are hitting this (subcase 580317-3). */
    /* Make sure that we have a valid VAS authentication context.
     * If it's not there, then we'll just fail since there is
     * no available group information. */
    if (rnote->vas_authctx == NULL) {
        LOG_RERROR(log_level, 0, r,
                   "%s: no available auth context for %s",
		   __func__,
                   rnote->vas_pname);
	RETURN(HTTP_FORBIDDEN);
    }
#endif

#define VASVER ((VAS_API_VERSION_MAJOR * 10000) + \
    	        (VAS_API_VERSION_MINOR * 100)   + \
    	        VAS_API_VERSION_MICRO)
#if VASVER < 40100
#define vas_auth_check_client_membership(c,i,a,n) \
    	vas_auth_is_client_member(c,a,n)
#endif

    vaserr = auth_vas_is_user_in_group(rnote->user, name);
    switch (vaserr) {
        case VAS_ERR_SUCCESS: /* user is member of group */
	    RETURN(OK);
            break;
            
        case VAS_ERR_NOT_FOUND: /* user not member of group */
            LOG_RERROR(log_level, 0, r,
                       "%s: %s not member of %s",
		       __func__,
                       auth_vas_user_get_principal_name(rnote->user),
                       name);
	    RETURN(HTTP_FORBIDDEN);
            break;
            
        case VAS_ERR_EXISTS: /* configured group not found */
            LOG_RERROR(log_level, 0, r,
                       "%s: group %s does not exist",
		       __func__,
                       name);
            RETURN(HTTP_FORBIDDEN);
            break;
            
        default: /* other type of error */
            LOG_RERROR(log_level, 0, r,
                       "%s: fatal vas error: %s",
		       __func__,
                       vas_err_get_string(sc->vas_ctx, 1));
	    RETURN(HTTP_INTERNAL_SERVER_ERROR);
            break;
    }

finish:
    UNLOCK_VAS(r);

    return result;
}

/**
 * Checks if the authenticated user appears in a UNIX group
 * Assumes the server config has been initialised.
 *   @param r The authenticated request
 *   @param name The name of the UNIX group to check membership of
 *   @return OK if group contains user, otherwise HTTP_...
 */
static int
match_unix_group(request_rec *r, const char *name, int log_level)
{
    vas_err_t                 vaserr;
    int                       result;
    int                       user_matches = 0;
    int                       err;
    auth_vas_server_config   *sc;
    auth_vas_rnote           *rnote;
    struct group             *gr;
    struct passwd            *pw = NULL;
    char **                   sp;

    ASSERT(r != NULL);
    ASSERT(name != NULL);
    ASSERT(RUSER(r) != NULL);

    sc = GET_SERVER_CONFIG(r->server->module_config);
    ASSERT(sc != NULL);
    ASSERT(sc->vas_ctx != NULL);

    if ((err = LOCK_VAS(r))) {
	LOG_RERROR(APLOG_ERR, 0, r,
                   "%s: unable to acquire lock", __func__);
	return err;
    }

    if ((err = rnote_get(sc, r, &rnote)))
	RETURN(err);

    if ((err = set_user_obj(r)))
	RETURN(err);

    /* Determine the user's unix name */
    vaserr = vas_user_get_pwinfo(sc->vas_ctx, NULL, rnote->vas_user_obj, &pw);
    if (vaserr == VAS_ERR_NOT_FOUND) {
        /* User does not map to a unix user, so cannot be part of a group */
	RETURN(HTTP_FORBIDDEN);
    }
    if (vaserr != VAS_ERR_SUCCESS) {
	LOG_RERROR(APLOG_ERR, 0, r,
                   "%s: vas_user_get_pwinfo(): %s", __func__,
                   vas_err_get_string(sc->vas_ctx, 1));
	RETURN(HTTP_INTERNAL_SERVER_ERROR);
    }

    /* 
     * Obtain the list of users in the unix group.
     * Note that we deliberately cause a 500 error if the group
     * is not found, because we assert 
     */
#if HAVE_GETGRNAM_R
    {
        char *buf;
        size_t buflen = 16384;  /* GETGR_R_SIZE_MAX is not portable :( */
        struct group *gbuf;
        
        gbuf = (struct group *)apr_palloc(r->pool, 
                sizeof (struct group));
        if (gbuf)
            buf = apr_palloc(r->pool, buflen);
	if (gbuf == NULL || buf == NULL) {
	    LOG_RERROR(APLOG_ERR, APR_ENOMEM, r, "apr_palloc");
	    RETURN(HTTP_INTERNAL_SERVER_ERROR);
	}
        if ((err = getgrnam_r(name, gbuf, buf, buflen, &gr))) {
            LOG_RERROR(log_level, ret, r,
                       "getgrnam_r: cannot access group '%s'", name);
            RETURN(HTTP_INTERNAL_SERVER_ERROR);
        }
    }
#else
    gr = getgrnam(name);
    if (!gr) {
	LOG_RERROR_ERRNO(log_level, 0, r,
                   "getgrnam: cannot access group '%s'", name);
	RETURN(HTTP_INTERNAL_SERVER_ERROR);
    }
#endif

    /* Search the group list */
    for (sp = gr->gr_mem; sp && *sp; sp++) {
        if (strcmp(pw->pw_name, *sp) == 0) {
            user_matches = 1;
            break;
        }
    }

    if (user_matches) {
	RETURN(OK);
    } else {
	LOG_RERROR(log_level, 0, r,
		   "%s: %s not member of %s",
		   __func__,
		   auth_vas_user_get_principal_name(rnote->user),
		   name);
	RETURN(HTTP_FORBIDDEN);
    }

finish:
    UNLOCK_VAS(r);
    if (pw)
        free(pw);

    return result;
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
    int                       result;
    int                       err;
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
    
    if ((err = LOCK_VAS(r))) {
	LOG_RERROR(APLOG_ERR, 0, r,
                   "%s: unable to acquire lock", __func__);
	return err;
    }
    /* Use RETURN() from here on */

    if ((err = rnote_get(sc, r, &rnote)))
	RETURN(err);

    if ((vaserr = auth_vas_user_get_vas_user(rnote->user, &vasuser))) {
	LOG_RERROR(log_level, 0, r,
		"%s: fatal vas error for user_init: %d, %s",
		__func__,
		vaserr, vas_err_get_string(sc->vas_ctx, 1));
	RETURN(HTTP_FORBIDDEN);
    }

    if ((vaserr = vas_user_get_dn(sc->vas_ctx, sc->vas_serverid, vasuser,
		    &dn )) != VAS_ERR_SUCCESS ) 
    {
	LOG_RERROR(log_level, 0, r,
	       	"%s: fatal vas error for user_get_dn: %d, %s",
	       	__func__, vaserr, vas_err_get_string(sc->vas_ctx, 1));
	RETURN(HTTP_FORBIDDEN);
    }

    ASSERT(dn != NULL);
    if (dn_in_container(dn, container)) {
	RETURN(OK);
    } else {
        LOG_RERROR(APLOG_INFO, 0, r,
	       	"%s: user dn %s not in container %s",
	       	__func__, dn, container);
	RETURN(HTTP_FORBIDDEN);
    }

finish:
    if (vasuser) vas_user_free(sc->vas_ctx, vasuser);
    if (dn)      free(dn);

    UNLOCK_VAS(r);

    return result;
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
 * Match functions must assume the VAS context is UNLOCKED.
 */
static const struct match {
    const char *name;
    int (*func)(request_rec *r, const char *arg, int log_level);
    int has_args;
} matchtab[] = {
    { "user",	    match_user,	      1 },
    { "group",	    match_group,      1 },
    { "unix-group", match_unix_group, 1 },
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
    TRACE_R(r, "%s: user=%s authtype=%s",
	__func__, RUSER(r), RAUTHTYPE(r));

    /* Ignore authz requests for non-VAS authentication */
    if (!is_our_auth_type(r))
	return DECLINED;

    if (!server_ctx_is_valid(r->server)) {
	if (!USING_AUTH_AUTHORITATIVE(dc))
	    return DECLINED;
	LOG_RERROR(APLOG_ERR, 0, r,
	      "%s: no VAS context for server; FORBIDDEN", __func__);
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
		"%s: Unknown requirement '%s'", __func__, type);
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
                    USING_AUTH_AUTHORITATIVE(dc) ? APLOG_ERR : APLOG_NOTICE);
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
                USING_AUTH_AUTHORITATIVE(dc) ? APLOG_ERR : APLOG_NOTICE);
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
		  "%s: Denied access to user '%s' for uri '%s'",
		  __func__, RUSER(r), r->uri);
    return HTTP_FORBIDDEN;
}

/**
 * Authenticate a user using a plaintext password.
 *   @param r the request
 *   @param username the user's name
 *   @param password the password to authenticate against
 *   @return OK if credentials could be obtained for the user 
 *           with the given password to access this HTTP service
 */
static int
do_basic_accept(request_rec *r, const char *username, const char *password)
{
    int                     err;
    int                     result;
    vas_err_t               vaserr;
    auth_vas_server_config *sc = GET_SERVER_CONFIG(r->server->module_config);
    auth_vas_rnote         *rn;

    TRACE_R(r, "%s: user='%s' password=...", __func__, username);

    if ((err = LOCK_VAS(r))) {
	LOG_RERROR(APLOG_ERR, 0, r,
                   "%s: unable to acquire lock", __func__);
	return err;
    }
    /* Use RETURN() from here on */

    if ((err = rnote_get(sc, r, &rn)))
	RETURN(err);

    err = initialize_user(r, username);
    if (err)
	RETURN(err);

    /* Authenticate */
    vaserr = auth_vas_user_authenticate(rn->user,
	    VAS_ID_FLAG_USE_MEMORY_CCACHE, password);
    if (vaserr) {
	LOG_RERROR(APLOG_ERR, 0, r, /* This log message mimics mod_auth_basic's */
		"user %s: authentication failure for \"%s\": %s",
		username, r->uri, vas_err_get_string(sc->vas_ctx, 1));
	RETURN(HTTP_UNAUTHORIZED);
    }

    /* Authenticated */
    RAUTHTYPE(r) = "Basic";
    RUSER(r) = apr_pstrdup(RUSER_POOL(r), auth_vas_user_get_principal_name(rn->user));
    RETURN(OK);

finish:

    if (result == HTTP_UNAUTHORIZED) {
	/* Prompt the client to try again */
	add_auth_headers(r);
    }

    /* Release resources */
    UNLOCK_VAS(r);

    return result;
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
    memset(rn, 0, sizeof(*rn));
    rn->gss_ctx = GSS_C_NO_CONTEXT;
    rn->deleg_cred = GSS_C_NO_CREDENTIAL;
}

/** Releases storage associated with the rnote.
 * LOCK_VAS() must have been called prior to calling this.
 */
static void
rnote_fini(request_rec *r, auth_vas_rnote *rn)
{
    auth_vas_server_config *sc;
    OM_uint32 gsserr, minor;

    sc = GET_SERVER_CONFIG(r->server->module_config);

    if (rn->deleg_ccache) {
	krb5_context krb5ctx;
        if (!vas_krb5_get_context(sc->vas_ctx, &krb5ctx)) {
	    (void)krb5_cc_destroy(krb5ctx, rn->deleg_ccache);
	    rn->deleg_ccache = NULL;
        }
    }

    if (rn->deleg_cred != GSS_C_NO_CREDENTIAL) {
	if ((gsserr = gss_release_cred(&minor, &rn->deleg_cred)))
	    log_gss_error(APLOG_MARK, APLOG_ERR, 0, r,
		    "gss_release_cred", gsserr, minor);
    }

    if (rn->gss_ctx != GSS_C_NO_CONTEXT) {
	if (rn->client.value)
	    (void)gss_release_buffer(&minor, &rn->client);
	if ((gsserr = gss_delete_sec_context(&minor, &rn->gss_ctx, NULL)))
	    log_gss_error(APLOG_MARK, APLOG_ERR, 0, r,
		    "gss_delete_sec_context", gsserr, minor);
    }

    if (rn->user)
	auth_vas_user_unref(rn->user);
}

/** This function is called when the request pool is being released.
 * It is passed an auth_vas_rnote pointer we need to cleanup. */
static CLEANUP_RET_TYPE
auth_vas_cleanup_request(void *data)
{
    request_rec *r = (request_rec *)data;
    auth_vas_rnote *rn;

    /* "A cleanup function can safely allocate memory from the pool that is
     * being cleaned up." - APR 1.2 docs. */

    TRACE_R(r, "%s", __func__);
    rn = GET_RNOTE(r);
    if (rn != NULL) {
	if (LOCK_VAS(r))
	    LOG_RERROR(APLOG_WARNING, 0, r,
		    "%s: cannot acquire lock to release resources", __func__);

	rnote_fini(r, rn);
	UNLOCK_VAS(r);
	SET_RNOTE(r, NULL);
    }
    CLEANUP_RETURN;
}

/**
 * Gets a user object for the given username and stores it in the request note.
 * Both the request_rec and the username must not be NULL.
 *
 * Returns OK (0) on success or an HTTP error code on failure, usually
 * HTTP_UNAUTHORIZED (meaning unauthenticated).
 */
static int
initialize_user(request_rec *request, const char *username) {
    vas_err_t result; /* Our return code */
    vas_err_t vaserr; /* Temp storage */
    auth_vas_server_config *sc;
    auth_vas_rnote *rnote;

    /* Empty username is an automatic authentication failure
     * (and it used to trigger a bug in VAS, bug #9473). */
    if (username[0] == '\0')
        RETURN(HTTP_UNAUTHORIZED);

    sc = GET_SERVER_CONFIG(request->server->module_config);
    rnote = GET_RNOTE(request);

    /* This is a soft assertion */
    if (rnote->user != NULL) {
	LOG_RERROR(APLOG_ERR, 0, request,
		"%s: User is already set. Overriding it.", __func__);
	auth_vas_user_unref(rnote->user);
	rnote->user = NULL;
    }

    vaserr = auth_vas_user_alloc(sc->cache, username, &rnote->user);
    if (vaserr) {
	rnote->user = NULL; /* ensure */
	LOG_RERROR(APLOG_ERR, 0, request,
		"%s: Failed to initialize user for %s: %s",
		__func__, username, vas_err_get_string(sc->vas_ctx, 1));
	RETURN(HTTP_UNAUTHORIZED);
    }

    LOG_RERROR(APLOG_DEBUG, 0, request, "%s: Remote user principal name is %s",
	    __func__, auth_vas_user_get_principal_name(rnote->user));

    RETURN(OK);

finish:
    return result;
}

/**
 * Retrieves the request note for holding VAS information.
 * LOCK_VAS() must have been called prior to calling this.
 * @return 0 on success, or an HTTP error code on failure
 */
static int
rnote_get(auth_vas_server_config* sc, request_rec *r, auth_vas_rnote **rn_ptr)
{
    auth_vas_rnote  *rn = NULL;
    
    rn = GET_RNOTE(r);
    if (rn == NULL) {

        TRACE_R(r, "%s: creating rnote", __func__);
        rn = (auth_vas_rnote *)apr_palloc(r->connection->pool, sizeof *rn);

        /* initialize the rnote and set it on the record */
        rnote_init(rn);
        SET_RNOTE(r, rn);

        /* Arrange to release the RNOTE data when the request completes */
        apr_pool_cleanup_register(r->pool, r, auth_vas_cleanup_request,
	       	apr_pool_cleanup_null);
    } else {
        TRACE_R(r, "%s: reusing existing rnote", __func__);
    }

    /* Success */
    *rn_ptr = rn;
    return 0;
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

    TRACE_R(r, "%s: line='%.16s...'", __func__, auth_line);

    /* Get the parameter after "Authorization" */
    auth_param = ap_getword_white(r->pool, &auth_line);
    if (auth_param == NULL) {
	LOG_RERROR(APLOG_NOTICE, 0, r,
	   "%s: Client sent empty Negotiate auth-data parameter", __func__);
	return DECLINED;
    }

    sc = GET_SERVER_CONFIG(r->server->module_config);

    /* setup the input token */
    in_token.length = strlen(auth_param);
    in_token.value = (void *)auth_param;

    if ((result = LOCK_VAS(r))) {
	LOG_RERROR(APLOG_ERR, 0, r,
	   "%s: unable to acquire lock", __func__);
	return result;
    }

    /* Store negotiation context in the connection record */
    if ((result = rnote_get(sc, r, &rn))) {
	UNLOCK_VAS(r);
	/* no other resources to free */
	return result;
    }

    if (VAS_ERR_SUCCESS != vas_gss_initialize(sc->vas_ctx, sc->vas_serverid)) {
	LOG_RERROR(APLOG_ERR, 0, r, "Unable to initialize GSS: %s",
		vas_err_get_string(sc->vas_ctx, 1));
	UNLOCK_VAS(r);
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Accept token - have the VAS api handle the base64 stuff for us */
    TRACE_R(r, "calling vas_gss_spnego_accept, base64 token_size=%d",
            (int) in_token.length);
    gsserr = vas_gss_spnego_accept(sc->vas_ctx, sc->vas_serverid,
	    NULL, &rn->gss_ctx, NULL,
	    VAS_GSS_SPNEGO_ENCODING_BASE64, &in_token, &out_token,
	    &rn->deleg_cred);

    /* Handle completed GSSAPI negotiation */
    if (gsserr == GSS_S_COMPLETE) {
	OM_uint32       minor_status, err;
	gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;
	vas_err_t	vaserr;
	auth_vas_server_config	*sc;

	sc = GET_SERVER_CONFIG(r->server->module_config);

	/* Get the client's name */
	err = gss_inquire_context(&minor_status, rn->gss_ctx, &client_name,
		NULL, NULL, NULL, NULL, NULL, NULL);
	if (err != GSS_S_COMPLETE) {
	    result = HTTP_UNAUTHORIZED;
	    log_gss_error(APLOG_MARK, APLOG_ERR, 0, r,
		    "gss_inquire_context", err, minor_status);
	    goto done;
	}

	/* Convert the client's name into a visible string */
	err = gss_display_name(&minor_status, client_name, &buf, NULL);
	if (err != GSS_S_COMPLETE) {
	    result = HTTP_UNAUTHORIZED;
	    log_gss_error(APLOG_MARK, APLOG_ERR, 0, r,
		    "gss_display_name", err, minor_status);
	    goto done;
	}

	/* Copy out the authenticated user's name. */
	RUSER(r) = apr_pstrmemdup(RUSER_POOL(r), buf.value, buf.length);
	gss_release_buffer(&minor_status, &buf);
	if (RUSER(r) == NULL) {
	    LOG_RERROR(APLOG_ERR, APR_ENOMEM, r, "apr_pstrmemdup");
	    result = HTTP_INTERNAL_SERVER_ERROR;
	    goto done;
	}

	/* FIXME: Call initialize_user instead? */
	/* Create the remote user object now that we have their name */
	ASSERT(rn->user == NULL);
	vaserr = auth_vas_user_alloc(sc->cache, RUSER(r), &rn->user);
	if (vaserr) {
	    rn->user = NULL; /* ensure */
	    LOG_RERROR(APLOG_ERR, 0, r,
		    "%s: Error allocating user object for %s",
		    __func__, RUSER(r));
	    result = HTTP_INTERNAL_SERVER_ERROR;
	    goto done;
	}

	/* Save the VAS auth context */
	{
	    gss_cred_id_t servercred = GSS_C_NO_CREDENTIAL;
	    vas_gss_acquire_cred(sc->vas_ctx, sc->vas_serverid, &minor_status, GSS_C_ACCEPT, &servercred);

	vaserr = auth_vas_user_use_gss_result(rn->user, servercred, rn->gss_ctx);
	if (vaserr) {
	    result = HTTP_UNAUTHORIZED;
	    /* We know that the cache & user stuff uses the same vas context as
	     * the server, but using the vas_ctx here still feels dirty. */
	    LOG_RERROR(APLOG_ERR, 0, r,
		    "%s: auth_vas_user_use_gss_result failed: %s", __func__,
		    vas_err_get_string(sc->vas_ctx, 1));
	    goto done;
	}

	/* FIXME: free properly */
	gss_release_cred(&minor_status, &servercred);

	}

	/* Keep a copy of the client's mechanism name in the connection note */
	err = gss_export_name(&minor_status, client_name, &rn->client);
	if (err != GSS_S_COMPLETE) {
	    result = HTTP_UNAUTHORIZED;
	    log_gss_error(APLOG_MARK, APLOG_ERR, 0, r,
		    "gss_export_name", err, minor_status);
	}

	TRACE_R(r, "authenticated user: '%s'", RUSER(r));

	/* Authentication has succeeded at this point */
	RAUTHTYPE(r) = (char *)VAS_AUTH_TYPE;
	result = OK;
    } else if (gsserr == GSS_S_CONTINUE_NEEDED) {
	TRACE_R(r, "waiting for more tokens from client");
	result = HTTP_UNAUTHORIZED;
    } else if (strcmp(auth_param, "TlRM") == 0) {
	const auth_vas_dir_config *dc = GET_DIR_CONFIG(r->per_dir_config);
	LOG_RERROR(APLOG_ERR, 0, r,
		    "NTLM authentication attempted");
	/* Already logged the failure cause */
	gsserr = 0;
	if (dc->ntlm_error_document)
	    ap_custom_response(r, HTTP_UNAUTHORIZED, dc->ntlm_error_document);
	else
	    ap_custom_response(r, HTTP_UNAUTHORIZED, apr_pstrcat(r->pool,
			DOCTYPE_HTML_2_0
			"<HTML><HEAD>\n"
			"<TITLE>NTLM authentication not supported</TITLE>\n"
			"</HEAD><BODY>\n"
			"<H1>NTLM authentication not supported</H1>\n"
			"The server received an NTLM authentication token,\n"
			"but NTLM authentication is not supported.\n"
			"This is usually the result of\n"
			"not being in the same Active Directory domain as this server,\n"
			"using an old version of\n"
			"Internet Explorer (earlier than version 6.0) or entering\n"
			"the wrong password in IE's password dialog.\n"
			"<H2>Solving this problem</H2>\n"
			"<UL>\n"
			"<LI>If your computer is on an Active Directory domain, see\n"
			"<A HREF=\"http://rc.quest.com/topics/mod_auth_vas/howto.php#browser-config\">"
			"http://rc.quest.com/topics/mod_auth_vas/howto.php#browser-config</A>\n"
			"for browser configuration instructions.\n"
			"<LI>For Internet Explorer 6 on Windows 2000, see\n"
			"<A HREF=\"http://support.microsoft.com/kb/299838\">"
			"http://support.microsoft.com/kb/299838</A>"
			"<LI>If your computer is not in the same Active Directory domain\n"
			"as this server, there is no cross-realm trust and this server\n"
			"does not accept \"Basic\" (password) authentication, you will\n"
			"not be able to access it.\n"
			"<LI>Internet Explorer on Microsoft Windows 98 or NT 4.0\n"
			"does not support the Kerberos authentication mechanism\n"
			"used by this server.\n"
			"</UL>\n"
			"<P>For further help, please contact your support personnel\n"
			"or the server administrator.\n"
			"<P>This error page can be customized with the\n"
			"<A HREF=\"http://rc.quest.com/topics/mod_auth_vas/install.php#config-dir\">AuthVasNTLMErrorDocument</A>\n"
			"configuration option.\n"
			, ap_psignature("<HR>\n", r),
			"</BODY></HTML>\n"
			, NULL
			));
	result = HTTP_UNAUTHORIZED;
    } else {
	/* Any other result means we send back an Unauthorized result */
	LOG_RERROR(APLOG_ERR, 0, r,
                   "%s: %s",
		   __func__,
                   vas_err_get_string(sc->vas_ctx, 1));
	result = HTTP_UNAUTHORIZED;
    }

 done:
    vas_gss_deinitialize(sc->vas_ctx);

    if (GSS_ERROR(gsserr))
	LOG_RERROR(APLOG_ERR, 0, r,
		   "%s: %s",
		   __func__,
		   vas_err_get_string(sc->vas_ctx, 1));

    UNLOCK_VAS(r);

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
	strncat(auth_out, out_token.value, out_token.length);

	/* Add to the outgoing header set */
	apr_table_set(r->err_headers_out, "WWW-Authenticate", auth_out);
	/* add_basic_auth_headers(r); */
    }

    /* Detect NTLMSSP attempts */
    if (gsserr == GSS_S_DEFECTIVE_TOKEN &&
        in_token.length >= 7 &&
        memcmp(in_token.value, "NTLMSSP", 7) == 0)
    {
	LOG_RERROR(APLOG_NOTICE, 0, r,
	    "Client used unsupported NTLMSSP authentication");
    }

 cleanup:
    if (LOCK_VAS(r))
	LOG_RERROR(APLOG_WARNING, 0, r,
	    "do_gss_spnego_accept: cannot acquire lock to release resources");
    else {
	gss_release_buffer(&gsserr, &out_token);
	if (client_name)
	    gss_release_name(NULL, &client_name);
	UNLOCK_VAS(r);
    }

    return result;
}


static void
set_cache_size(server_rec *server)
{
    auth_vas_server_config *sc;
#if defined(APXS1)
    long int size;
#else /* APXS2 */
    apr_int64_t size;
#endif /* APXS2 */
    char *end;

    sc = GET_SERVER_CONFIG(server->module_config);

    if (!sc->cache_size) /* Not configured */
	return;

#if defined(APXS1)
    size = strtol(sc->cache_size, &end, 10);
#else /* APXS2 */
    size = apr_strtoi64(sc->cache_size, &end, 10);
#endif /* APXS2 */

    if (*end == '\0') {
	/* Clamp the size to [1,UINT_MAX] */
	if (size < 1)
	    size = 1;
	if (size > UINT_MAX)
	    size = UINT_MAX;

	auth_vas_cache_set_max_size(sc->cache, (unsigned int) size);
    } else {
	LOG_ERROR(APLOG_WARNING, 0, server,
		"%s: invalid " CMD_CACHESIZE " setting: %s",
		__func__, sc->cache_size);
    }

    LOG_ERROR(APLOG_DEBUG, 0, server,
	    "%s: cache size is %u",
	    __func__, auth_vas_cache_get_max_size(sc->cache));
}

/**
 * Sets the cache timeout for the server cache based on the string-format
 * timeout value in the server config.
 *
 * The string may end with the suffix 'h', 'm', or 's' for Hours, Minutes and
 * Seconds. An unadorned value means seconds.
 *
 * The value must be an integer.
 */
static void
set_cache_timeout(server_rec *server)
{
    auth_vas_server_config *sc;
#if defined(APXS1)
    long int secs;
#else /* APXS2 */
    apr_int64_t secs;
#endif /* APXS2 */
    char *end;
    int multiplier = 1; /* Using a separate var to detect integer overflow */

    sc = GET_SERVER_CONFIG(server->module_config);

    if (!sc->cache_time) /* Not configured */
	return;

#if defined(APXS1)
    secs = strtol(sc->cache_time, &end, 10);
#else /* APXS2 */
    secs = apr_strtoi64(sc->cache_time, &end, 10);
#endif /* APXS2 */

    /* Clamp the time to [0,UINT_MAX] */
    if (secs < 0)
	secs = 0;
    if (secs > UINT_MAX)
	secs = UINT_MAX;

    /* Process (h)our/(m)inute/(s)econd suffixes.
     * Makes liberal use of fall-throughs. */
    switch (*end) {
	case 'h':
	    multiplier *= 60;
	case 'm':
	    multiplier *= 60;

	    /* Prevent wrapping */
	    if (secs > (UINT_MAX / multiplier))
		secs = UINT_MAX / multiplier;
	    else
		secs *= multiplier;

	case 's':
	case '\0':
	    auth_vas_cache_set_max_age(sc->cache, (unsigned int) secs);
	    break;

	default:
	    LOG_ERROR(APLOG_WARNING, 0, server,
		    "%s: invalid " CMD_CACHEEXPIRE " setting: %s",
		    __func__, sc->cache_time);
    }

    LOG_ERROR(APLOG_DEBUG, 0, server,
	    "%s: cache lifetime is %u seconds",
	    __func__, auth_vas_cache_get_max_age(sc->cache));
}

/**
 * Initialises the VAS context for a server.
 * Assumes that the server configuration files have been
 * parsed to fill in the server config records.
 * Sets the vas context to NULL if the service principal
 * name cannot be translated into a server key.
 * This function is called before the VAS mutex has
 * initialised, and should not call LOCK_VAS/UNLOCK_VAS
 *
 *   @param s the server being initialised for VAS
 *   @param p memory pool associated with server instance
 */
static void
auth_vas_server_init(apr_pool_t *p, server_rec *s)
{
    vas_err_t               vaserr;
    vas_auth_t             *vasauth;
    auth_vas_server_config *sc;
    char *tmp_realm;

    TRACE_S(s, "%s(host=%s)", __func__, s->server_hostname);

    sc = GET_SERVER_CONFIG(s->module_config);
    TRACE_S(s, "sc=%x", (int)sc);

    if (sc == NULL) {
	LOG_ERROR(APLOG_ERR, 0, s,
	    "%s: no server config", __func__);
	return;
    }

    if (sc->vas_ctx != NULL) {
	TRACE_S(s, "%s: already initialised", __func__);
	return;
    }

    TRACE_S(s, "%s: spn='%s'", __func__, sc->server_principal);

    /* Obtain a new VAS context for the web server */
    vaserr = vas_ctx_alloc(&sc->vas_ctx);
    if (vaserr != VAS_ERR_SUCCESS) {
        LOG_ERROR(APLOG_ERR, 0, s, 
		"vas_ctx_alloc failed, err = %d",
	       	vaserr);
	return;
    }

#if 0 /* Only available since about VAS 3.0.2.5.
       * Disabled for now for backwards-compatability. */
    vas_ctx_set_option(sc->vas_ctx,
	    VAS_CTX_OPTION_SEPARATOR_IN_ERROR_MESSAGE_STRING, ".");
#endif

    vaserr = vas_info_joined_domain(sc->vas_ctx, &tmp_realm, NULL);
    if (vaserr == VAS_ERR_SUCCESS) {
	/* sc->default_realm is always owned by apache */
	sc->default_realm = apr_pstrdup(p, tmp_realm);
	free(tmp_realm);
    }
    else {
	LOG_ERROR(APLOG_WARNING, vaserr, s,
		"VAS cannot determine the default realm, "
		"ensure it is set with AuthVasDefaultRealm.");
	/* make sure default_realm contains _something_. If one day
	 * sc->server_principal contains a full SPN, we could use the
	 * domain from it. See initialisation in auth_vas_create_server_config().
	 */
	sc->default_realm = "unknown-realm";
    }
    
    /* Create the vas_id for the server */
    vaserr = vas_id_alloc(sc->vas_ctx, 
                          sc->server_principal,
                          &sc->vas_serverid);
    if (vaserr != VAS_ERR_SUCCESS) {
	LOG_ERROR(APLOG_ERR, 0, s,
                  "vas_id_alloc failed on %s, err = %s",
                  sc->server_principal,
                  vas_err_get_string(sc->vas_ctx, 1));
	return;
    }

    /* Establish our credentials using the service keytab */
    /* Don't try getting a TGT yet. SPNs that are not also UPNs cannot
     * get a TGT and would cause this to fail. */
    vaserr = vas_id_establish_cred_keytab(sc->vas_ctx, 
                                          sc->vas_serverid, 
                                          VAS_ID_FLAG_USE_MEMORY_CCACHE |
                                          VAS_ID_FLAG_KEEP_COPY_OF_CRED |
                                          VAS_ID_FLAG_NO_INITIAL_TGT,
                                          NULL);
    if (vaserr != VAS_ERR_SUCCESS) {
	LOG_ERROR(APLOG_ERR, 0, s,
                  "vas_id_establish_cred_keytab failed, err = %s",
                  vas_err_get_string(sc->vas_ctx, 1));
	return;
    } else {
        TRACE_S(s, "successfully established creds for %s", sc->server_principal);
    }

    /* If this SPN is also a UPN, it should be able to authenticate against
     * itself and prove that the keytab works (eg. not expired). If it is just
     * an SPN (that usually means it's a service alias), it will return
     * unknown principal. */
    vaserr = vas_auth(sc->vas_ctx,
                      sc->vas_serverid,
                      sc->vas_serverid,
                      &vasauth);

    if (vaserr != VAS_ERR_SUCCESS) {
	vas_err_info_t *errinfo;

	errinfo = vas_err_get_cause_by_type(sc->vas_ctx, VAS_ERR_TYPE_KRB5);

	if (errinfo && errinfo->code == KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN) {
	    LOG_ERROR(APLOG_INFO, 0, s,
		      "Credential test for %s failed with %s, "
		      "this is harmless if it is a service alias",
		      sc->server_principal,
		      krb5_get_error_name(errinfo->code));
	} else {
	    LOG_ERROR(APLOG_ERR, 0, s,
		      "vas_auth failed, err = %s",
		      vas_err_get_string(sc->vas_ctx, 1));
	}

	if (errinfo)
	    vas_err_info_free(errinfo);
    } else {
        TRACE_S(s, "Successfully authenticated to %s with keytab",
		sc->server_principal);
        vas_auth_free(sc->vas_ctx, vasauth);
    }

    sc->cache = auth_vas_cache_new(s->process->pool, sc->vas_ctx, sc->vas_serverid,
	    (void(*)(void*))auth_vas_user_ref,
	    (void(*)(void*))auth_vas_user_unref,
	    (const char*(*)(void*))auth_vas_user_get_name);

    set_cache_size(s);
    set_cache_timeout(s);
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

struct ip_cmp_closure {
    request_rec *request;
    int match_found;
#if defined(APXS1)
    struct sockaddr_in sockaddr;
#else /* APXS2 */
    apr_sockaddr_t *sockaddr_p;
#endif /* APXS2 */
};

/**
 * Callback to determine whether a host matches a subnet.
 * The match state will be returned in both the closure
 * (::ip_cmp_closure::match_found) and this function's return code.
 * The ::ip_cmp_closure::match_found field is necessary for APXS1 but also
 * used on APXS2. Beware that the ::ip_cmp_closure::match_found field and
 * this function's return code are inverse.
 *
 * @param[in,out] rec
 *            Closure with match info (request, client address) and match
 *            state.
 *
 * @param[in] key
 *            Ignored.
 *
 * @param[in] value
 *            String representation of the network address and mask, separated
 *            by a forward-slash. If the forward-slash is omitted, it is
 *            assumed to be an exact host match. The mask may be in either
 *            dotted-decimal address or number-of-bits notation.
 *
 * @return ZERO if the subnet matched the IP, or NON-ZERO if it did not match.
 *            (like ::strcmp). Errors also return non-zero. Callers must stop
 *            iterating with the same closure if they receive a zero return, or
 *            a match state in the closure might be overridden with a no-match
 *            state. apr_table_do and ap_table_do behave correctly.
 */
static int
mav_ip_subnet_cmp(void *rec, const char *key, const char *value)
{
    enum { MATCH = 0, NO_MATCH = 1, ERROR = 2 };
    struct ip_cmp_closure *closure = (struct ip_cmp_closure *)rec;
    request_rec *r = closure->request;

    closure->match_found = 0;

#if !defined(APXS1) /* Apache 2 */
    {
	apr_ipsubnet_t *ipsubnet;
	char addr[sizeof("0000:0000:0000:0000:0000:0000:0000:0000")];
	char *slash;
	const char *mask;
	apr_status_t subnet_create_err;

	slash = strchr(value, '/');
	if (slash) {
	    int count = slash - value;
	    mask = slash + 1;
	    if (count > sizeof(addr) - 1) {
		/* Too long to be a valid IPv4 or IPv6 address */
		LOG_RERROR(APLOG_ERR, 0, r,
			"%s: Invalid address from config (%s): too long",
			__func__, value);
		return ERROR;
	    }

	    memcpy(addr, value, count);
	    addr[count] = '\0';

	    subnet_create_err =
		apr_ipsubnet_create(&ipsubnet, addr, mask, closure->request->pool);
	    memset(addr, '\0', sizeof(addr));
	} else {
	    /* No subnet provided - checking exact host */
	    subnet_create_err =
		apr_ipsubnet_create(&ipsubnet, value, NULL, closure->request->pool);
	}

	if (subnet_create_err) {
	    LOG_RERROR(APLOG_ERR, subnet_create_err, r,
		    "Error turning %s/%s into an IP subnet",
		    addr, mask);
	    return ERROR;
	}

	if (apr_ipsubnet_test(ipsubnet, closure->sockaddr_p))
	    closure->match_found = 1;
	
	return !closure->match_found;
    }

#else /* APXS1 */
    {
	/* APXS1 only supports IPv4 */
	struct in_addr sinaddr;
	char addr[sizeof("255.255.255.255")], *slash;
	int length;
	const char *mask;
	const char const default_mask[] = "32";

	slash = strchr(value, '/');

	if (slash) { /* Netmask (probably) supplied */
	    length = slash - value;
	    
	    mask = slash + 1;
	    if (!*mask) {
		LOG_RERROR(APLOG_WARNING, 0, r,
			"Coercing empty netmask to the default (%s)",
			default_mask);
		mask = default_mask;
	    }
	} else { /* No netmask specified */
	    mask = default_mask;
	    length = strlen(value);
	}

	if (length > sizeof(addr) - 1) {
	    LOG_RERROR(APLOG_ERR, 0, r,
		    "Invalid address (%.*s): too long",
		    length, value);
	    return ERROR;
	}

	memcpy(addr, value, length);
	addr[length] = '\0';

	if (inet_aton(addr, &sinaddr) == 0) {
	    LOG_RERROR(APLOG_ERR, 0, r, "Invalid address: %s", addr);
	    return ERROR;
	}

	if (strchr(mask, '.')) { /* Mask looks like a dotted quad */
	    struct in_addr sin_mask;

	    if (inet_aton(mask, &sin_mask) == 0) {
		LOG_RERROR(APLOG_ERR, 0, r,
			"Invalid netmask address: %s", addr);
		return ERROR;
	    }

	    if ((sinaddr.s_addr & sin_mask.s_addr) ==
		    (closure->sockaddr.sin_addr.s_addr & sin_mask.s_addr))
		closure->match_found = 1;
	    else
		closure->match_found = 0;
	} else { /* Mask looks like a bit count */
	    unsigned long int mask_bits;
	    char *endptr;
	    uint32_t netmask;

	    mask_bits = strtol(mask, &endptr, 10);
	    if (*endptr != '\0' || mask_bits > 32 || mask_bits < 0) {
		LOG_RERROR(APLOG_ERR, 0, r,
			"Invalid netmask /%s: must be in the range 0 to 32",
			mask);
		return ERROR;
	    }

	    netmask = 0xFFFFFFFFul << (32 - mask_bits);

	    if ((ntohl(closure->sockaddr.sin_addr.s_addr) & netmask) ==
			(ntohl(sinaddr.s_addr) & netmask))
		closure->match_found = 1;
	}
	return !closure->match_found;
    }
#endif /* APXS1 */
}

/**
 * Determines whether the client should be allowed to do Negotiate auth.
 * @return non-zero if so, zero if not.
 */
static int
is_negotiate_enabled_for_client(request_rec *r)
{
    auth_vas_dir_config *dc;
    struct ip_cmp_closure closure;

    ASSERT(r != NULL);

    dc = GET_DIR_CONFIG(r->per_dir_config);

    if (!USING_AUTH_NEGOTIATE(dc))
	return 0;

    if (dc->negotiate_subnets == NULL) /* All subnets */
	return 1;

#if !defined(APXS1)
    {
	apr_status_t err;

	err = apr_sockaddr_info_get(&closure.sockaddr_p, r->connection->remote_ip, APR_UNSPEC, 0, 0, r->pool);
	if (err != APR_SUCCESS) {
	    LOG_RERROR(APLOG_ERR, err, r,
		    "%s: Error turning %s into a sockaddr struct",
		    __func__, r->connection->remote_ip);
	    return 0;
	}
    }
#else /* APXS1 */
    if (inet_aton(r->connection->remote_ip, &closure.sockaddr.sin_addr) == 0) {
	LOG_RERROR(APLOG_ERR, 0, r,
		"%s: Error turning remote IP %s into a struct sin_addr_t",
		__func__, r->connection->remote_ip);
	return 0;
    }
#endif /* APXS1 */

    closure.request = r;

    apr_table_do(mav_ip_subnet_cmp, &closure, dc->negotiate_subnets, NULL);
    return closure.match_found;
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

    if (is_negotiate_enabled_for_client(r))
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
    TRACE_R(r, "%s: auth_type=%s", __func__, type);

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
	      "%s: no VAS context", __func__);
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
    if (strcasecmp(auth_type, "Negotiate") == 0 && is_negotiate_enabled_for_client(r))
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
	     ASSERT(RAUTHTYPE(r) != NULL);
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
    auth_vas_dir_config *dc;

    if (!is_our_auth_type(r) || RUSER(r) == NULL)
	return NULL;

    dc = GET_DIR_CONFIG(r->per_dir_config);
    if (!USING_SUEXEC(dc))
	return NULL;

    if ((id = apr_palloc(r->pool, sizeof (ap_unix_identity_t))) == NULL)
	return NULL;

    /* This will hit vas_nss where Kerberos principals are understood */
    if (apr_uid_get(&id->uid, &id->gid, RUSER(r), r->pool) != APR_SUCCESS)
	return NULL;

    TRACE_R(r, "%s: RUSER=%s uid=%d gid=%d", __func__, RUSER(r),
	    (int)id->uid, (int)id->gid);

    id->userdir = 0;

    return id;
}
#endif /* HAVE_UNIX_SUEXEC */

/**
 * Exports delegated credentials into a file, and sets the subprocess
 * environment KRB5CCNAME to point to the file. The file gets removed
 * by rnote_fini() during request cleanup.
 *
 * This function performs no action if already exported, export 
 * delegation is disabled, or if the GSS credential is unavailable.
 */
static void
export_cc(request_rec *r)
{
    OM_uint32 major, minor;
    auth_vas_rnote *rn;
    const auth_vas_dir_config *dc;
    auth_vas_server_config *sc;
    vas_err_t vaserr;
    krb5_context krb5ctx;
    krb5_ccache ccache;
    krb5_error_code krb5err;
    char *path;

    rn = GET_RNOTE(r);

    /* Check that an authentication was performed */
    if (rn == NULL)
        return;

    /* Check if we delegated already */
    if (rn->deleg_ccache)
	return;

    /* Check if a delegated cred is available */
    if (rn->deleg_cred == GSS_C_NO_CREDENTIAL)
	return;

    /* Check if VasAuthExportDelegated is turned on */
    dc = GET_DIR_CONFIG(r->per_dir_config);
    ASSERT(dc != NULL);
    if (!USING_EXPORT_DELEGATED(dc))
	return;

    sc = GET_SERVER_CONFIG(r->server->module_config);
    ASSERT(sc != NULL);
    ASSERT(sc->vas_ctx != NULL);

    if (LOCK_VAS(r) != OK) {
	LOG_RERROR(APLOG_ERR, 0, r,
		   "export_cc: unable to acquire lock to export credentials");
	return;
    }

    /* Pull the credential cache filename out */
    if ((vaserr = vas_krb5_get_context(sc->vas_ctx, &krb5ctx))) {
            LOG_RERROR(APLOG_ERR, 0, r,
                       "vas_krb5_get_context: %s",
                       vas_err_get_string(sc->vas_ctx, 1));
	    goto finish;
    }

    if ((krb5err = krb5_cc_new_unique(krb5ctx, "FILE", NULL, &ccache))) {
            LOG_RERROR(APLOG_ERR, 0, r, "krb5_cc_new_unique: %.100s", 
		    krb5_get_err_text(krb5ctx, krb5err));
	    goto finish;
    }

    if ((major = gss_krb5_copy_ccache(&minor, rn->deleg_cred, ccache))) {
	log_gss_error(APLOG_MARK, APLOG_ERR, 0, r,
		    "gss_krb5_copy_ccache", major, minor);
	(void)krb5_cc_destroy(krb5ctx, ccache);
	goto finish;
    }

    rn->deleg_ccache = ccache;

    /* Allow subprocesses see the cred cache path */
    path = apr_pstrdup(r->pool, krb5_cc_get_name(krb5ctx, ccache));
    TRACE_R(r, "%s: cred cache at %s", __func__, path);
    apr_table_setn(r->subprocess_env, "KRB5CCNAME", path);

    /* XXX for SUEXEC the file would have to be chowned */

finish:
    UNLOCK_VAS(r);
}

static struct ldap_lookup_map {
    const char *const ldap_attr;
    vas_err_t (*vas_func)(vas_ctx_t *ctx, vas_id_t *serverid, vas_user_t *user, char **result);
} quick_ldap_lookups[] = {
    { "sAMAccountName",		vas_user_get_sam_account_name },
    { "distinguishedName",	vas_user_get_dn },
    { "objectSid",		vas_user_get_sid },
    { NULL, NULL }
};

/**
 * Set the remote username (REMOTE_USER variable) to the chosen attribute.
 * Only call this if the remote_user_attr is not NULL.
 */
static void
set_remote_user_attr(request_rec *r, const char *attr)
{
    const char *old_ruser = RUSER(r);
    auth_vas_server_config *sc;
    const char *const anames[2] = { attr, NULL };
    vas_attrs_t *attrs;
    auth_vas_rnote *rn;

    ASSERT(r != NULL);

    /* Depends on the remote_user_map_methods having the right info */
    ASSERT(attr != NULL);
    ASSERT(attr[0]);

    if (strcasecmp(attr, "userPrincipalName") == 0) {
	LOG_RERROR(APLOG_DEBUG, 0, r,
		"%s: Returning early because REMOTE_USER is already the UPN",
		__func__);
	return;
    }

    /* RUSER might already be set - particularly on Apache 1 where it is
     * per-connection not per-request */
    /* XXX: It might have to be changed to a different attr */
    if(strchr(RUSER(r), '@') == NULL) {
	LOG_RERROR(APLOG_DEBUG, 0, r,
		"%s: REMOTE_USER appears to already have been set to %s",
		__func__, RUSER(r));
	return;
    }

    sc = GET_SERVER_CONFIG(r->server->module_config);
    ASSERT(sc != NULL);

    if (LOCK_VAS(r)) {
	LOG_RERROR(APLOG_ERR, 0, r, "Failed to lock VAS");
	return;
    }

    rn = GET_RNOTE(r);

    if (set_user_obj(r))
	return;

    /* Look for attributes that are likely to be in the vas cache */
    {
	struct ldap_lookup_map *map;

	for (map = quick_ldap_lookups; map->ldap_attr; ++map) {
	    ASSERT(map->vas_func != NULL);
	    if (strcasecmp(map->ldap_attr, attr) == 0) {
		char *attrval;

		LOG_RERROR(APLOG_DEBUG, 0, r,
			"%s: Using vas cache for lookup of %s attribute",
			__func__, attr);

		if (map->vas_func(sc->vas_ctx, sc->vas_serverid,
			    rn->vas_user_obj, &attrval) == VAS_ERR_SUCCESS)
		{ /* success */
		    RUSER(r) = apr_pstrdup(RUSER_POOL(r), attrval);
		    free(attrval);
		} else { /* VAS error */
		    LOG_RERROR(APLOG_ERR, 0, r,
			    "Error looking up %s attribute in vas cache: %s",
			    attr, vas_err_get_string(sc->vas_ctx, 1));
		}
		goto finish;
	    }
	}

	/* uidNumber and gidNumber are special cases because libvas provides a
	 * struct passwd not a char* */
	if (strcasecmp("uidNumber", attr) == 0 || strcasecmp("gidNumber", attr) == 0) {
	    const char ug = *attr; /* u or g */
	    struct passwd *pw;

	    LOG_RERROR(APLOG_DEBUG, 0, r,
		    "%s: Using vas cache for lookup of %cidNumber attribute",
		    __func__, ug);
	    if (vas_user_get_pwinfo(sc->vas_ctx, sc->vas_serverid,
			rn->vas_user_obj, &pw) == VAS_ERR_SUCCESS)
	    { /* success */
		RUSER(r) = apr_psprintf(RUSER_POOL(r), "%u",
			ug == 'u' ? pw->pw_uid : pw->pw_gid);
		free(pw);
	    } else { /* VAS error (or user is not Unix-enabled) */
		LOG_RERROR(APLOG_ERR, 0, r,
			"Error looking up %cidNumber attribute in vas cache: %s",
			ug, vas_err_get_string(sc->vas_ctx, 1));
	    }
	    goto finish;
	}
    }

    LOG_RERROR(APLOG_DEBUG, 0, r,
	    "%s: VAS cache lookup unavailable for %s, doing LDAP query",
	    __func__, attr);

    if (vas_user_get_attrs(sc->vas_ctx, sc->vas_serverid, rn->vas_user_obj,
		anames, &attrs) == VAS_ERR_SUCCESS) {
	char **strvals;
	int count;
	vas_err_t vaserr;

	vaserr = vas_vals_get_string(sc->vas_ctx, attrs, attr, &strvals,
		&count);
	if (vaserr == VAS_ERR_SUCCESS || vaserr == VAS_ERR_MORE_VALS) {
	    ASSERT(count > 0);
	    ASSERT(strvals);
	    ASSERT(strvals[0]);

	    RUSER(r) = apr_pstrdup(RUSER_POOL(r), strvals[0]);

	    (void) vas_vals_free_string(sc->vas_ctx, strvals, count);
	} else {
	    LOG_RERROR(APLOG_ERR, 0, r,
		    "Failed getting %s attribute values: %s",
		    attr, vas_err_get_string(sc->vas_ctx, 1));
	}

	vas_attrs_free(sc->vas_ctx, attrs);
    }
    else {
	LOG_RERROR(APLOG_ERR, 0, r,
		"vas_user_get_attrs() failed to get attribute %s: %s",
		attr, vas_err_get_string(sc->vas_ctx, 1));
    }

finish:
    UNLOCK_VAS(r);

    LOG_RERROR(APLOG_INFO, 0, r,
	    "Remote user set from %.100s to %.100s (attribute %s)",
	    old_ruser, RUSER(r), attr);
}


/**
 * Convert the authenticated user name into a local username.
 */
static void
localize_remote_user(request_rec *r, const char *unused)
{
#ifdef APR_HAS_USER
    apr_status_t aprst;
    apr_uid_t uid, gid;
    char *username;

    ASSERT(r != NULL);
    TRACE_R(r, __func__);

    /* Convert the UPN into a UID, then convert the UID back again */

    if ((aprst = apr_uid_get(&uid, &gid, RUSER(r), r->pool) != OK)) {
	/* User is probably not Unix-enabled. Try stripping the realm anyway
	 * for consistency */

	LOG_RERROR(APLOG_DEBUG, aprst, r,
		"apr_uid_get failed for %s (normal for non-Unix users), "
		"using strcmp method",
		RUSER(r));

	localize_remote_user_strcmp(r);
	return;
    }

    /* Unix-enabled user, convert back to their name */
    if ((aprst = apr_uid_name_get(&username, uid, RUSER_POOL(r))) != OK) {
	LOG_RERROR(APLOG_ERR, aprst, r, "apr_uid_name_get failed for uid %d", uid);
	return;
    }

    /* Set the authorized username to the localized name.
     * username was allocated out of the right pool. */
    RUSER(r) = username;
    return;

#else /* !APR_HAS_USER */
    localize_remote_user_strcmp(r);
    return;
#endif /* !APR_HAS_USER */
}

/**
 * Strips "@DEFAULT-REALM" from the end of RUSER(r) if it is there.
 * If the realm does not match, it is not stripped.
 */
static void
localize_remote_user_strcmp(request_rec *r)
{
    const auth_vas_server_config *sc;
    char *at, *user_realm;

    ASSERT(r != NULL);
    TRACE_R(r, __func__);

    at = strchr(RUSER(r), '@');
    if (!at)
	return; /* Not a UPN */

    user_realm = at + 1;

    ASSERT(r->server != NULL);
    sc = GET_SERVER_CONFIG(r->server->module_config);

    ASSERT(sc->default_realm != NULL);
    if (strcasecmp(user_realm, sc->default_realm) == 0) {
	LOG_RERROR(APLOG_DEBUG, 0, r, "stripping matching realm from "
		"user %s", RUSER(r));
	*at = '\0'; /* Trimming RUSER(r) directly */
    }
}

/**
 * Process the AuthVasUseNegotiate option which may be "On" (default),
 * "Off", or a list of subnets to suggest negotiate auth to.
 * @return NULL on success or an error message.
 */
static const char *
set_negotiate_conf(cmd_parms *cmd, void *struct_ptr, const char *args)
{
    auth_vas_dir_config *dc = (auth_vas_dir_config*)struct_ptr;
    char *opt;

    opt = ap_getword_white(cmd->pool, &args);
    if (!*opt)
	return "Insufficient parameters for " CMD_USENEGOTIATE;

    if (strcasecmp(opt, "On") == 0) {
	dc->auth_negotiate = FLAG_ON;
	/* dc->negotiate_subnets left as NULL indicating all subnets */
	return NULL;
    }

    if (strcasecmp(opt, "Off") == 0) {
	dc->auth_negotiate = FLAG_OFF;
	/* dc->negotiate_subnets unused (remains NULL) */
	return NULL;
    }

    dc->auth_negotiate = FLAG_ON;
    dc->negotiate_subnets = apr_table_make(cmd->pool, 2);

    do {
	apr_table_add(dc->negotiate_subnets, "", opt);
    } while (*(opt = ap_getword_white(cmd->pool, &args)));

    return NULL;
}

static struct {
    const char *name;
    void (*method)(request_rec *r, const char *line);
    /** Human-readable name of the kind of argument expected by this method.
     * NULL means no argument expected. */
    const char *require_arg_type;
} remote_user_map_methods[] = {
    { "ldap-attr", set_remote_user_attr, "LDAP attribute" },
    { "local", localize_remote_user, NULL },
    { "default", NULL, NULL }
};

static const size_t num_remote_user_map_methods =
	sizeof(remote_user_map_methods) / sizeof(remote_user_map_methods[0]);

/**
 * Processes the RemoteUserMap option, ensuring that required arguments are
 * provided.
 * \return \c NULL on success or an error message.
 */
static const char *
set_remote_user_map_conf(cmd_parms *cmd, void *struct_ptr, const char *args)
{
    auth_vas_server_config *sc;
    auth_vas_dir_config *dc = (auth_vas_dir_config*)struct_ptr;
    char *optval1, *optval2;
    int i;

    sc = GET_SERVER_CONFIG(cmd->server->module_config);
    ASSERT(sc != NULL);

    optval1 = ap_getword_white(cmd->pool, &args);

    if (!optval1)
	return CMD_REMOTEUSERMAP" option requires at least one argument";

    optval2 = ap_getword_white(cmd->pool, &args);

    ASSERT(dc != NULL);

    dc->remote_user_map = optval1;
    dc->remote_user_map_args = optval2;

    for (i = 0; i < num_remote_user_map_methods; ++i) {
	if (strcasecmp(optval1, remote_user_map_methods[i].name) == 0) {
	    if (remote_user_map_methods[i].require_arg_type && !optval2)
		return apr_psprintf(cmd->pool,
			CMD_REMOTEUSERMAP" %s requires an argument of type %s",
			optval1, remote_user_map_methods[i].require_arg_type);
	    return NULL; /* Option is valid. */
	}
    }

    return apr_psprintf(cmd->pool,
	    "Unrecognised parameter to "CMD_REMOTEUSERMAP": %s", optval1);
}

/**
 * Sets RUSER(r) according to the remote_user_map configuration.
 */
static void
set_remote_user(request_rec *r)
{
    auth_vas_dir_config *dc;
    const char *method_name, *args;
    int i;

    dc = GET_DIR_CONFIG(r->per_dir_config);
    ASSERT(dc != NULL);

    if (dc->remote_user_map == NULL)
	dc->remote_user_map = "default";

    method_name = dc->remote_user_map;
    args = dc->remote_user_map_args;

    for (i = 0; i < num_remote_user_map_methods; ++i) {
	if (strcasecmp(method_name, remote_user_map_methods[i].name) == 0) {
	    if (remote_user_map_methods[i].method)
		(*remote_user_map_methods[i].method)(r, args);
	    return;
	}
    }
    /* XXX: This should already have been detected and flagged as an error */
    LOG_RERROR(APLOG_ERR, 0, r, "Unknown " CMD_REMOTEUSERMAP " \"%s\"", method_name);
}

/**
 * Fix up environment for any delegated credentials.
 */
static int
auth_vas_fixup(request_rec *r)
{
    const auth_vas_dir_config *dc;

    if (!is_our_auth_type(r))
	return DECLINED;

    dc = GET_DIR_CONFIG(r->per_dir_config);
    ASSERT(dc != NULL);

    TRACE_R(r, "auth_vas_fixup");
    export_cc(r);

    set_remote_user(r);

    return OK;
}

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
    TRACE_P(p, __func__);
    if (dc != NULL) {
	dc->auth_negotiate = FLAG_UNSET;
	dc->negotiate_subnets = NULL;
	dc->auth_basic = FLAG_UNSET;
	dc->auth_authoritative = FLAG_UNSET;
	dc->export_delegated = FLAG_UNSET;
	dc->localize_remote_user = FLAG_UNSET;
	dc->remote_user_map = "default";
	dc->remote_user_map_args = NULL;
	dc->use_suexec = FLAG_UNSET;
	dc->ntlm_error_document = NULL;
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
    TRACE_P(p, __func__);
    if (merged_dc != NULL) {
	merged_dc->auth_negotiate = FLAG_MERGE(base_dc->auth_negotiate,
		new_dc->auth_negotiate);
	merged_dc->auth_basic = FLAG_MERGE(base_dc->auth_basic,
		new_dc->auth_basic);
	merged_dc->auth_authoritative = FLAG_MERGE(base_dc->auth_authoritative,
		new_dc->auth_authoritative);
	merged_dc->export_delegated = FLAG_MERGE(base_dc->export_delegated,
		new_dc->export_delegated);
	merged_dc->use_suexec = FLAG_MERGE(base_dc->use_suexec,
		new_dc->use_suexec);

	if (new_dc->auth_negotiate == FLAG_UNSET)
	    merged_dc->negotiate_subnets = base_dc->negotiate_subnets;
	else /* Flag set */
	    merged_dc->negotiate_subnets = new_dc->negotiate_subnets;

	/*
	 * Handle deprecated AuthVasLocalizeRemoteUser
	 *  AuthVasLocalizeRemoteUser on  -> AuthVasRemoteUserMap local
	 *  AuthVasLocalizeRemoteUser off -> AuthVasRemoteUserMap default
	 */
	if (strcasecmp(new_dc->remote_user_map, "default") != 0) {
	    if (new_dc->localize_remote_user != FLAG_UNSET)
		LOG_P_ERROR(APLOG_NOTICE, 0, p,
			"Ignoring " CMD_LOCALIZEREMOTEUSER " option "
			"because " CMD_REMOTEUSERMAP " is set");

	    merged_dc->remote_user_map = apr_pstrdup(p,
		    new_dc->remote_user_map);
	    merged_dc->remote_user_map_args = apr_pstrdup(p,
		    new_dc->remote_user_map_args);
	} else if (new_dc->localize_remote_user == FLAG_ON) {
	    merged_dc->remote_user_map = "local";
	    merged_dc->remote_user_map_args = NULL;
	} else if (new_dc->localize_remote_user == FLAG_OFF &&
		strcasecmp(base_dc->remote_user_map, "local") == 0) {
	    /* Localize is explicitly off but the parent's was explicitly on */
	    merged_dc->remote_user_map = "default";
	    merged_dc->remote_user_map_args = NULL;
	} else {
	    merged_dc->remote_user_map = apr_pstrdup(p,
		    base_dc->remote_user_map);
	    merged_dc->remote_user_map_args = apr_pstrdup(p,
		    base_dc->remote_user_map_args);
	}

	if (new_dc->ntlm_error_document) {
	    if (strcasecmp(new_dc->ntlm_error_document, "default") == 0)
		merged_dc->ntlm_error_document = NULL;
	    else
		merged_dc->ntlm_error_document = apr_pstrdup(p,
			new_dc->ntlm_error_document);
	}
    }
    return (void *)merged_dc;
}

/** Passed an auth_vas_server_config pointer */
static CLEANUP_RET_TYPE
auth_vas_server_config_destroy(void *data)
{
    auth_vas_server_config *sc = (auth_vas_server_config *)data;
    
    if (sc != NULL) {

	if (sc->cache) {
	    auth_vas_cache_flush(sc->cache);
	    sc->cache = NULL;
	}
        
	/* sc->default_realm is always handled by apache */

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
	sc->server_principal = DEFAULT_SERVER_PRINCIPAL;
    }
    
    /* register our server config cleanup function */
    apr_pool_cleanup_register(p, sc, auth_vas_server_config_destroy,
	    apr_pool_cleanup_null);
    
    TRACE_P(p, "%s (%s:%u)", __func__,
	    s->server_hostname ? s->server_hostname : "<global>", s->port);
    return (void *)sc;
}

#if !defined(APXS1) /* Unused on APXS1 */
/*
 * Logs version information about this module.
 */
static void
auth_vas_print_version(apr_pool_t *plog)
{
    LOG_P_ERROR(APLOG_INFO, 0, plog, "mod_auth_vas version %s, VAS %s",
	    MODAUTHVAS_VERSION, vas_product_version(0, 0, 0));
}
#endif

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
    auth_vas_print_version(p);

    ap_hook_post_config(auth_vas_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(auth_vas_child_init, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_auth_checker(auth_vas_auth_checker, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_check_user_id(auth_vas_check_user_id, NULL, NULL, APR_HOOK_MIDDLE);

#if HAVE_UNIX_SUEXEC
    ap_hook_get_suexec_identity(auth_vas_suexec, NULL, NULL, APR_HOOK_FIRST);
#endif
    ap_hook_fixups(auth_vas_fixup, NULL, NULL, APR_HOOK_MIDDLE);

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
    auth_vas_fixup,			/* fixer_upper */
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

/* vim: ts=8 sw=4 noet tw=80
 */
