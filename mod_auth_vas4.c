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
 */

/*
 *  MODAUTHVAS_VERBOSE	- define this to get verbose debug level logging
 *  MODAUTHVAS_DIAGNOSTIC - define this to enable assertions
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

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

#include "log.h"

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

#if HAVE_MOD_AUTH_H
# include <mod_auth.h>
#endif

#if HAVE_AP_PROVIDER_H
# include <ap_provider.h>
#endif

/*
 * Per-server configuration structure - exists for lifetime of server process.
 */
typedef struct {
    vas_ctx_t       *vas_ctx;               /* The global VAS context - needs locking */
    vas_id_t        *vas_serverid;          /* The server identity */
    apr_time_t      creds_established_at;   /* The last time vas_id_establish_cred_keytab() was called. */
    auth_vas_cache  *cache;                 /* See cache.h */
    const char      *server_principal;      /* AuthVasServerPrincipal or NULL */
    char            *default_realm;         /* AuthVasDefaultRealm (never NULL) */
    char            *cache_size;            /* Configured cache size */
    char            *cache_time;            /* Configured cache lifetime */
    char            *keytab_filename;       /* AuthVasKeytabFile */
} auth_vas_server_config;

/*
 * Per-directory configuration data - computed while traversing htaccess.
 * The int types should only be accessed using the USING_*() macros defined
 * below. This is because they might be uninitialised.
 */
typedef struct {
    int                 auth_negotiate;			/**< AuthVasUseNegotiate (default on) */
    apr_table_t         *negotiate_subnets;     /**< AuthVasUseNegotiate (list of subnets, or NULL for all) */
    int                 auth_basic;			    /**< AuthVasUseBasic (default off) */
    int                 auth_authoritative;		/**< AuthVasAuthoritative (default on) */
    int                 export_delegated;		/**< AuthVasExportDelegated (default off) */
    int                 authz;				    /**< AuthVasAuthz (default on) */
    char                *remote_user_map;		/**< AuthVasRemoteUserMap (NULL if unset) */
    char                *remote_user_map_args;	/**< Argument to AuthVasRemoteUserMap (NULL if none) */
    int                 use_suexec;			    /**< AuthVasSuexecAsRemoteUser (default off) */
    char                *ntlm_error_document;	/**< AuthVasNTLMErrorDocument (default built-in) */
    authn_provider_list *auth_providers;        /**< AuthVasProvider (default vas) */
    char                *dir;
} auth_vas_dir_config;

/* Default behaviour if a flag is not set */
#define DEFAULT_USING_AUTH_NEGOTIATE            FLAG_ON
#define DEFAULT_USING_AUTH_BASIC                FLAG_OFF
#define DEFAULT_USING_AUTH_AUTHORITATIVE        FLAG_ON
#define DEFAULT_USING_EXPORT_DELEGATED          FLAG_OFF
#define DEFAULT_USING_SUEXEC                    FLAG_OFF
#define DEFAULT_USING_AUTHZ                     FLAG_ON

/* Returns the field flag, or def if dc is NULL or dc->field is FLAG_UNSET */
#define USING_AUTH_DEFAULT(dc, field, def) \
		((dc) ? TEST_FLAG_DEFAULT((dc)->field, def) : def)

/* Macros to safely test the per-directory flags, applying defaults. */
#define USING_AUTH_BASIC(dc) USING_AUTH_DEFAULT(dc, auth_basic, DEFAULT_USING_AUTH_BASIC)
#define USING_AUTH_AUTHORITATIVE(dc) USING_AUTH_DEFAULT(dc, auth_authoritative, DEFAULT_USING_AUTH_AUTHORITATIVE)
#define USING_EXPORT_DELEGATED(dc) USING_AUTH_DEFAULT(dc, export_delegated,   DEFAULT_USING_EXPORT_DELEGATED)
#define USING_SUEXEC(dc) USING_AUTH_DEFAULT(dc, use_suexec, DEFAULT_USING_SUEXEC)
/** Indicates that Negotiate auth is enabled for _some_ hosts, not
 * necessarily all. Use is_negotiate_enabled_for_client() to check the current
 * client. */
#define USING_AUTH_NEGOTIATE(dc) USING_AUTH_DEFAULT(dc, auth_negotiate, DEFAULT_USING_AUTH_NEGOTIATE)
#define USING_MAV_AUTHZ(dc) USING_AUTH_DEFAULT(dc, authz, DEFAULT_USING_AUTHZ)
    
/*
 * Miscellaneous constants.
 */
#define VAS_AUTH_TYPE               "VAS4"
#define DEFAULT_AUTHN_PROVIDER      "vas4"
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
    auth_vas_user *mav_user;		/* User information (shared) */
    vas_user_t *vas_user_obj;		/* The remote user object (lazy initialisation - possibly NULL) */
    gss_ctx_id_t gss_ctx;		/* Negotiation context */
    gss_buffer_desc client;		/* Exported mech name */
    gss_cred_id_t deleg_cred;		/* Delegated credential */
    krb5_ccache deleg_ccache;		/* Exported cred cache */
} auth_vas_rnote;

/* Forward declaration for module structure: see bottom of this file. */
module AP_MODULE_DECLARE_DATA auth_vas4_module;

/* Prototypes */
static const char *server_set_string_slot(cmd_parms *cmd, void *ignored, const char *arg);
static const char *set_remote_user_map_conf(cmd_parms *cmd, void *struct_ptr, const char *args);
static const char *set_negotiate_conf(cmd_parms *cmd, void *struct_ptr, const char *args);
static int server_ctx_is_valid(server_rec *s);
static int dn_in_container(const char *dn, const char *container);
static int is_our_auth_type(const request_rec *r);
static void log_gss_error(const char *file, int line, int module_index, int level, apr_status_t result, request_rec *r, const char *pfx, OM_uint32 gsserr, OM_uint32 gsserr_minor);
static void rnote_init(auth_vas_rnote *rn);
static void rnote_fini(request_rec *r, auth_vas_rnote *rn);
static apr_status_t auth_vas_cleanup_request(void *data);
static int rnote_get(auth_vas_server_config *sc, request_rec *r, auth_vas_rnote **rn_ptr);
static int do_gss_spnego_accept(request_rec *r, const char *auth_line);
static void auth_vas_server_init(apr_pool_t *p, server_rec *s);
static void add_basic_auth_headers(request_rec *r);
static void add_auth_headers(request_rec *r);
#if HAVE_UNIX_SUEXEC
  static ap_unix_identity_t *auth_vas_suexec(const request_rec *r);
#endif
static void export_cc(request_rec *r);
static int auth_vas_fixup(request_rec *r);
static void *auth_vas_create_dir_config(apr_pool_t *p, char *dirspec);
static void *auth_vas_merge_dir_config(apr_pool_t *p, void *base_conf, void *new_conf);
static apr_status_t auth_vas_server_config_destroy(void *data);
static void *auth_vas_create_server_config(apr_pool_t *p, server_rec *s);
static int auth_vas_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s);
static void auth_vas_child_init(apr_pool_t *p, server_rec *s);
static void auth_vas_register_hooks(apr_pool_t *p);
static void set_remote_user(request_rec *r);
static void set_remote_user_attr(request_rec *r, const char *line);
static void localize_remote_user(request_rec *r, const char *line);
static void localize_remote_user_strcmp(request_rec *r);
static int initialize_user(request_rec *request, const char *username);
static authn_status authn_vas_check_password(request_rec *r, const char *user, const char *password);
static int get_server_creds(server_rec *s);
static const char *add_authn_provider(cmd_parms *cmd, void *config, const char *arg);

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
	    MAV_LOG_RERRNO(APLOG_ERR, r, error, "apr_thread_mutex_lock");
	return error;
} /* auth_vas_lock */

static void auth_vas_unlock(request_rec *r) {
   	apr_status_t error;

	ASSERT(auth_vas_libvas_mutex != NULL);
	error = apr_thread_mutex_unlock(auth_vas_libvas_mutex);
	if (error)
	    MAV_LOG_RERRNO(APLOG_WARNING, r, error, "apr_thread_mutex_unlock");
} /* auth_vas_unlock */
#else
# define LOCK_VAS(r)   apr_thread_mutex_lock(auth_vas_libvas_mutex)
# define UNLOCK_VAS(r) (void)apr_thread_mutex_unlock(auth_vas_libvas_mutex)
#endif

/* Sets a string slot in the server config */
static const char *
server_set_string_slot(cmd_parms *cmd, void *ignored, const char *arg)
{
	return ap_set_string_slot(cmd, 
	    (char *)GET_SERVER_CONFIG(cmd->server->module_config), 
	    (char *)arg);
}

/*
 * Configuration commands table for this module.
 */
#define CMD_USENEGOTIATE        "AuthVasUseNegotiate"
#define CMD_USEBASIC            "AuthVasUseBasic"
#define CMD_AUTHORITATIVE       "AuthVasAuthoritative"
#define CMD_EXPORTDELEG         "AuthVasExportDelegated"
#define CMD_LOCALIZEREMOTEUSER  "AuthVasLocalizeRemoteUser" /**< Deprecated */
#define CMD_REMOTEUSERMAP       "AuthVasRemoteUserMap"
#define CMD_SPN                 "AuthVasServerPrincipal"
#define CMD_REALM               "AuthVasDefaultRealm"
#define CMD_USESUEXEC           "AuthVasSuexecAsRemoteUser"
#define CMD_NTLMERRORDOCUMENT   "AuthVasNTLMErrorDocument"
#define CMD_CACHESIZE           "AuthVasCacheSize"
#define CMD_CACHEEXPIRE         "AuthVasCacheExpire"
#define CMD_KEYTABFILE          "AuthVasKeytabFile"
#define CMD_AUTHZ               "AuthVasAuthz"
#define CMD_VASPROVIDERS        "AuthVasProvider"

static const command_rec auth_vas_cmds[] =
{
    AP_INIT_RAW_ARGS(CMD_USENEGOTIATE, set_negotiate_conf,
		(void*)APR_OFFSETOF(auth_vas_dir_config, negotiate_subnets),
		ACCESS_CONF | OR_AUTHCFG,
		"Kerberos SPNEGO authentication using Active Directory (On, Off or list of subnets)"),
    AP_INIT_FLAG(CMD_USEBASIC, ap_set_flag_slot,
		(void*)APR_OFFSETOF(auth_vas_dir_config, auth_basic),
		ACCESS_CONF | OR_AUTHCFG,
		"Basic Authentication using Active Directory"),
    AP_INIT_FLAG(CMD_AUTHORITATIVE, ap_set_flag_slot,
		(void*)APR_OFFSETOF(auth_vas_dir_config, auth_authoritative),
		ACCESS_CONF | OR_AUTHCFG,
		"Authenticate authoritatively ('Off' allows fall-through to other authentication modules)"),
    AP_INIT_FLAG(CMD_EXPORTDELEG, ap_set_flag_slot,
        (void*)APR_OFFSETOF(auth_vas_dir_config, export_delegated),
		ACCESS_CONF | OR_AUTHCFG,
		"Write delegated credentials to a file, setting KRB5CCNAME"),
    AP_INIT_FLAG(CMD_USESUEXEC, ap_set_flag_slot,
		(void*)APR_OFFSETOF(auth_vas_dir_config, use_suexec),
		ACCESS_CONF | OR_AUTHCFG,
		"Execute CGI scripts as the authenticated remote user (if suEXEC is active)"),
    AP_INIT_RAW_ARGS(CMD_REMOTEUSERMAP, set_remote_user_map_conf,
		(void*)APR_OFFSETOF(auth_vas_dir_config, remote_user_map),
		ACCESS_CONF | OR_AUTHCFG,
		"How to map the remote user identity to the REMOTE_USER environment variable"),
    AP_INIT_TAKE1(CMD_NTLMERRORDOCUMENT, ap_set_string_slot,
		(void*)APR_OFFSETOF(auth_vas_dir_config, ntlm_error_document),
		ACCESS_CONF | OR_AUTHCFG,
		"Error page or string to provide when a client attempts unsupported NTLM authentication"),
    AP_INIT_TAKE1(CMD_SPN, server_set_string_slot,
		(void*)APR_OFFSETOF(auth_vas_server_config, server_principal),
		RSRC_CONF,
		"User Principal Name (LDAP userPrincipalName) for the server"),
    AP_INIT_TAKE1(CMD_REALM, server_set_string_slot,
        (void*)APR_OFFSETOF(auth_vas_server_config, default_realm),
        RSRC_CONF,
        "Default realm for authorization"),
    AP_INIT_TAKE1(CMD_CACHESIZE, server_set_string_slot,
		(void*)APR_OFFSETOF(auth_vas_server_config, cache_size),
		RSRC_CONF,
		"Cache size (number of objects)"),
    AP_INIT_TAKE1(CMD_CACHEEXPIRE, server_set_string_slot,
		(void*)APR_OFFSETOF(auth_vas_server_config, cache_time),
		RSRC_CONF,
		"Cache object lifetime (expiry)"),
    AP_INIT_TAKE1(CMD_KEYTABFILE, server_set_string_slot,
		(void*)APR_OFFSETOF(auth_vas_server_config, keytab_filename),
		RSRC_CONF,
		"Keytab file to use for authentication"),
    AP_INIT_FLAG(CMD_AUTHZ, ap_set_flag_slot,
		(void*)APR_OFFSETOF(auth_vas_dir_config, authz),
		ACCESS_CONF | OR_AUTHCFG,
		"Whether mod_auth_vas4 should provide authorization checks, or decline in favor of other authz modules"),
    AP_INIT_ITERATE(CMD_VASPROVIDERS, add_authn_provider,
        (void*)APR_OFFSETOF(auth_vas_dir_config, auth_providers),
        OR_AUTHCFG,
        "specify the auth providers for a directory or location"),
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
	" AP2"
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

/**
 * Checks that the VAS server context and mod_auth_vas cache are initialized
 * and available.
 * Returns true if they are initialized and ready to be used
 * otherwise logs an error and returns false.
 * Callers should not attempt to LOCK or UNLOCK the VAS context if this
 * function returns false.
 *   @param s A server configuration structure.
 */
static int server_ctx_is_valid(server_rec *s)
{
    auth_vas_server_config *sc;

    ASSERT(s != NULL);
    sc = GET_SERVER_CONFIG(s->module_config);
    ASSERT(sc != NULL);
    return (sc->vas_ctx != NULL && sc->cache != NULL);
} /* server_ctx_is_valid */

/**
 * Ensure the vas_user_obj is set.
 * Callers must hold the VAS lock.
 * This function will log an error message if a failure occurs and an error
 * cause is available.
 *
 * @return OK (0) on success, or an HTTP error code (nonzero) on error.
 */
static int set_user_obj(request_rec *r)
{
    auth_vas_server_config *sc = NULL;
    auth_vas_rnote *rn = NULL;

    TRACE8_R(r, "%s: called", __func__);

    ASSERT(r != NULL);

    sc = GET_SERVER_CONFIG(r->server->module_config);
    ASSERT(sc != NULL);
    ASSERT(sc->vas_ctx != NULL);

    rn = GET_RNOTE(r);
    if (!rn) {
        TRACE3_R(r, "%s: HTTP_INTERNAL_SERVER_ERROR: END", __func__);
        TRACE8_R(r, "%s: end", __func__);
    	return HTTP_INTERNAL_SERVER_ERROR;
    }
    
    if (auth_vas_user_get_vas_user_obj(rn->mav_user)) {
        TRACE1_R(r, "%s: vas user object is already set for user %s", __func__, auth_vas_user_get_name(rn->mav_user));
        TRACE8_R(r, "%s: end", __func__);
    	return 0; /* Already set */
    }else {
        ERROR_R(r, "%s: Failed to set user object for %.100s: %s", __func__, RUSER(r), vas_err_get_string(sc->vas_ctx, 1));
        TRACE8_R(r, "%s: end", __func__);
        return HTTP_UNAUTHORIZED;
    }
}

/**
 * Returns a string describing the error errnum, in a thread-safe way and
 * possibly stored in the given buffer.
 *
 * This is the GNU-style strerror_r syntax.
 */
static char *sensible_strerror_r(int errnum, char *buf, size_t buflen) {
#if HAVE_STRERROR_R
# if STRERROR_R_CHAR_P /* GNU-style */

    return strerror_r(errnum, buf, buflen);

# else /* XSI/POSIX-compliant, returns int */

    if (strerror_r(errnum, buf, buflen) == 0)
	return buf;

# endif
#endif

    /* No strerror_r or the XSI version failed */
    apr_cpystrn(buf, "<unknown error>", buflen);
    return buf;
}

/**
 * Checks if the given dn matches "*,container".
 * Assumes the dn and container have been normalised to contain
 * no spaces, escapes or double quotes. Container comparison is
 * performed case-insensitively. Strict inclusion is tested.
 * @return true if dn is in the container
 */
static int dn_in_container(const char *dn, const char *container)
{
    int offset;
   
    offset = strlen(dn) - strlen(container);
    return offset > 0 &&
	   dn[offset - 1] == ',' && 
	   strcasecmp(dn + offset, container) == 0;
} /* dn_in_container */

/**
 * Returns true if the configured authentication type for the
 * request is understood by this module.
 *   @param r The request being authenticated
 *   @return true if the AuthType is "VAS", or the
 *           AuthType is "Basic" and AuthVasUseBasic is on.
 */
static int is_our_auth_type(const request_rec *r)
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
} /* is_our_auth_type */

/**
 * Authenticate a user using a plaintext password.
 *
 * This is the Apache 2.2+ native auth checker.
 *
 *   @param r the request
 *   @param username the user's name
 *   @param password the password to authenticate against
 *   @return AUTH_GRANTED if credentials could be obtained for the user
 *           with the given password to access this HTTP service, or one of the
 *           other AUTH_* values on error.
 */
static authn_status authn_vas_check_password(request_rec *r, const char *username, const char *password)
{
    int                     result = AUTH_GENERAL_ERROR;
    vas_err_t               vaserr;
    auth_vas_server_config *sc = GET_SERVER_CONFIG(r->server->module_config);
    auth_vas_rnote         *rn;
    
    TRACE8_R(r, "%s: called", __func__);
    DEBUG_R(r, "auth_vas authenticate called for user: user='%s'", username);

    if (LOCK_VAS(r)) {
	    ERROR_R(r, "%s: unable to acquire lock", __func__);
        TRACE8_R(r, "%s: end", __func__);
    	return AUTH_GENERAL_ERROR;
    }
    /* Use RETURN() from here on */

    if (rnote_get(sc, r, &rn)) {
        ERROR_R(r, "auth_vas authenticate: unable to request note");
        TRACE8_R(r, "%s: end", __func__);
	    RETURN(AUTH_GENERAL_ERROR);
    }

    if (initialize_user(r, username)) {
        ERROR_R(r, "auth_vas authenticate: unable to initialize user %s", username);
        TRACE8_R(r, "%s: end", __func__);
    	RETURN(AUTH_USER_NOT_FOUND);
    }

    /* Authenticate */
    /* XXX: Clearing the error is a hack to avoid misleading error messages if
     * the error occurs within the auth_vas_cache and not within libvas. */
    vas_err_clear(sc->vas_ctx);

    vaserr = auth_vas_user_authenticate(rn->mav_user, VAS_ID_FLAG_USE_MEMORY_CCACHE, password);
    if (vaserr) {
    	ERROR_R(r, /* This log message mimics mod_auth_basic's */
		"user %s: authentication failure for \"%s\": %s",
		username, r->uri, vas_err_get_string(sc->vas_ctx, 1));
    	RETURN(AUTH_DENIED);
    }

    /* Authenticated */
    /* XXX: Is this necessary? If not, be sure to remove the
     * assumption in set_remote_user that the RUSER is the UPN. */
    //RUSER(r) = apr_pstrdup(RUSER_POOL(r), auth_vas_user_get_principal_name(rn->mav_user));
    RUSER(r) = apr_pstrdup(RUSER_POOL(r), auth_vas_user_get_name(rn->mav_user));

    UNLOCK_VAS(r);
    /* set_remote_user does its own locking if necessary */
    set_remote_user(r);
    DEBUG_R(r, "auth_vas authenticate: Authenticated user is %s", RUSER(r));
    TRACE8_R(r, "%s: end", __func__);
    return AUTH_GRANTED;

finish:
    /* Release resources */
    UNLOCK_VAS(r);
    
    TRACE8_R(r, "%s: end", __func__);
    return result;
} /* authn_vas_check_password */

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
static void log_gss_error(const char *file, int line, int module_index, int level, apr_status_t result,
	      request_rec *r, const char *pfx, OM_uint32 gsserr,
	      OM_uint32 gsserr_minor)
{
    OM_uint32 seq = 0;
    OM_uint32 more, minor_status;

    /* Use the GSSAPI to obtain the error message text */
    do {
    	gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;
	    more = gss_display_status(&minor_status, gsserr, GSS_C_GSS_CODE, GSS_C_NO_OID, &seq, &buf);
    	MAV_LOG_RERRNO(level, r, result, "%s: %.*s", pfx, (int)buf.length, (char*)buf.value);
	    gss_release_buffer(&minor_status, &buf);
    } while (more);

    /* And the mechanism-specific error */
    do {
    	gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;
    	more = gss_display_status(&minor_status, gsserr_minor, GSS_C_MECH_CODE, GSS_C_NO_OID, &seq, &buf);
    	MAV_LOG_RERRNO(level, r, result, "%s: %.*s", pfx, (int)buf.length, (char*)buf.value);
    	gss_release_buffer(&minor_status, &buf);
    } while (more);

} /* log_gss_error */

/** Initialises an new rnote to an empty state. */
static void rnote_init(auth_vas_rnote *rn)
{
    rn->gss_ctx = GSS_C_NO_CONTEXT;
    rn->deleg_cred = GSS_C_NO_CREDENTIAL;
} /* rnote_init */

/** Releases storage associated with the rnote.
 * LOCK_VAS() must have been called prior to calling this.
 */
static void rnote_fini(request_rec *r, auth_vas_rnote *rn)
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
	    log_gss_error(APLOG_MARK, APLOG_ERR, 0, r, "gss_release_cred", gsserr, minor);
    }

    if (rn->gss_ctx != GSS_C_NO_CONTEXT) {
	if (rn->client.value)
	    (void)gss_release_buffer(&minor, &rn->client);
	if ((gsserr = gss_delete_sec_context(&minor, &rn->gss_ctx, NULL)))
	    log_gss_error(APLOG_MARK, APLOG_ERR, 0, r, "gss_delete_sec_context", gsserr, minor);
    }

    if (rn->mav_user)
	auth_vas_user_unref(rn->mav_user);
} /* rnote_fini */

/** This function is called when the request pool is being released.
 * It is passed an auth_vas_rnote pointer we need to cleanup. */
static apr_status_t auth_vas_cleanup_request(void *data)
{
    request_rec *r = (request_rec *)data;
    auth_vas_rnote *rn;

    /* "A cleanup function can safely allocate memory from the pool that is
     * being cleaned up." - APR 1.2 docs. */

    TRACE8_R(r, "%s: called", __func__);
    rn = GET_RNOTE(r);
    if (rn != NULL) {
	if (LOCK_VAS(r))
	    WARN_R(r, "%s: cannot acquire lock to release resources", __func__);
    	rnote_fini(r, rn);
    	UNLOCK_VAS(r);
	    SET_RNOTE(r, NULL);
    }
    TRACE8_R(r, "%s: end", __func__);
    return OK;
} /* auth_vas_cleanup_request */

/**
 * Gets a user object for the given username and stores it in the request note.
 * Both the request_rec and the username must not be NULL.
 *
 * Returns OK (0) on success or an HTTP error code on failure, usually
 * HTTP_UNAUTHORIZED (meaning unauthenticated).
 */
static int initialize_user(request_rec *request, const char *username) {
    vas_err_t result; /* Our return code */
    vas_err_t vaserr; /* Temp storage */
    auth_vas_server_config *sc;
    auth_vas_rnote *rnote;

    TRACE8_R(request, "%s called", __func__);

    /* Empty username is an automatic authentication failure
     * (and it used to trigger a bug in VAS, bug #9473). */
    if (username[0] == '\0')
        RETURN(HTTP_UNAUTHORIZED);

    sc = GET_SERVER_CONFIG(request->server->module_config);
    rnote = GET_RNOTE(request);

    /* This is a soft assertion */
    if (rnote->mav_user != NULL) {
    	ERROR_R(request, "%s: User is already set. Overriding it.", __func__);
	    auth_vas_user_unref(rnote->mav_user);
    	rnote->mav_user = NULL;
    }

    vaserr = auth_vas_user_alloc(sc->cache, username, &rnote->mav_user);
    if (vaserr) {
    	rnote->mav_user = NULL; /* ensure */
	    ERROR_R(request, "%s: Failed to initialize user for %s: %s", __func__, username, vas_err_get_string(sc->vas_ctx, 1));
    	RETURN(HTTP_UNAUTHORIZED);
    }
    
    DEBUG_R(request, "%s: Initialized user %s",__func__, username);
    TRACE4_R(request, "%s: Initialized user principal name is %s", __func__, auth_vas_user_get_principal_name(rnote->mav_user));
    TRACE4_R(request, "%s: Initialized user name is %s", __func__, auth_vas_user_get_name(rnote->mav_user));

    RETURN(OK);

finish:
    TRACE8_R(request, "%s end", __func__);
    return result;
} /* initialize_user */

/**
 * Retrieves the request note for holding VAS information.
 * LOCK_VAS() must have been called prior to calling this.
 * @return 0 on success, or an HTTP error code on failure
 */
static int rnote_get(auth_vas_server_config* sc, request_rec *r, auth_vas_rnote **rn_ptr)
{
    auth_vas_rnote  *rn = NULL;

    TRACE8_R(r, "%s: called", __func__);
    
    rn = GET_RNOTE(r);
    if (rn == NULL) {

        TRACE_R(r, "%s: creating rnote", __func__);
        rn = (auth_vas_rnote *)apr_pcalloc(r->connection->pool, sizeof *rn);

        /* initialize the rnote and set it on the record */
        rnote_init(rn);
        SET_RNOTE(r, rn);

        /* Arrange to release the RNOTE data when the request completes */
        apr_pool_cleanup_register(r->pool, r, auth_vas_cleanup_request,
	       	apr_pool_cleanup_null);
    } else {
        TRACE1_R(r, "%s: reusing existing rnote", __func__);
    }

    /* Success */
    *rn_ptr = rn;
    TRACE8_R(r, "%s: end",__func__);
    return 0;
} /* rnote_get */


/**
 * Performs one acceptance step in the SPNEGO protocol using
 * a BASE64-encoded token in auth_line.
 *   @return OK if SPNEGO has completed and RUSER(r) has been set.
 *		Otherwise returns an error.
 */
static int do_gss_spnego_accept(request_rec *r, const char *auth_line)
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
    
    TRACE8_R(r, "%s: called", __func__);

    ASSERT(auth_line != NULL);

    TRACE1_R(r, "%s: line='%.16s...'", __func__, auth_line);

    /* Get the parameter after "Authorization" */
    auth_param = ap_getword_white(r->pool, &auth_line);
    if (auth_param == NULL) {
        MAV_LOG_R(APLOG_NOTICE, r, "%s: Client sent empty Negotiate auth-data parameter", __func__);
        TRACE8_R(r, "%s: end", __func__);
    	return DECLINED;
    }

    sc = GET_SERVER_CONFIG(r->server->module_config);

    TRACE_R(r, "%s: server keytab: %s", __func__, sc->keytab_filename ? sc->keytab_filename : "using default HTTP.keytab");
    TRACE_R(r, "%s: server principal: %s", __func__, sc->server_principal ? sc->server_principal : "Not Set");

    /* setup the input token */
    in_token.length = strlen(auth_param);
    in_token.value = (void *)auth_param;

    if ((result = LOCK_VAS(r))) {
	    ERROR_R(r, "%s: unable to acquire lock", __func__);
        TRACE8_R(r, "%s: end", __func__);
    	return result;
    }

    /* Store negotiation context in the connection record */
    if ((result = rnote_get(sc, r, &rn))) {
	    UNLOCK_VAS(r);
    	/* no other resources to free */
        TRACE8_R(r, "%s: end", __func__);
	    return result;
    }

    if (VAS_ERR_SUCCESS != vas_gss_initialize(sc->vas_ctx, sc->vas_serverid)) {
	    ERROR_R(r, "Unable to initialize GSS: %s", vas_err_get_string(sc->vas_ctx, 1));
    	UNLOCK_VAS(r);
        TRACE8_R(r, "%s: end", __func__);
    	return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Accept token - have the VAS api handle the base64 stuff for us */
    TRACE_R(r, "calling vas_gss_spnego_accept, base64 token_size=%d", (int) in_token.length);
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

        TRACE_R(r, "%s: server keytab %s", __func__, sc->keytab_filename ? sc->keytab_filename : "using default HTTP.keytab");

    	/* Get the client's name */
	    err = gss_inquire_context(&minor_status, rn->gss_ctx, &client_name,
		    NULL, NULL, NULL, NULL, NULL, NULL);
    	if (err != GSS_S_COMPLETE) {
            result = HTTP_UNAUTHORIZED;
	        log_gss_error(APLOG_MARK, APLOG_ERR, 0, r, "gss_inquire_context", err, minor_status);
    	    goto done;
	    }

    	/* Convert the client's name into a visible string */
    	err = gss_display_name(&minor_status, client_name, &buf, NULL);
    	if (err != GSS_S_COMPLETE) {
	        result = HTTP_UNAUTHORIZED;
	        log_gss_error(APLOG_MARK, APLOG_ERR, 0, r, "gss_display_name", err, minor_status);
    	    goto done;
	    }

    	/* Copy out the authenticated user's name. */
	    RUSER(r) = apr_pstrmemdup(RUSER_POOL(r), buf.value, buf.length);
    	gss_release_buffer(&minor_status, &buf);
	    if (RUSER(r) == NULL) {
    	    MAV_LOG_RERRNO(APLOG_ERR, r, APR_ENOMEM, "apr_pstrmemdup");
	        result = HTTP_INTERNAL_SERVER_ERROR;
    	    goto done;
	    }

    	/* Create the remote user object now that we have their name */
    	result = initialize_user(r, RUSER(r));
    	if (result)
	        goto done;

    	/* Set RUSER to the configured attribute.
	     * This has to be done after user object initialisation to ensure
    	 * the right user object is created.
	     * set_remote_user() does its own locking if necessary. */
    	UNLOCK_VAS(r);
	    set_remote_user(r);
    	LOCK_VAS(r);

    	/* Save the VAS auth context */
	    
	    gss_cred_id_t servercred = GSS_C_NO_CREDENTIAL;
	    vas_gss_acquire_cred(sc->vas_ctx, sc->vas_serverid, &minor_status, GSS_C_ACCEPT, &servercred);
	     
    	vaserr = auth_vas_user_use_gss_result(rn->mav_user, servercred, rn->gss_ctx);
    	if (vaserr) {
	        result = HTTP_UNAUTHORIZED;
    	    /* We know that the cache & user stuff uses the same vas context as
	         * the server, but using the vas_ctx here still feels dirty. */
	        ERROR_R(r, "%s: auth_vas_user_use_gss_result failed: %s", __func__, vas_err_get_string(sc->vas_ctx, 1));
    	    goto done;
	    }

    	/* FIXME: free properly */
	    gss_release_cred(&minor_status, &servercred);

    	/* Keep a copy of the client's mechanism name in the connection note */
    	err = gss_export_name(&minor_status, client_name, &rn->client);
	    if (err != GSS_S_COMPLETE) {
	        result = HTTP_UNAUTHORIZED;
    	    log_gss_error(APLOG_MARK, APLOG_ERR, 0, r, "gss_export_name", err, minor_status);
	    }

        TRACE1_R(r, "%s: authenticated user: '%s'", __func__, RUSER(r));

    	/* Authentication has succeeded at this point */
    	RAUTHTYPE(r) = (char *)VAS_AUTH_TYPE;
	    result = OK;
    } else if (gsserr == GSS_S_CONTINUE_NEEDED) {
    	TRACE_R(r, "waiting for more tokens from client");
	    result = HTTP_UNAUTHORIZED;
    } else if (strncmp(auth_param, "TlRM", 4) == 0) {
    	const auth_vas_dir_config *dc = GET_DIR_CONFIG(r->per_dir_config);
	    MAV_LOG_R(APLOG_INFO, r, "NTLM authentication attempted");
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
    	ERROR_R(r, "%s: %s", __func__, vas_err_get_string(sc->vas_ctx, 1));
    	result = HTTP_UNAUTHORIZED;
    }

 done:
    vas_gss_deinitialize(sc->vas_ctx);

    if (GSS_ERROR(gsserr))
    	ERROR_R(r, "%s: %s", __func__, vas_err_get_string(sc->vas_ctx, 1));

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
	        MAV_LOG_RERRNO(APLOG_ERR, r, APR_ENOMEM, "apr_palloc");
    	    result = HTTP_INTERNAL_SERVER_ERROR;
	        goto cleanup;
    	}

	    /* Construct the header value string */
    	strcpy(auth_out, NEGOTIATE_TEXT);
	    strncat(auth_out, out_token.value, out_token.length);

    	/* Add to the outgoing header set. */
	    apr_table_setn(r->err_headers_out, IS_FORWARD_PROXY_REQUEST(r) ? "Proxy-Authenticate" : "WWW-Authenticate", auth_out);
    	/* add_basic_auth_headers(r); */
    }

    /* Detect NTLMSSP attempts */
    if (gsserr == GSS_S_DEFECTIVE_TOKEN && in_token.length >= 7 && memcmp(in_token.value, "NTLMSSP", 7) == 0)
    {
    	MAV_LOG_R(APLOG_NOTICE, r, "Client used unsupported NTLMSSP authentication");
    }

 cleanup:
    if (LOCK_VAS(r))
    	WARN_R(r, "do_gss_spnego_accept: cannot acquire lock to release resources");
    else {
	    gss_release_buffer(&gsserr, &out_token);
    	if (client_name)
	        gss_release_name(NULL, &client_name);
    	UNLOCK_VAS(r);
    }

    TRACE8_R(r, "%s: end", __func__);
    return result;
} /* do_gss_spnego_accept */

/**
 *
 *
 *
 */
static void set_cache_size(server_rec *server)
{
    auth_vas_server_config *sc;
    apr_int64_t size;
    char *end;

    sc = GET_SERVER_CONFIG(server->module_config);

    if (!sc->cache_size) /* Not configured */
	return;

    size = apr_strtoi64(sc->cache_size, &end, 10);

    if (*end == '\0') {
	/* Clamp the size to [1,UINT_MAX] */
	if (size < 1)
	    size = 1;
	if (size > UINT_MAX)
	    size = UINT_MAX;

	auth_vas_cache_set_max_size(sc->cache, (unsigned int) size);
    } else {
    	MAV_LOG_S(APLOG_WARNING, server, "%s: invalid " CMD_CACHESIZE " setting: %s", __func__, sc->cache_size);
    }

    DEBUG_S(server, "%s: cache size is %u", __func__, auth_vas_cache_get_max_size(sc->cache));
} /* set_cache_size */

/**
 * Sets the cache timeout for the server cache based on the string-format
 * timeout value in the server config.
 *
 * The string may end with the suffix 'h', 'm', or 's' for Hours, Minutes and
 * Seconds. An unadorned value means seconds.
 *
 * The value must be an integer.
 */
static void set_cache_timeout(server_rec *server)
{
    auth_vas_server_config *sc;
    apr_int64_t secs;
    char *end;
    int multiplier = 1; /* Using a separate var to detect integer overflow */

    sc = GET_SERVER_CONFIG(server->module_config);

    if (!sc->cache_time) /* Not configured */
	return;

    secs = apr_strtoi64(sc->cache_time, &end, 10);

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
		secs = UINT_MAX;
	    else
		secs *= multiplier;

	case 's':
	case '\0':
	    auth_vas_cache_set_max_age(sc->cache, (unsigned int) secs);
	    break;

	default:
	    MAV_LOG_S(APLOG_WARNING, server, "%s: invalid " CMD_CACHEEXPIRE " setting: %s", __func__, sc->cache_time);
    }

    DEBUG_S(server, "%s: cache lifetime is %u seconds", __func__, auth_vas_cache_get_max_age(sc->cache));
} /* set_cache_timeout */

/**
 * Establishes Kerberos credentials for the given server.
 * Returns an HTTP error code or OK on success.
 */
static int get_server_creds(server_rec *s)
{
    vas_err_t vaserr;
    auth_vas_server_config *sc = GET_SERVER_CONFIG(s->module_config);
  
    TRACE8_S(s, "%s: Called", __func__);

    TRACE_S(s, "%s: using %s", __func__, sc->keytab_filename ? sc->keytab_filename : " default HTTP.keytab");

    /* Don't try getting a TGT yet.
     * SPNs that are not also UPNs cannot get a TGT and would fail. */
    vaserr = vas_id_establish_cred_keytab(sc->vas_ctx,
					  sc->vas_serverid,
					    VAS_ID_FLAG_USE_MEMORY_CCACHE
					  | VAS_ID_FLAG_KEEP_COPY_OF_CRED
					  | VAS_ID_FLAG_NO_INITIAL_TGT,
					  sc->keytab_filename);
    if (vaserr) {
        ERROR_S(s, "vas_id_establish_cred_keytab failed: %s", vas_err_get_string(sc->vas_ctx, 1));
        TRACE8_S(s, "%s: end", __func__);
    	return HTTP_INTERNAL_SERVER_ERROR;
    }

    TRACE_S(s, "Successfully established credentials for %s", sc->server_principal);

    sc->creds_established_at = apr_time_now();
    TRACE8_S(s, "%s: end", __func__);
    return OK;
} /* get_server_creds */

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
static void auth_vas_server_init(apr_pool_t *p, server_rec *s)
{
    vas_err_t               vaserr;
    vas_auth_t             *vasauth;
    auth_vas_server_config *sc;
    char *tmp_realm;

    TRACE8_S(s, "%s: called", __func__);
    LOG_S(APLOG_TRACE1, s, "called");

    DEBUG_S(s, "%s: Initializing %s for host: %s: Defined on line %i in conf file: %s", __func__, (s->is_virtual ? "VirtualHost" : "Server"), s->server_hostname, s->defn_line_number, s->defn_name ? s->defn_name : "default conf file");

    sc = GET_SERVER_CONFIG(s->module_config);
    TRACE_S(s, "%s: Server config=%pp", __func__, sc); /* %pp is apr_vformatter syntax for a (void*) */

    if (sc == NULL) {
    	ERROR_S(s, "%s: no server config", __func__);
        TRACE8_S(s, "%s: end", __func__);
    	return;
    }

    if (sc->vas_ctx != NULL) {
    	TRACE1_S(s, "%s: context has already initialised", __func__);
        TRACE8_S(s, "%s: end", __func__);
        return;
    }

    DEBUG_S(s, "%s: Using servicePrincipalName '%s'", __func__, sc->server_principal);

    /* Obtain a new VAS context for the web server */
    vaserr = vas_ctx_alloc(&sc->vas_ctx);
    if (vaserr != VAS_ERR_SUCCESS) {
        ERROR_S(s, "vas_ctx_alloc failed, err = %d", vaserr);
        TRACE8_S(s, "%s: end", __func__);
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
	    MAV_LOG_SERRNO(APLOG_WARNING, s, vaserr, "VAS cannot determine the default realm, ensure it is set with AuthVasDefaultRealm.");
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
    	ERROR_S(s, "vas_id_alloc failed on %s, err = %s", sc->server_principal, vas_err_get_string(sc->vas_ctx, 1));
        TRACE8_S(s, "%s: end", __func__);
    	return;
    }

    /* Establish our credentials using the service keytab */
    if (get_server_creds(s) != OK) {
        TRACE8_S(s, "%s: end", __func__);
	    return;
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
	        MAV_LOG_S(APLOG_INFO, s, "Credential test for %s failed with %s, " "this is harmless if it is a service alias", sc->server_principal, krb5_get_error_name(errinfo->code));
    	} else {
	        ERROR_S(s, "vas_auth failed, err = %s", vas_err_get_string(sc->vas_ctx, 1));
	    }

    	if (errinfo)
	        vas_err_info_free(errinfo);
    } else {
        DEBUG_S(s, "%s: Successfully authenticated as %s using the %s",
                __func__,            
    		    sc->server_principal,
                (sc->keytab_filename ? sc->keytab_filename : "default HTTP.ketyab"));
                vas_auth_free(sc->vas_ctx, vasauth);
    }

    sc->cache = auth_vas_cache_new(p, sc->vas_ctx, sc->vas_serverid,
	    (void(*)(void*))auth_vas_user_ref,
	    (void(*)(void*))auth_vas_user_unref,
	    (const char*(*)(void*))auth_vas_user_get_name);

    set_cache_size(s);
    set_cache_timeout(s);

    TRACE8_S(s, "%s: end", __func__);
} /* auth_vas_server_init */

/**
 * Appends the Basic auth header, if enabled
 *
 * The ap_note_auth_failure functions *replace* any existing WWW-Authenticate
 * or Proxy-Authenticate header, so don't use them.
 */
static void add_basic_auth_headers(request_rec *r)
{
    const auth_vas_dir_config *dc;
    const auth_vas_server_config *sc;
    char *s;

    ASSERT(r != NULL);

    TRACE8_R(r, "%s", __func__);

    dc = GET_DIR_CONFIG(r->per_dir_config);
    ASSERT(dc != NULL);
    
    sc = GET_SERVER_CONFIG(r->server->module_config);
    ASSERT(sc != NULL);
    if (USING_AUTH_BASIC(dc)) {
    	s = apr_psprintf(r->pool, "Basic realm=\"%s\"", ap_auth_name(r) ? ap_auth_name(r) : sc->default_realm);
    	ASSERT(s != NULL);
        TRACE1_R(r, "%s: Adding Basic to auth header: %s", __func__, s);
	    apr_table_addn(r->err_headers_out, IS_FORWARD_PROXY_REQUEST(r) ? "Proxy-Authenticate" : "WWW-Authenticate", s);
    }else
        DEBUG_R(r, "%s: AuthVasUseBasic is set to off. Basic Authentication is not allowed", __func__);

    TRACE8_R(r, "%s: end", __func__);
} /* add_basic_auth_headers */

struct ip_cmp_closure {
    request_rec *request;
    int match_found;
    apr_sockaddr_t *sockaddr_p;
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
static int mav_ip_subnet_cmp(void *rec, const char *key, const char *value)
{
    enum { MATCH = 0, NO_MATCH = 1, ERROR = 2 };
    struct ip_cmp_closure *closure = (struct ip_cmp_closure *)rec;
    request_rec *r = closure->request;

    closure->match_found = 0;
    
	apr_ipsubnet_t *ipsubnet;
	char addr[sizeof("0000:0000:0000:0000:0000:0000:0000:0000")];
	char *slash;
	apr_status_t subnet_create_err;

	slash = strchr(value, '/');
	if (slash) {
	    const char *const mask = slash + 1; /* for convenience */
	    int addrlen = slash - value;

	    if (addrlen > sizeof(addr) - 1) {
    		/* Too long to be a valid IPv4 or IPv6 address */
	    	ERROR_R(r, "%s: Invalid address from config (%s): too long", __func__, value);
		    return ERROR;
	    }

	    memcpy(addr, value, addrlen);
	    addr[addrlen] = '\0';

	    subnet_create_err =
		apr_ipsubnet_create(&ipsubnet, addr, mask, closure->request->pool);
	} else {
	    /* No subnet provided - checking exact host */
	    subnet_create_err =
		apr_ipsubnet_create(&ipsubnet, value, NULL, closure->request->pool);
	}

	if (subnet_create_err) {
	    MAV_LOG_RERRNO(APLOG_ERR, r, subnet_create_err, "Failed to convert %s into an IP subnet", value); 
        return ERROR;
	}

	if (apr_ipsubnet_test(ipsubnet, closure->sockaddr_p))
	    closure->match_found = 1;
	
	return !closure->match_found;
    
} /* mav_ip_subnet_cmp */

/**
 * Determines whether the client should be allowed to do Negotiate auth.
 * @return non-zero if so, zero if not.
 */
static int is_negotiate_enabled_for_client(request_rec *r)
{
    auth_vas_dir_config *dc;
    struct ip_cmp_closure closure;
    apr_status_t status; 

    ASSERT(r != NULL);

    TRACE8_R(r,"%s called",__func__);

    dc = GET_DIR_CONFIG(r->per_dir_config);

    if (!USING_AUTH_NEGOTIATE(dc)) {
        TRACE1_R(r, "%s: Using Auth Negotiate",__func__);
        TRACE8_R(r, "%s: end",__func__);
    	return 0;
    }

    if (dc->negotiate_subnets == NULL) { /* All subnets */
        TRACE1_R(r, "%s: Using all subnets", __func__);
        TRACE8_R(r, "%s: end", __func__);
    	return 1;
    }

   	status = apr_sockaddr_info_get(&closure.sockaddr_p, r->connection->client_ip, APR_UNSPEC, 0, 0, r->pool);
    if (status != APR_SUCCESS) {
        MAV_LOG_RERRNO(APLOG_ERR, r, status, "%s: Error turning %s into a sockaddr struct", __func__, r->connection->client_ip);
        TRACE8_R(r, "%s: end", __func__);
   	    return 0;
    } else {
           TRACE4_R(r, "%s: Success in turning %s into a sockaddr struct", __func__, r->connection->client_ip);
    }

    closure.request = r;

    apr_table_do(mav_ip_subnet_cmp, &closure, dc->negotiate_subnets, NULL);
    TRACE8_R(r, "%s: end", __func__);
    return closure.match_found;
} /* is_negotiate_enabled_for_client */

/**
 * Appends the headers
 *   WWW-Authenticate: Negotiate
 *   WWW-Authenticate: Basic realm="realm"	 (if enabled)
 * to the request's error response headers.
 *
 * Proxy-Authenticate is used instead of WWW-Authenticate in proxy mode.
 *
 * The ap_note_auth_failure functions *replace* any existing WWW-Authenticate
 * or Proxy-Authenticate header, so don't use them.
 */
static void add_auth_headers(request_rec *r)
{
    ASSERT(r != NULL);

    TRACE8_R(r, "%s called", __func__);

    if (is_negotiate_enabled_for_client(r)) {
        DEBUG_R(r, "%s: Adding Negotiate to auth_header: %s", __func__, IS_FORWARD_PROXY_REQUEST(r) ? "Proxy-Authenticate Negotiate" : "WWW-Authenticate Negotiate");
       	apr_table_addn(r->err_headers_out, IS_FORWARD_PROXY_REQUEST(r) ? "Proxy-Authenticate" : "WWW-Authenticate", "Negotiate");
    }

    add_basic_auth_headers(r);

    TRACE8_R(r, "%s end", __func__);
} /* add_auth_headers */

/**
 * Gets the authentication line from the header
 *
 *
 *
 */
static int get_auth_line(request_rec *r, const char **auth_line)
{
    TRACE8_R(r, "%s: start", __func__);
    
    auth_vas_dir_config     *dc = GET_DIR_CONFIG(r->per_dir_config);
    const char *header_auth_line = NULL;

    /* Pick out the client request's Authorization header(s) */
    header_auth_line = apr_table_get(r->headers_in, (PROXYREQ_PROXY == r->proxyreq) ? "Proxy-Authorization" : "Authorization");

    TRACE4_R(r, "%s: auth_line %s", __func__, header_auth_line ? header_auth_line : "Not set");

    if (!header_auth_line)
    {
        if (USING_AUTH_NEGOTIATE(dc)) {
            /* There were no Authorization headers: Deny access now,
             * but offer possible means of negotiation via WWW-Authenticate */
            TRACE1_R(r, "%s: sending initial negotiate headers", __func__);
            add_auth_headers(r);
        } else if (USING_AUTH_BASIC(dc)) {
            TRACE1_R(r, "%s: sending initial basic headers", __func__);
            add_basic_auth_headers(r);
        } else {
            WARN_R(r, "%s off and %s off; no authentication possible", CMD_USENEGOTIATE, CMD_USEBASIC);
        }
        /* Note that in the absence of Authorization headers there is no way
         * that any other auth module will be able to authenticate either, so
         * there's no need to return DECLINED if not authoritative. */
        TRACE1_R(r, "%s: Returning HTTP_UNAUTHORIZED", __func__);
        TRACE8_R(r, "%s: end", __func__);
        return HTTP_UNAUTHORIZED;
    }

    TRACE8_R(r, "%s: end",__func__);

    *auth_line = header_auth_line;    
    
    return OK;
} /* get_auth_line */

/**
 * Analyze the request headers, authenticate the user, 
 * and set the user information in the request record (r->user and r->ap_auth_type). 
 *
 * This method is only run when Apache determines that authentication/authorization is required for this 
 * resource (as determined by the 'Require' directive). 
 *
 * It runs after the registered authz_provider checks, and before the registered authn_provider checks. 
 * This method should be registered with ap_hook_check_authn().
 *
 *   @param r The request being authenticated
 *   @return OK if the client user is authorized access, DECLINED, or HTTP_FORBIDDEN
 *           if it isn't.
 */
static int authenticate_gss_user(request_rec *r)

{
    auth_vas_dir_config *conf = GET_DIR_CONFIG(r->per_dir_config);
    
    const char *sent_user = NULL, *sent_pw = NULL, *auth_type, *current_auth, *auth_line;
    int length, res;
    authn_status auth_result = AUTH_GENERAL_ERROR;
    authn_provider_list *current_provider;
    char *decoded_line;

    TRACE8_R(r, "%s: called", __func__);

    current_auth = ap_auth_type(r);

    TRACE1_R(r, "%s: Directory Auth Type : %s", __func__, current_auth ? current_auth : "Not Set");

    if(!current_auth || strcasecmp(current_auth, VAS_AUTH_TYPE)) {
        WARN_R(r, "AuthType %s != %s, not handling this request", current_auth ? current_auth : "(null)", VAS_AUTH_TYPE);
        TRACE8_R(r, "%s: end", __func__);
        return DECLINED;
    }

    if (!server_ctx_is_valid(r->server)) {
        if (!USING_AUTH_AUTHORITATIVE(conf)) {
            TRACE8_R(r, "%s: end", __func__);
            return DECLINED;
        }
        ERROR_R(r, "%s: no VAS context, check for errors logged at startup", __func__);
        TRACE8_R(r, "%s: end", __func__);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    r->ap_auth_type = (char*)current_auth;

    res = get_auth_line(r, &auth_line);
    if(res) {
        TRACE2_R(r, "%s: get_auth_line result: %i", __func__, res);
        TRACE8_R(r, "%s: End", __func__);
        return res;
    }

    auth_type = ap_getword_white(r->pool, &auth_line);
    TRACE1_R(r, "%s Attempting Authentication using %s auth'", __func__, auth_type);

    if( auth_type ) {
        if (strcasecmp(auth_type, "Basic") == 0 && auth_line != NULL) {
            TRACE2_R(r, "%s: Header Auth Type is %s. Setting username", __func__, auth_type);
            decoded_line = apr_palloc(r->pool, apr_base64_decode_len(auth_line) + 1);
            length = apr_base64_decode(decoded_line, auth_line);
            /* Null-terminate the string. */
            decoded_line[length] = '\0';

            sent_user = ap_getword_nulls(r->pool, (const char**)&decoded_line, ':');
            sent_pw = decoded_line;

            /* set the user, even though the user is unauthenticated at this point */
            r->user = (char *)sent_user;

            // If auth_type is basic go through the providers list, other wise we will handle it.
            current_provider = conf->auth_providers;
            do {
                const authn_provider *provider;

                if(!current_provider) {
                    DEBUG_R(r, "%s: No providers listed in conf, using default %s", __func__, DEFAULT_AUTHN_PROVIDER);
                    provider = ap_lookup_provider(AUTHN_PROVIDER_GROUP,
                                                  DEFAULT_AUTHN_PROVIDER,
                                                  AUTHN_PROVIDER_VERSION);

                    if(!provider || !provider->check_password) {
                        ERROR_R(r, "No Authn provider configured");
                        auth_result = AUTH_GENERAL_ERROR;
                        break;
                    }
                    apr_table_setn(r->notes, AUTHN_PROVIDER_NAME_NOTE, "vas");
                }
                else {
                    provider = current_provider->provider;
                    apr_table_setn(r->notes, AUTHN_PROVIDER_NAME_NOTE, current_provider->provider_name);
                }
    
                auth_result = provider->check_password(r, sent_user, sent_pw);

                TRACE1_R(r, "%s: authentication provider <%s> returned auth result %i", __func__, current_provider ? current_provider->provider_name : DEFAULT_AUTHN_PROVIDER, auth_result);

                apr_table_unset(r->notes, AUTHN_PROVIDER_NAME_NOTE);

                if(auth_result != AUTH_USER_NOT_FOUND) {
                    break;
                }   

                if(!conf->auth_providers) {
                    break;
                }

                current_provider = current_provider->next;

            } while (current_provider);
            /* End Basic Auth */
        } else if(strcasecmp(auth_type, "Negotiate") == 0 && is_negotiate_enabled_for_client(r)) {
            TRACE2_R(r, "%s: Header Auth Type is %s. Authenticate using SPNEGO", __func__, auth_type);
            sent_user = NULL;
            sent_pw = NULL;

            if (!USING_AUTH_NEGOTIATE(conf)) {
                if (!USING_AUTH_AUTHORITATIVE(conf)) {
                    TRACE8_R(r, "%s: end", __func__);
                    return DECLINED;
                }
                ERROR_R(r, "%s: Negotiate authentication denied (%s off)", __func__, CMD_USENEGOTIATE);
                TRACE8_R(r, "%s: end", __func__);
                return HTTP_UNAUTHORIZED;
            }

            auth_result = do_gss_spnego_accept(r, auth_line);

            if (auth_result != OK) {
                TRACE1_R(r, "%s: do_gss_spnego_accept return %i, adding basic auth headers", __func__, auth_result);
                add_basic_auth_headers(r);
            }
            DEBUG_R(r, "%s: auth_result %i", __func__, auth_result);
            TRACE8_R(r, "%s: end", __func__);
            return (auth_result == OK || USING_AUTH_AUTHORITATIVE(conf)) ?  auth_result : DECLINED;
        } /* End Negotiate Auth */
        else {
            TRACE2_R(r, "%s: Unknown auth_type %s", __func__, auth_type);
            /* We don't understand. Deny access. */
            add_auth_headers(r);
            TRACE8_R(r, "%s: end", __func__);
            return USING_AUTH_AUTHORITATIVE(conf) ? HTTP_UNAUTHORIZED : DECLINED;
        }
    }
    
    if (auth_result != AUTH_GRANTED) {
        int return_code;

        TRACE1_R(r, "%s: auth_result != AUTH_GRANTED. %i", __func__, auth_result);

        /* If we're not authoritative, then any error is ignored. */
        if (!(conf->auth_authoritative) && auth_result != AUTH_DENIED) {
            TRACE8_R(r, "%s: end", __func__);
            return DECLINED;
        }

        switch (auth_result) {
            case AUTH_DENIED:
                ERROR_R(r, "%s: user %s: authentication failure for \"%s\": " "Password Mismatch", __func__, sent_user, r->uri);
                return_code = HTTP_UNAUTHORIZED;
                break;
            case AUTH_USER_NOT_FOUND:
                ERROR_R(r, "%s: user %s not found: %s", __func__, sent_user, r->uri);
                return_code = HTTP_UNAUTHORIZED;
                break;
            case AUTH_GENERAL_ERROR:
                DEBUG_R(r, "%s: AUTH_GENERAL_ERROR",__func__);
            default:
                /* We'll assume that the module has already said what its error
                 * was in the logs.
                 */
                DEBUG_R(r, "%s: auth error %i", __func__, auth_result);
                return_code = HTTP_INTERNAL_SERVER_ERROR;
                break;
        }

        /* If we're returning 403, tell them to try again. */
        if (return_code == HTTP_UNAUTHORIZED) {
            add_basic_auth_headers(r);
        }
        DEBUG_R(r, "%s: auth_result %i", __func__, return_code);
        TRACE8_R(r, "%s: end", __func__);
        return return_code;
    }else{
        TRACE1_R(r, "%s: auth_result == AUTH_GRANTED. %i", __func__, auth_result);
    }

    TRACE8_R(r, "%s: end", __func__);
    return OK;
} /* authenticate_gss_user */

#if HAVE_UNIX_SUEXEC
/**
 * Provides uid/gid of a VAS authenticated user, for when suEXEC is enabled.
 * @param r curent request
 * @return pointer to an identity structure
 */
static ap_unix_identity_t * auth_vas_suexec(const request_rec *r)
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
} /* auth_vas_suexec */
#endif /* HAVE_UNIX_SUEXEC */

/**
 * Exports delegated credentials into a file, and sets the subprocess
 * environment KRB5CCNAME to point to the file. The file gets removed
 * by rnote_fini() during request cleanup.
 *
 * This function performs no action if already exported, export 
 * delegation is disabled, or if the GSS credential is unavailable.
 */
static void export_cc(request_rec *r)
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
	    ERROR_R(r, "export_cc: unable to acquire lock to export credentials");
	    return;
    }

    /* Pull the credential cache filename out */
    if ((vaserr = vas_krb5_get_context(sc->vas_ctx, &krb5ctx))) {
        ERROR_R(r, "vas_krb5_get_context: %s", vas_err_get_string(sc->vas_ctx, 1));
	    goto finish;
    }

    if ((krb5err = krb5_cc_new_unique(krb5ctx, "FILE", NULL, &ccache))) {
        ERROR_R(r, "krb5_cc_new_unique: %.100s", krb5_get_err_text(krb5ctx, krb5err));
	    goto finish;
    }

    if ((major = gss_krb5_copy_ccache(&minor, rn->deleg_cred, ccache))) {
    	log_gss_error(APLOG_MARK, APLOG_ERR, 0, r, "gss_krb5_copy_ccache", major, minor);
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
} /* export_cc */

static struct ldap_lookup_map {
    const char *const ldap_attr;
    vas_err_t (*vas_func)(vas_ctx_t *ctx, vas_id_t *serverid, vas_user_t *user, char **result);
} quick_ldap_lookups[] = {
    { "sAMAccountName",		vas_user_get_sam_account_name },
    { "distinguishedName",	vas_user_get_dn },
    { "objectSid",		    vas_user_get_sid },
    { "userPrincipalName",	vas_user_get_upn },
    { NULL, NULL }
}; /* struct ldap_lookup_map quick_ldap_lookups[] */

/**
 * Set the remote username (REMOTE_USER variable) to the chosen attribute.
 * Only call this if the remote_user_attr is not NULL.
 */
static void set_remote_user_attr(request_rec *r, const char *attr)
{
    const char *old_ruser = RUSER(r);
    auth_vas_server_config *sc;
    const char *const anames[2] = { attr, NULL };
    vas_attrs_t *attrs;
    auth_vas_rnote *rn;

    ASSERT(r != NULL);

    TRACE8_R(r, "%s: called",__func__);

    /* Depends on the remote_user_map_methods having the right info */
    ASSERT(attr != NULL);
    ASSERT(attr[0]);

    sc = GET_SERVER_CONFIG(r->server->module_config);
    ASSERT(sc != NULL);

    if (LOCK_VAS(r)) {
	    ERROR_R(r, "Failed to lock VAS");
        TRACE8_R(r, "%s: end", __func__);
	    return;
    }

    rn = GET_RNOTE(r);

    /* Lookups sometimes fail if the server creds have expired. Ensure they're
     * not too old. As of this writing I've been unable to reproduce the crash
     * that occurs as a result of having expired credentials. See bug #569.
     * Our workaround is to reinitialize credentials after half the default
     * ticket_lifetime (ie. reinitialize every 5 hours). */
#define MAV_REINIT_CREDS_AFTER_SECS 18000
    if (apr_time_sec(apr_time_now()) > apr_time_sec(sc->creds_established_at) + MAV_REINIT_CREDS_AFTER_SECS)
    {
    	DEBUG_R(r, "%s: reinitializing server credentials", __func__);
	if (get_server_creds(r->server) != OK)
	    goto finish;
    }

    if (set_user_obj(r))
    	goto finish;

    /* Look for attributes that are likely to be in the vas cache */
    {
	    struct ldap_lookup_map *map;

    	for (map = quick_ldap_lookups; map->ldap_attr; ++map) {
	        ASSERT(map->vas_func != NULL);
	        if (strcasecmp(map->ldap_attr, attr) == 0) {
    		    char *attrval;

    		    DEBUG_R(r, "%s: Using VAS cache for lookup of %s attribute", __func__, attr);

    	    	if (map->vas_func(sc->vas_ctx, sc->vas_serverid,(vas_user_t*)auth_vas_user_get_vas_user_obj(rn->mav_user), &attrval) == VAS_ERR_SUCCESS)
          		{ /* success */
	    	        RUSER(r) = apr_pstrdup(RUSER_POOL(r), attrval);
		            free(attrval);
        		} else { /* VAS error */
    	    	    ERROR_R(r, "Error looking up %s attribute in VAS cache: %s", attr, vas_err_get_string(sc->vas_ctx, 1));
       		    }
		        goto finish;
	        }
	    }

	    /* uidNumber and gidNumber are special cases because libvas provides a
    	 * struct passwd not a char* */
    	if (strcasecmp("uidNumber", attr) == 0 || strcasecmp("gidNumber", attr) == 0) {
	        const char ug = *attr; /* u or g */
    	    struct passwd *pw;

	        DEBUG_R(r, "%s: Using VAS cache for lookup of %cidNumber attribute", __func__, ug);
    	    if (vas_user_get_pwinfo(sc->vas_ctx, sc->vas_serverid, (vas_user_t*)auth_vas_user_get_vas_user_obj(rn->mav_user), &pw) == VAS_ERR_SUCCESS)
	        { /* success */
        		RUSER(r) = apr_psprintf(RUSER_POOL(r), "%u", ug == 'u' ? pw->pw_uid : pw->pw_gid);
		        free(pw);
	        } else { /* VAS error (or user is not Unix-enabled) */
    	    	ERROR_R(r, "Error looking up %cidNumber attribute in VAS cache: %s", ug, vas_err_get_string(sc->vas_ctx, 1));
	        }
	       goto finish;
	    }
    }

    DEBUG_R(r, "%s: VAS cache lookup unavailable for %s, doing LDAP query", __func__, attr);

    if (vas_user_get_attrs(sc->vas_ctx, sc->vas_serverid, (vas_user_t*)auth_vas_user_get_vas_user_obj(rn->mav_user), anames, &attrs) == VAS_ERR_SUCCESS) {
    	char **strvals;
	    int count;
    	vas_err_t vaserr;

	    vaserr = vas_vals_get_string(sc->vas_ctx, attrs, attr, &strvals, &count);
    	if (vaserr == VAS_ERR_SUCCESS || vaserr == VAS_ERR_MORE_VALS) {
	        ASSERT(count > 0);
	        ASSERT(strvals);
    	    ASSERT(strvals[0]);

	        RUSER(r) = apr_pstrdup(RUSER_POOL(r), strvals[0]);

	        (void) vas_vals_free_string(sc->vas_ctx, strvals, count);
	    } else {
	        ERROR_R(r, "Failed getting %s attribute values: %s", attr, vas_err_get_string(sc->vas_ctx, 1));
	    }

    	vas_attrs_free(sc->vas_ctx, attrs);
    }
    else {
	    ERROR_R(r, "vas_user_get_attrs() failed to get attribute %s: %s", attr, vas_err_get_string(sc->vas_ctx, 1));
    }

finish:
    UNLOCK_VAS(r);

    MAV_LOG_R(APLOG_INFO, r, "Remote user set from %.100s to %.100s (attribute %s)", old_ruser, RUSER(r), attr);

    TRACE8_R(r, "%s: end", __func__);

} /* set_remote_user_attr */


/**
 * Convert the authenticated user name into a local username.
 */
static void localize_remote_user(request_rec *r, const char *unused)
{
#ifdef APR_HAS_USER
    apr_status_t aprst;
    apr_uid_t uid, gid;
    char *username;

    ASSERT(r != NULL);
    TRACE8_R(r, "%s: called",  __func__);

    /* Convert the UPN into a UID, then convert the UID back again */

    if ((aprst = apr_uid_get(&uid, &gid, RUSER(r), r->pool) != OK)) {
	    /* User is probably not Unix-enabled. Try stripping the realm anyway
    	 * for consistency */

    	DEBUG_R(r, "apr_uid_get failed for %s (normal for non-Unix users), " "using strcmp method", RUSER(r));

	    localize_remote_user_strcmp(r);
        TRACE8_R(r, "%s: end", __func__);
    	return;
    }

    /* Unix-enabled user, convert back to their name */
    if ((aprst = apr_uid_name_get(&username, uid, RUSER_POOL(r))) != OK) {
	    MAV_LOG_RERRNO(APLOG_ERR, r, aprst, "apr_uid_name_get failed for uid %d", uid);
        TRACE8_R(r, "%s: end", __func__);
	    return;
    }

    /* Set the authorized username to the localized name.
     * username was allocated out of the right pool. */
    RUSER(r) = username;
    TRACE8_R(r, "%s: end", __func__);
    return;

#else /* !APR_HAS_USER */
    localize_remote_user_strcmp(r);
    TRACE8_R(r, "%s: end", __func__);
    return;
#endif /* !APR_HAS_USER */
} /* localize_remote_user */

/**
 * Strips "@DEFAULT-REALM" from the end of RUSER(r) if it is there.
 * If the realm does not match, it is not stripped.
 */
static void localize_remote_user_strcmp(request_rec *r)
{
    const auth_vas_server_config *sc;
    char *at, *user_realm;

    ASSERT(r != NULL);
    TRACE8_R(r, "%s: called",  __func__);

    at = strchr(RUSER(r), '@');
    if (!at) {
        TRACE8_R(r, "%s: end", __func__);
    	return; /* Not a UPN */
    }

    user_realm = at + 1;

    ASSERT(r->server != NULL);
    sc = GET_SERVER_CONFIG(r->server->module_config);

    ASSERT(sc->default_realm != NULL);
    if (strcasecmp(user_realm, sc->default_realm) == 0) {
	    DEBUG_R(r, "stripping matching realm from " "user %s", RUSER(r));
       	*at = '\0'; /* Trimming RUSER(r) directly */
    }
    TRACE8_R(r, "%s: end", __func__);
} /* localize_remote_user_strcmp */

/**
 * Process the AuthVasUseNegotiate option which may be "On" (default),
 * "Off", or a list of subnets to suggest negotiate auth to.
 * @return NULL on success or an error message.
 */
static const char * set_negotiate_conf(cmd_parms *cmd, void *struct_ptr, const char *args)
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
} /* set_negotiate_conf */

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
}; /* struct remote_user_map_methods */

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
} /* set_remote_user_map_conf */

/**
 * Sets RUSER(r) according to the remote_user_map configuration.
 *
 * Callers must not hold the VAS lock.
 */
static void set_remote_user(request_rec *r)
{
    auth_vas_dir_config *dc;
    const char *method_name, *args;
    int i;

    TRACE8_R(r, "%s: called", __func__);

	DEBUG_R(r, "%s: setting REMOTE_USER for %s", __func__, RUSER(r));

    dc = GET_DIR_CONFIG(r->per_dir_config);
    ASSERT(dc != NULL);

    if (dc->remote_user_map == NULL)
    	dc->remote_user_map = "default";

    method_name = dc->remote_user_map;
    args = dc->remote_user_map_args;

    DEBUG_R(r, "%s: setting REMOTE_USER variable using %s %s name mapping", __func__, method_name, (args ? args : ""));

    for (i = 0; i < num_remote_user_map_methods; ++i) {
    	if (strcasecmp(method_name, remote_user_map_methods[i].name) == 0) {
	        if (remote_user_map_methods[i].method)
		        (*remote_user_map_methods[i].method)(r, args);
            DEBUG_R(r, "%s: Mapped user to %s using %s %s name mapping", __func__, RUSER(r), method_name, (args ? args: ""));
            TRACE8_R(r, "%s: End",__func__);
    	    return;
	    }
    }
    /* XXX: This should already have been detected and flagged as an error */
    ERROR_R(r, "Unknown " CMD_REMOTEUSERMAP " \"%s\"", method_name);

    TRACE8_R(r, "%s: End",__func__);
} /* set_remote_user */

/**
 * Fix up environment for any delegated credentials.
 */
static int auth_vas_fixup(request_rec *r)
{
    const auth_vas_dir_config *dc;

    TRACE8_R(r, "%s: called", __func__);

    if (!is_our_auth_type(r)) {
        TRACE8_R(r, "%s: end", __func__);
	    return DECLINED;
    }

    dc = GET_DIR_CONFIG(r->per_dir_config);
    ASSERT(dc != NULL);

    export_cc(r);

    TRACE8_R(r, "%s: end", __func__);

    return OK;
} /* auth_vas_fixup */

/**
 * Creates and initialises a directory configuration structure.
 * This function is called when a &lt;Directory&gt; configuration
 * entry is encountered during the path walk.
 *   @param p memory pool to create configuration record from
 *   @param dirspec (unreliable)
 *   @return allocated storage for this module's per-directory config data
 */
static void * auth_vas_create_dir_config(apr_pool_t *p, char *dirspec)
{
    auth_vas_dir_config *conf = (auth_vas_dir_config *)apr_pcalloc(p, sizeof *conf);
    TRACE_P(p, "%s: called", __func__);
    if (conf != NULL) {
	conf->auth_negotiate = FLAG_UNSET;
	conf->negotiate_subnets = NULL;
	conf->auth_basic = FLAG_UNSET;
	conf->auth_authoritative = FLAG_UNSET;
	conf->export_delegated = FLAG_UNSET;
	conf->remote_user_map = "default";
	conf->remote_user_map_args = NULL;
	conf->use_suexec = FLAG_UNSET;
	conf->ntlm_error_document = NULL;
	conf->authz = FLAG_UNSET;
    conf->dir = dirspec;
    }
    return conf;
} /* auth_vas_create_dir_config */

/**
 * Merges a parent directory configuration with a base directory config.
 * Each field of a freshly allocated merged config is computed from
 * the base_conf and new_conf structures.
 *   @param p memory pool from which to allocate new merged config structure
 *   @param base_conf the parent directory's config structure
 *   @param new_conf the directory config being processed
 *   @return the resulting, merged config structure
 */
static void * auth_vas_merge_dir_config(apr_pool_t *p, void *base_conf, void *new_conf)
{
    auth_vas_dir_config *base_dc = (auth_vas_dir_config *)base_conf;
    auth_vas_dir_config *new_dc = (auth_vas_dir_config *)new_conf;
    auth_vas_dir_config *merged_dc;

    merged_dc = (auth_vas_dir_config *)apr_pcalloc(p, sizeof *merged_dc);
    MAV_LOG_P(APLOG_INFO, p,"%s: called", __func__);
    if (merged_dc != NULL) {
        merged_dc->auth_negotiate = FLAG_MERGE(base_dc->auth_negotiate, new_dc->auth_negotiate);
        merged_dc->auth_basic = FLAG_MERGE(base_dc->auth_basic, new_dc->auth_basic);
        merged_dc->auth_authoritative = FLAG_MERGE(base_dc->auth_authoritative, new_dc->auth_authoritative);
    	merged_dc->export_delegated = FLAG_MERGE(base_dc->export_delegated, new_dc->export_delegated);
        merged_dc->use_suexec = FLAG_MERGE(base_dc->use_suexec, new_dc->use_suexec);
        merged_dc->authz = FLAG_MERGE(base_dc->authz, new_dc->authz);
        if (new_dc->auth_negotiate == FLAG_UNSET)
	        merged_dc->negotiate_subnets = base_dc->negotiate_subnets;
        else /* Flag set */
	        merged_dc->negotiate_subnets = new_dc->negotiate_subnets;

    	if (strcasecmp(new_dc->remote_user_map, "default") != 0) {
	        merged_dc->remote_user_map = apr_pstrdup(p, new_dc->remote_user_map);
	        merged_dc->remote_user_map_args = apr_pstrdup(p, new_dc->remote_user_map_args);
    	} else {
	        merged_dc->remote_user_map = apr_pstrdup(p, base_dc->remote_user_map);
	        merged_dc->remote_user_map_args = apr_pstrdup(p, base_dc->remote_user_map_args);
    	}

        if (new_dc->auth_providers) {
            merged_dc->auth_providers = new_dc->auth_providers;
        } else if (base_dc->auth_providers) {
            merged_dc->auth_providers = base_dc->auth_providers;
        }

	    if (new_dc->ntlm_error_document) {
	        if (strcasecmp(new_dc->ntlm_error_document, "default") == 0)
    		    merged_dc->ntlm_error_document = NULL;
    	    else
	        	merged_dc->ntlm_error_document = apr_pstrdup(p, new_dc->ntlm_error_document);
    	} else if (base_dc->ntlm_error_document) {
	        /* Inherit. strdup is probably unnecessary */
	        merged_dc->ntlm_error_document = apr_pstrdup(p, base_dc->ntlm_error_document);
    	}
    }
    return (void *)merged_dc;
} /* auth_vas_merge_dir_config */

/**
 * Merges a parent server configuration with a base server configuration.
 * Each field of a freshly allocated merged config is computed from
 * the base_conf and new_conf structures.
 *   @param p memory pool from which to allocate new merged config structure
 *   @param base_conf the parent server's config structure
 *   @param new_conf the server config being processed
 *   @return the resulting, merged config structure
 */
static void *auth_vas_merge_server_config(apr_pool_t *p, void *base_conf, void *new_conf)
{
    TRACE_P(p, "%s Merging server configs", __func__);

    auth_vas_server_config *base_sc = (auth_vas_server_config *) base_conf;
    auth_vas_server_config *new_sc = (auth_vas_server_config *) new_conf;
    auth_vas_server_config *merged_sc;

    merged_sc = (auth_vas_server_config *) apr_pcalloc(p, sizeof *merged_sc);

    /*
     * Overwrite the server default of HTTP/, if it is NULL then we will ether
     * pick up the parents server setting, or reset it back to HTTP/. This will 
     * allow us to pick up the parents server setting if it was set and is not
     * using the default value.
    */
    new_sc->server_principal = NULL;

    TRACE_P(p, "%s: called", __func__);

    if (merged_sc != NULL) {
        if (new_sc->server_principal) {
            if (strcasecmp(new_sc->server_principal, "default") == 0)
                merged_sc->server_principal = DEFAULT_SERVER_PRINCIPAL;
            else
                merged_sc->server_principal = apr_pstrdup(p,
                        new_sc->server_principal);
        } else if (base_sc->server_principal) {
            merged_sc->server_principal = apr_pstrdup(p,
                    base_sc->server_principal);
        }

        if (new_sc->default_realm) {
            if (strcasecmp(new_sc->default_realm, "default") == 0)
                merged_sc->default_realm = NULL;
            else
                merged_sc->default_realm
                        = apr_pstrdup(p, new_sc->default_realm);
        } else if (base_sc->default_realm) {
            merged_sc->default_realm = apr_pstrdup(p, base_sc->default_realm);
        }

        if (new_sc->keytab_filename) {
            if (strcasecmp(new_sc->keytab_filename, "default") == 0)
                merged_sc->keytab_filename = NULL;
            else
                merged_sc->keytab_filename = apr_pstrdup(p,
                        new_sc->keytab_filename);
        } else if (base_sc->keytab_filename) {
            merged_sc->keytab_filename = apr_pstrdup(p,
                    base_sc->keytab_filename);
        }
    }

    return (void *) merged_sc;
} /* auth_vas_merge_server_config */

/** Passed an auth_vas_server_config pointer */
static apr_status_t auth_vas_server_config_destroy(void *data)
{
    auth_vas_server_config *sc = (auth_vas_server_config *)data;
    
    if (sc != NULL) {

	    if (sc->cache) {
	        auth_vas_cache_flush(sc->cache);
    	    sc->cache = NULL;
	    }
        
    	/* sc->default_realm is always handled by apache */
	    /* sc->keytab_filename is always handled by apache */

        if (sc->vas_serverid != NULL) {
            vas_id_free(sc->vas_ctx, sc->vas_serverid);
            sc->vas_serverid = NULL;
        }        
       
        if (sc->vas_ctx) {
            vas_ctx_free(sc->vas_ctx);
            sc->vas_ctx = NULL;            
        }
    }

    return OK;
} /* auth_vas_server_config_destroy */

/**
 * Creates and initialises a server configuration structure.
 * This function is called for each virtual host server at startup.
 *   @param p memory pool to create configuration record from
 *   @param s pointer to server being configured
 *   @return allocated storage for this module's per-directory config data
 */
static void * auth_vas_create_server_config(apr_pool_t *p, server_rec *s)
{
    auth_vas_server_config *sc;

    sc = (auth_vas_server_config *)apr_pcalloc(p, sizeof *sc);
    if (sc != NULL) {
	/* XXX Shouldn't we default to "HTTP/" + s->server_hostname ? */
	sc->server_principal = DEFAULT_SERVER_PRINCIPAL;
    }
    
    /* register our server config cleanup function */
    apr_pool_cleanup_register(p, sc, auth_vas_server_config_destroy, apr_pool_cleanup_null);
    
    TRACE_P(p, "%s (%s:%u)", __func__, s->server_hostname ? s->server_hostname : "<global>", s->port);
    return (void *)sc;
} /* auth_vas_create_server_config */

/*
 * Logs version information about this module.
 */
static void auth_vas_print_version(apr_pool_t *plog)
{
    MAV_LOG_P(APLOG_INFO, plog, "mod_auth_vas version %s, VAS %s", MODAUTHVAS_VERSION, vas_product_version(0, 0, 0));
} /* auth_vas_print_version */

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
static int auth_vas_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    server_rec *sp;

    ap_add_version_component(p, "mod_auth_vas4/" MODAUTHVAS_VERSION);

    /* Create a VAS context for each virtual host */
    for (sp = s; sp; sp = sp->next) {
    	auth_vas_server_init(p, sp);
    }

    return OK;
} /* auth_vas_post_config */

/**
 * Initialises per-process mutexes.
 * This function is called when the server forks a new process.
 * We initialise the process-wide VAS mutex used to
 * control exclusive access to the thread-unsafe VAS
 * library.
 */
static void auth_vas_child_init(apr_pool_t *p, server_rec *s)
{
    int r;
    r = apr_thread_mutex_create(&auth_vas_libvas_mutex, APR_THREAD_MUTEX_UNNESTED, p);

    if (r != OK) {
	    MAV_LOG_SERRNO(APLOG_ERR, s, r, "apr_thread_mutex_create");
    	auth_vas_libvas_mutex = NULL;
    }
} /* auth_vas_child_init */

/**
 *
 *
 *
 *
 */
static const char *add_authn_provider(cmd_parms *cmd, void *config, const char *arg)
{
    TRACE8_P( cmd->pool, "%s: called", __func__); 

    auth_vas_dir_config *conf = (auth_vas_dir_config *)config;
    authn_provider_list *newp;

    newp = apr_pcalloc(cmd->pool, sizeof(authn_provider_list));
    newp->provider_name = arg;

    MAV_LOG_P(APLOG_DEBUG, cmd->pool, "%s: Authn provider %s", __func__, arg);

    /* lookup and cache the actual provider now */
    newp->provider = ap_lookup_provider(AUTHN_PROVIDER_GROUP,
                                        newp->provider_name,
                                        AUTHN_PROVIDER_VERSION);

    if (newp->provider == NULL) {
        /* by the time they use it, the provider should be loaded and registered with us. */
        DEBUG_P(cmd->pool, "%s: Unknown Authn provider: %s", __func__, newp->provider_name);
        TRACE8_P(cmd->pool, "%s: end", __func__);
        return apr_psprintf(cmd->pool, "Unknown Authn provider: %s", newp->provider_name);
    }

    if (!newp->provider->check_password) {
        /* if it doesn't provide the appropriate function, reject it */
        DEBUG_P(cmd->pool, "%s: The '%s' Authn provider doesn't support basic vas Authentication", __func__, newp->provider_name);
        TRACE8_P(cmd->pool, "%s: end", __func__);
        return apr_psprintf(cmd->pool, "The '%s' Authn provider doesn't support basic VAS Authentication", newp->provider_name);
    }

    /* Add it to the list now. */
    if (!conf->auth_providers) {
        DEBUG_P(cmd->pool, "%s: Added Authn provider %s to list of Vas providers", __func__, newp->provider_name);
        conf->auth_providers = newp;
    }
    else {
        authn_provider_list *last = conf->auth_providers;

        while (last->next) {
            TRACE1_P(cmd->pool, "%s: Last provider %s", __func__, last->provider_name);
            last = last->next;
        }
        last->next = newp;
        DEBUG_P(cmd->pool, "%s: dded Authn provider <%s> to list of VAS providers", __func__, last->next->provider_name);
    }
    TRACE8_P(cmd->pool, "%s: end", __func__);
    return NULL;
} /* add_authn_provider */

/**
 *
 * Checks if the authenticated user appears in a UNIX group
 * Assumes the server config has been initialised.
 *   @param r The authenticated request
 *   @param groupname The name of the UNIX group to check membership of
 *   @param pwd  The passwd struct that containes the users information
 *   @return AUTHZ_GRANTED if group contains user, otherwise AUTHZ__...
 */
static authz_status check_unixgroup_membership(request_rec *r, const char *groupname, struct passwd **pwd)
{
    authz_status    result  = AUTHZ_DENIED;
    int err;
    struct group    *gr;
    char            **sp;
    struct passwd *pw = *pwd;

    ASSERT(r != NULL);

    TRACE8_R(r, "%s: called", __func__);

    if(!groupname) {
        TRACE8_R(r, "%s: end", __func__);
        return AUTHZ_DENIED;
    }
    if(!pw) {
        TRACE8_R(r, "%s: end", __func__);
        return AUTHZ_DENIED;
    }

    /* 
     * Obtain the list of users in the unix group.
     * We deliberately cause a 500 error if the group is not found, because
     * specifying a non-existent group in the config file is a configuration
     * (internal) error, not a user error.
     */
#if HAVE_GETGRNAM_R
    {
        char *buf;
        size_t buflen = 16384;  /* GETGR_R_SIZE_MAX is not portable :( */
        struct group *gbuf;

        gbuf = (struct group *)apr_palloc(r->pool,
                sizeof (struct group));
        buf = apr_palloc(r->pool, buflen);
        if (gbuf == NULL || buf == NULL) {
            /* apr_vformatter has %pS for apr_size_t since APR 1.3.0, but that
             * is way too new so we cast size_t to unsigned long */
            MAV_LOG_RERRNO(APLOG_ERR, r, APR_ENOMEM, "%s: apr_palloc (%lu + %lu)", __func__, (unsigned long)sizeof(struct group), (unsigned long)buflen);
            UNLOCK_VAS(r);
            TRACE8_R(r, "%s: end", __func__);
            return AUTHZ_GENERAL_ERROR;
        }
        if ((err = getgrnam_r(groupname, gbuf, buf, buflen, &gr))) {
            WARN_R(r, "%s: getgrnam_r: cannot access group '%s': %s", __func__, groupname, sensible_strerror_r(err, buf, buflen));
            UNLOCK_VAS(r);
            TRACE8_R(r, "%s: end", __func__);
            return AUTHZ_GENERAL_ERROR;
        }
    }
#else /* !HAVE_GETGRNAM_R */
    errno = 0;
    gr = getgrnam(groupname);
    if (!gr && errno) {
        WARN_R(r, "%s: getgrnam: cannot access group '%s'", __func__,  groupname);
        UNLOCK_VAS(r);
        TRACE8_R(r, "%s: end", __func__);
        return AUTHZ_GENERAL_ERROR;
    }
#endif /* !HAVE_GETGRNAM_R */
    if (!gr) {
        WARN_R(r, "%s: No such group '%s'", __func__, groupname);
        UNLOCK_VAS(r);
        TRACE8_R(r, "%s: end", __func__);
        return AUTHZ_DENIED;
    }

    /* Check if user's primary GID matches */
    if (pw->pw_gid == gr->gr_gid) {
        TRACE1_R(r, "%s: user %s primary group matches %s", __func__, RUSER(r), groupname);
        UNLOCK_VAS(r);
        TRACE8_R(r, "%s: end", __func__);
        return AUTHZ_GRANTED;
    }

    /* Search the group list */
    for (sp = gr->gr_mem; sp && *sp; sp++) {
        if (strcmp(pw->pw_name, *sp) == 0) {
            TRACE1_R(r, "%s: user %s is a member of the unix-group %s", __func__, RUSER(r), groupname);
            UNLOCK_VAS(r);
            TRACE8_R(r, "%s: end", __func__);
            return AUTHZ_GRANTED;
        }
    } 

    TRACE8_R(r, "%s: end", __func__);
    return result;
} /* check_unixgroup_membership */

/**
 * Authorizes users based on Require unix-group
 * @param r The authenticated request
 *   @param require_args
 *   @param parsed_require_args
 *   @return AUTHZ_GRANTED if group contains user, otherwise AUTHZ__...
 */
static authz_status authz_vas_unixgroup_check_authorization(request_rec *r, const char *require_args, const void *parsed_require_args)
{
    vas_err_t               vaserr;
    int                     err;
    authz_status            result = AUTHZ_DENIED;
    auth_vas_server_config  *sc;
    auth_vas_dir_config     *dc;
    auth_vas_rnote          *rnote;
    struct passwd           *pw =      NULL;

    ASSERT(r != NULL);
    TRACE8_R(r, "%s: called", __func__);

    dc = GET_DIR_CONFIG(r->per_dir_config);

    if ( !USING_MAV_AUTHZ(dc))
    {
        TRACE8_R(r, "%s: end", __func__);
        return DECLINED;
    }

    if (!r->user) {
        TRACE8_R(r, "%s: end", __func__);
        return AUTHZ_DENIED_NO_USER;
    }

    TRACE1_R(r, "%s: user=%s, authtype=%s", __func__, RUSER(r), RAUTHTYPE(r));

    sc = GET_SERVER_CONFIG(r->server->module_config);
    ASSERT(sc != NULL);
    ASSERT(sc->vas_ctx != NULL);

    if ((err = LOCK_VAS(r))) {
        ERROR_R(r, "%s: unable to acquire lock", __func__);
        TRACE8_R(r, "%s: end", __func__);
        return err;
    }

    TRACE1_R(r, "%s: getting rnote", __func__);

    if ((err = rnote_get(sc, r, &rnote))) {
        TRACE1_R(r, "%s: failed to get rnote", __func__);
        UNLOCK_VAS(r);
        TRACE8_R(r, "%s: end", __func__);
        return err;
    }

    TRACE1_R(r, "%s: seting user object",__func__);

    if ((err = set_user_obj(r))) {
        TRACE1_R(r, "%s: failed to set user object", __func__);
        UNLOCK_VAS(r);
        TRACE8_R(r, "%s: end",__func__);
        return err;
    }

    /* Determine the user's unix name */
    vaserr = vas_user_get_pwinfo(sc->vas_ctx, NULL, rnote->vas_user_obj, &pw);
    vas_user_t * vas_user_obj = (vas_user_t*)auth_vas_user_get_vas_user_obj(rnote->mav_user);

    if(!vas_user_obj){
        TRACE1_R(r, "%s: vas_user_obj is not set for user %s", __func__, auth_vas_user_get_name(rnote->mav_user));
    }

    vaserr = vas_user_get_pwinfo(sc->vas_ctx, NULL, (vas_user_t*)auth_vas_user_get_vas_user_obj(rnote->mav_user), &pw);
    if (vaserr == VAS_ERR_NOT_FOUND) {
        /* User does not map to a unix user, so cannot be part of a group */
        TRACE1_R(r, "%s: User does not map to a unix user, so cannot be part of a unix-group", __func__);
        UNLOCK_VAS(r);
        if(pw) free(pw);
        TRACE8_R(r, "%s: end",__func__);
        return AUTHZ_DENIED;
    }
    if (vaserr != VAS_ERR_SUCCESS) {
        ERROR_R(r, "%s: vas_user_get_pwinfo(): %s", __func__, vas_err_get_string(sc->vas_ctx, 1));
        UNLOCK_VAS(r);
        if(pw) free(pw);
        TRACE8_R(r, "%s: end",__func__);
        return AUTHZ_GENERAL_ERROR;
    }

    const char* group_names = require_args;
    char *group_name;

    DEBUG_R(r, "%s: require unix-group: testing for group membership in \"%s\"", __func__, group_names);

    while((group_name = ap_getword_conf(r->pool, &group_names)) && group_name[0]) {
        TRACE1_R(r, "%s: checking if user is member of group %s", __func__, group_name);
        result = check_unixgroup_membership(r, group_name, &pw);
        if( result == AUTHZ_GRANTED ) {
            TRACE1_R(r, "%s: user %s is a member of group %s", __func__, auth_vas_user_get_principal_name(rnote->mav_user), group_name);
            break;
        }
        TRACE2_R(r, "%s: %s is not a member of %s", __func__, auth_vas_user_get_principal_name(rnote->mav_user), group_name);
    }

    if(result != AUTHZ_GRANTED) {
        DEBUG_R(r, "%s: %s is not a member of any require unix-group \"%s\"", __func__, auth_vas_user_get_principal_name(rnote->mav_user), require_args);
    }
    UNLOCK_VAS(r);
    if(pw) free(pw);
    DEBUG_R(r, "%s: require unix-group-> %s", __func__, result == AUTHZ_GRANTED ? "AUTHZ_GRANTED" : "AUTHZ_DENIED");
    TRACE1_R(r, "%s: returned %i", __func__, result);
    TRACE8_R(r, "%s: end",__func__);
    return result;

} /* authz_vas_unixgroup_check_authorization */

/**
 * Authorizes users based on Require ad-group
 * @param r The authenticated request
 *   @param require_args
 *   @param parsed_require_args
 *   @return AUTHZ_GRANTED if group contains user, otherwise AUTHZ__...
 */
static authz_status authz_vas_adgroup_check_authorization(request_rec *r, const char *require_args, const void *parsed_require_args)
{

    vas_err_t               vaserr;
    int                     err = AUTHZ_DENIED;
    authz_status            result = AUTHZ_DENIED;
    auth_vas_server_config  *sc;
    auth_vas_dir_config     *dc;
    auth_vas_rnote          *rnote;

    ASSERT(r != NULL);

    TRACE8_R(r, "%s: called", __func__);

    dc = GET_DIR_CONFIG(r->per_dir_config);

    if ( !USING_MAV_AUTHZ(dc))
    {
        TRACE8_R(r, "%s: end", __func__);
        return DECLINED;
    }

    if (!r->user) {
        TRACE8_R(r, "%s: end", __func__);
        return AUTHZ_DENIED_NO_USER;
    }

    TRACE1_R(r, "%s: user=%s, authtype=%s", __func__, RUSER(r), RAUTHTYPE(r));

    sc = GET_SERVER_CONFIG(r->server->module_config);
    ASSERT(sc != NULL);
    ASSERT(sc->vas_ctx != NULL);

    if ((err = LOCK_VAS(r))) {
        ERROR_R(r, "%s: unable to acquire lock", __func__);
        TRACE8_R(r, "%s: end", __func__);
        return err;
    }

    if ((err = rnote_get(sc, r, &rnote))) {
        TRACE1_R(r, "%s: failed to get rnote", __func__);
        UNLOCK_VAS(r);
        TRACE8_R(r, "%s: end", __func__);
        return err;
    }

#define VASVER ((VAS_API_VERSION_MAJOR * 10000) + \
                (VAS_API_VERSION_MINOR * 100)   + \
                VAS_API_VERSION_MICRO)
#if VASVER < 40100
#   define vas_auth_check_client_membership(c,i,a,n) \
        DEBUG_R(r, "%s: i is %s", __func__, i ? "set" : "not set"); \
        vas_auth_is_client_member(c,a,n)
#endif
    const char* group_names = require_args;
    char *group_name;

    DEBUG_R(r, "%s: require ad-group: testing for group membership in \"%s\"", __func__, group_names);

    while((group_name = ap_getword_conf(r->pool, &group_names)) && group_name[0]) {
        TRACE1_R(r, "%s: checking if user is member of group %s", __func__, group_name);
        vaserr = auth_vas_is_user_in_group(rnote->mav_user, group_name);
        if(vaserr == VAS_ERR_SUCCESS) {
            TRACE1_R(r, "%s: user %s is a member of group %s", __func__, auth_vas_user_get_principal_name(rnote->mav_user), group_name);
            result = AUTHZ_GRANTED;
            break;
        }
        else if(vaserr == VAS_ERR_EXISTS) {
            WARN_R(r, "%s: group %s does not exist", __func__, group_name);
            result = AUTHZ_DENIED;
        }else if(vaserr == VAS_ERR_NOT_FOUND) {
            TRACE2_R(r, "%s: %s is not a member of %s", __func__, auth_vas_user_get_principal_name(rnote->mav_user), group_name);
            result = AUTHZ_DENIED;
        }else { /* other type of error */
            ERROR_R(r, "%s: fatal vas error: %s", __func__, vas_err_get_string(sc->vas_ctx, 1));
            result = AUTHZ_GENERAL_ERROR;
            break;
        }
    }

    if(result != AUTHZ_GRANTED) {
        DEBUG_R(r, "%s: %s is not a member of any require ad-group \"%s\"", __func__, auth_vas_user_get_principal_name(rnote->mav_user), require_args);
    }

    UNLOCK_VAS(r);
    DEBUG_R(r, "%s: require ad-user -> %s", __func__, result == AUTHZ_GRANTED ? "AUTHZ_GRANTED" : "AUTHZ_DENIED");
    TRACE1_R(r, "%s: returned %i", __func__, result);
    TRACE8_R(r, "%s: end",__func__);
    return result;

} /* authz_vas_adgroup_check_authorization */

/**
 * Authorizes users based on Require ad-dn
 * @param r The authenticated request
 *   @param require_args
 *   @param parsed_require_args
 *   @return AUTHZ_GRANTED if containers contains users dn, otherwise AUTHZ__...
 */
static authz_status authz_vas_adcontainer_check_authorization(request_rec *r, const char *require_args, const void *parsed_require_args)
{
    vas_err_t               vaserr;
    int                     err = AUTHZ_DENIED;
    authz_status            result = AUTHZ_DENIED;
    auth_vas_server_config  *sc = NULL;
    auth_vas_dir_config     *dc = NULL;
    auth_vas_rnote          *rnote = NULL;
//    vas_user_t              *vasuser = NULL;
    char                    *dn = NULL;

    ASSERT(r != NULL);

    TRACE8_R(r, "%s: called", __func__);

    dc = GET_DIR_CONFIG(r->per_dir_config);

    if ( !USING_MAV_AUTHZ(dc))
    {
        TRACE8_R(r, "%s: end", __func__);
        return DECLINED;
    }

    if (!r->user) {
        TRACE8_R(r, "%s: end", __func__);
        return AUTHZ_DENIED_NO_USER;
    }

    TRACE1_R(r, "%s: user=%s, authtype=%s", __func__, RUSER(r), RAUTHTYPE(r));

    sc = GET_SERVER_CONFIG(r->server->module_config);
    ASSERT(sc != NULL);
    ASSERT(sc->vas_ctx != NULL);

    if ((err = LOCK_VAS(r))) {
        ERROR_R(r, "%s: unable to acquire lock", __func__);
        TRACE8_R(r, "%s: end", __func__);
        return err;
    }

    if ((err = rnote_get(sc, r, &rnote))) {
        TRACE1_R(r, "%s: failed to get rnote", __func__);
        UNLOCK_VAS(r);
        TRACE8_R(r, "%s: end", __func__);
        return err;
    }

    if ((vaserr = vas_user_get_dn(sc->vas_ctx, sc->vas_serverid, (vas_user_t*)auth_vas_user_get_vas_user_obj(rnote->mav_user), &dn )) != VAS_ERR_SUCCESS ) {
        ERROR_R(r, "%s: error getting user's distinguishedName: %d, %s", __func__, vaserr, vas_err_get_string(sc->vas_ctx, 1));
        RETURN(AUTHZ_DENIED);
    }
    
    const char* container_names = require_args;
    char *container_name;

    DEBUG_R(r, "%s: require ad-dn: testing if users dn is in containers \"%s\"", __func__, container_names);

    while((container_name = ap_getword_conf(r->pool, &container_names)) && container_name[0]) {
        TRACE1_R(r, "%s: checking if users dn is in container \"%s\"", __func__, container_name);
        if (dn_in_container(dn, container_name)) {
            TRACE1_R(r, "%s: users dn \"%s\" is in container \"%s\"", __func__, dn, container_name);
            result = AUTHZ_GRANTED;
            break;
        } 
        TRACE2_R(r, "%s: user dn \"%s\" is NOT in container \"%s\"", __func__, dn, container_name);
    }

finish:
    if(result != AUTHZ_GRANTED)
    {
        DEBUG_R(r, "%s: user dn \"%s\" is not in any of the require ad-dn containers \"%s\"", __func__, dn, require_args);
    }   

    if (dn)      free(dn);

    UNLOCK_VAS(r);

    DEBUG_R(r, "%s: require ad-dn-> %s", __func__, result == AUTHZ_GRANTED ? "AUTHZ_GRANTED" : "AUTHZ_DENIED");
    TRACE1_R(r, "%s: returned %i", __func__, result);
    TRACE8_R(r, "%s: end",__func__);
    return result;

} /* authz_vas_adcontainer_check_authorization */

static const authn_provider authn_vas_provider = {
    &authn_vas_check_password,
    NULL /**< get_realm_hash, for Digest auth */
};

static const authz_provider authz_vas_unixgroup_provider =
{
    &authz_vas_unixgroup_check_authorization,
    NULL,
};

static const authz_provider authz_vas_adgroup_provider =
{
    &authz_vas_adgroup_check_authorization,
    NULL,
};

static const authz_provider authz_vas_adcontainer_provider =
{
    &authz_vas_adcontainer_check_authorization,
    NULL,
};

/*
 * Module linkage structures.
 * Apache uses this at load time to discover the module entry points.
 */

/**
 * Registers this module's hook functions into Apache2 runtime hook lists.
 * This function is called immediately after our shared library image
 * has been loaded into memory.
 */
static void auth_vas_register_hooks(apr_pool_t *p)
{
    MAV_LOG_P(APLOG_TRACE1, p, "Registering auth_vas hooks");

    auth_vas_print_version(p);

    /* Register authn provider
     * The version argument is the interface version, not the module version */
    ap_register_auth_provider(p, AUTHN_PROVIDER_GROUP, DEFAULT_AUTHN_PROVIDER,
                              AUTHN_PROVIDER_VERSION,
                              &authn_vas_provider,
                              AP_AUTH_INTERNAL_PER_CONF);

    /* Register authz providers */
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "unix-group",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_vas_unixgroup_provider,
                              AP_AUTH_INTERNAL_PER_CONF);

    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "ad-group",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_vas_adgroup_provider,
                              AP_AUTH_INTERNAL_PER_CONF);

    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "ad-dn",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_vas_adcontainer_provider,
                              AP_AUTH_INTERNAL_PER_CONF);

    ap_hook_check_authn(authenticate_gss_user, NULL, NULL, APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_CONF);
    ap_hook_post_config(auth_vas_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(auth_vas_child_init, NULL, NULL, APR_HOOK_MIDDLE);

#if HAVE_UNIX_SUEXEC
    ap_hook_get_suexec_identity(auth_vas_suexec, NULL, NULL, APR_HOOK_FIRST);
#endif
    ap_hook_fixups(auth_vas_fixup, NULL, NULL, APR_HOOK_MIDDLE);

    MAV_LOG_P(APLOG_TRACE1, p, "hooks registered");
}

/*
 * This Apache2 module's public interface
 */
AP_DECLARE_MODULE(auth_vas4) =
{
    STANDARD20_MODULE_STUFF,
    auth_vas_create_dir_config,		/* create_dir_config */
    auth_vas_merge_dir_config,		/* merge_dir_config */
    auth_vas_create_server_config,	/* create_server_config */
    auth_vas_merge_server_config,	/* merge_server_config */
    auth_vas_cmds,                  /* cmds */
    auth_vas_register_hooks         /* register_hooks */
};

/*
 * Prints a message with a GSS error code to traceLogFileName if TRACE_DEBUG is defined otherwise prints to stderr
 */
void print_gss_err(const char *prefix, OM_uint32 major_status, OM_uint32 minor_status)
{
    OM_uint32       majErr, minErr  = 0;
    OM_uint32       message_context = 0;
    gss_buffer_desc status_string   = GSS_C_EMPTY_BUFFER;

    if ( GSS_ERROR(major_status) || GSS_SUPPLEMENTARY_INFO(major_status) ) {
        /* First process the Major status code */
        do {
            /* Get the status string associated
               with the Major (GSS=API) status code */
            majErr = gss_display_status( &minErr, major_status, GSS_C_GSS_CODE, GSS_C_NO_OID, &message_context, &status_string );
            /* Print the status string */
            #ifdef TRACE_DEBUG
                tfprintf("%s: %.*s\n", prefix, (int)status_string.length, (char*)status_string.value );
            #else
                fprintf(stderr, "%s: %.*s\n", prefix, (int)status_string.length, (char*)status_string.value );
            #endif
            /* Free the status string buffer */
            gss_release_buffer( &minErr, &status_string );
        } while( message_context && !GSS_ERROR( majErr ) );

        /* Then process the Minor status code */
        do {
            /* Get the status string associated
               with the Minor (mechanism) status code */
            majErr = gss_display_status( &minErr, minor_status, GSS_C_MECH_CODE, GSS_C_NO_OID, &message_context, &status_string );
            /* Print the status string */
            #ifdef TRACE_DEBUG
                tfprintf(": %.*s\n", (int)status_string.length, (char*)status_string.value );
            #else
                fprintf(stderr, ": %.*s\n", (int)status_string.length, (char*)status_string.value );
            #endif
            /* Free the status string buffer */
            gss_release_buffer( &minErr, &status_string );
        } while( message_context && !GSS_ERROR( majErr ) );
    }
}
