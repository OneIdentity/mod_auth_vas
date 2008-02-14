/*
 * mod_auth_vas: VAS authentication module for Apache.
 *
 *   Copyright 2008 Quest Software, Inc.
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
 *   Authors:
 *     Ted Percival <ted.percival@quest.com>
 *
 *   @file
 *   A class and associated function for manipulating reference-counted users
 *   which are stored in a cache for performance.
 *
 *   The cache is based around the idea of lots of users authenticating to a
 *   single service - as such each cache object is associated with a single vas
 *   server identity. This simplifies caching by maintaining a one-to-many
 *   (service-to-user) association and should fit most authentication use cases.
 *   In particular it matches the mod_auth_vas use case ;)
 *
 *   Major differences from the libvas API are:
 *   - Users are represented by an auth_vas_user rather than a vas_id_t.
 *   - Credential establishment and authentication are done in one step, by
 *     auth_vas_user_authenticate.
 *   - User objects are reference counted and shared. Access to them should be
 *     locked.
 *
 *   Functions are not thread safe. Be careful.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "compat.h"
#include "user.h"
#include "cache.h"

/**
 * A cacheable user object.
 *
 * Can also represent a service (really, anything that can be represented by
 * a vas_id_t -- anything with a userPrincipalName).
 *
 * All vas_* objects are associated with the cache's vas_ctx_t, so libvas
 * functions are called using user->cache->vas_ctx as the vas_ctx_t.
 */
struct auth_vas_user {
    unsigned int	refcount;
    auth_vas_cache	*cache;
    vas_id_t	*vas_id;
    vas_user_t	*vas_user;
    vas_auth_t	*vas_authctx; /**< To be set by vas_gss_auth() or vas_auth() */
    char	*username; /**< As provided by the client */
    char	*principal_name; /**< Krb5 userPrincipalName */
    char	*password;
    int	credflags; /**< Flags used when establishing credentials */
};

/**
 * Determine whether the given user is in a particular group.
 *
 * @param user User to check. Must not be NULL.
 *
 * @param group Group name to check. Must not be NULL.
 *
 * @return VAS_ERR_SUCCESS if the user is a member of the group,
 * VAS_ERR_NOT_FOUND if the user is not a member, VAS_ERR_INVALID_PARAM if the
 * user has no auth context (no error is logged), or any other error code that
 * vas_auth_check_client_membership may return.
 *
 * @sa vas_auth_check_client_membership
 */
vas_err_t
auth_vas_is_user_in_group(auth_vas_user *user, const char *group) {
    vas_ctx_t *vasctx;

    if (user->vas_authctx == NULL)
	return VAS_ERR_INVALID_PARAM;

    vasctx = auth_vas_cache_get_vasctx(user->cache);

    /* No caching, simply a pass-through because
     * vas_auth_check_client_membership does not hit the network. */

    return vas_auth_check_client_membership(vasctx, user->vas_id,
	    user->vas_authctx, group);
}

#define RETURN(x) do { \
    result = (x); \
    goto finish; \
} while (0)

/**
 * Get (and cache) the auth_vas_user for the given username.
 */
vas_err_t
auth_vas_user_alloc(
	auth_vas_cache *cache,
	const char *username,
	auth_vas_user **outuser)
{
    vas_err_t result; /* This function's return code. */
    vas_err_t vaserr; /* Temp storage */
    vas_ctx_t *vasctx; /* Don't free */
    vas_id_t *local_id;
    auth_vas_user *cached_user;

    vasctx = auth_vas_cache_get_vasctx(cache);

    /* User IDs are only dependent on the machine's default_realm, which will
     * not change within the lifetime of the process, so we only need to
     * check that the username matches.
     */
    cached_user = (auth_vas_user*)auth_vas_cache_get(cache, username);

    if (!cached_user) {
	char *upn;

	vaserr = vas_id_alloc(vasctx, username, &local_id);
	if (vaserr)
	    RETURN(vaserr);

	vaserr = vas_id_get_name(vasctx, local_id, &upn, NULL);
	if (vaserr) {
	    /* We'd better fail the whole function. */
	    vas_id_free(vasctx, local_id);
	    RETURN(vaserr);
	}

	cached_user = calloc(1, sizeof(*cached_user));
	cached_user->cache = cache;
	cached_user->username = strdup(username);
	cached_user->vas_id = local_id;
	cached_user->principal_name = upn;

	/* Cache refs the user object for itself */
	auth_vas_cache_insert(cache, cached_user->username, cached_user);
    }

    /* Success */
    auth_vas_user_ref(cached_user); /* For the caller */
    *outuser = cached_user;

    RETURN(VAS_ERR_SUCCESS);

finish:
    return result;
}

/**
 * Sets the user's vas_auth state based on GSS authentication.
 * If the cached user already has a vas_auth state then the existing one is
 * kept. Whether an existing cached vas_auth context is used or whether a new
 * one is derived from the given GSS authentication parameters is transparent
 * to the caller.
 *
 * Based on vas_gss_auth, and has the same return codes.
 */
vas_err_t
auth_vas_user_use_gss_result(
	auth_vas_user *user,
	gss_cred_id_t cred,
	gss_ctx_id_t context)
{
    vas_err_t vaserr;
    vas_ctx_t *vasctx;

    if (user->vas_authctx) /* cached */
	return VAS_ERR_SUCCESS;

    vasctx = auth_vas_cache_get_vasctx(user->cache);

    vaserr = vas_gss_auth(vasctx, cred, context, &user->vas_authctx);
    if (vaserr)
	user->vas_authctx = NULL; /* ensure */

    return vaserr;
}

/**
 * Get a vas_user_t for the given auth_vas_user.
 * None of the things we use a vas_user_t for hit the network, so there's no
 * need to cache or share the user object. This is a pass-through for
 * vas_user_init.
 *
 * The result must be freed by the caller using vas_user_free().
 */
vas_err_t
auth_vas_user_get_vas_user(const auth_vas_user *avuser, vas_user_t **vasuserp)
{
    vas_ctx_t *vasctx;
    vas_id_t *serverid;

    vasctx = auth_vas_cache_get_vasctx(avuser->cache);
    serverid = auth_vas_cache_get_serverid(avuser->cache);

    /* Use username instead of principal_name because any other name is
     * susceptible to failure when username-attr-name is not userPrincipalName.
     */
    return vas_user_init(vasctx, serverid, avuser->username, 0, vasuserp);
}

/**
 * Get the user's username, as they provided it.
 * Generally you should use this for any libvas object initialisations instead
 * of the userPrincipalName (auth_vas_user_get_principal_name), because
 * usernames are resolved according to username-attr-name which is not
 * necessarily the userPrincipalName.
 */
const char *
auth_vas_user_get_name(const auth_vas_user *user)
{
    return user->username;
}

/**
 * Get the user's userPrincipalName.
 * Generally you should use auth_vas_user_get_name for any libvas object
 * initialisations instead of this, because
 * usernames are resolved according to username-attr-name which is not
 * necessarily the userPrincipalName.
 */
const char *
auth_vas_user_get_principal_name(const auth_vas_user *user)
{
    return user->principal_name;
}

/**
 * Increments the reference count on the given user object.
 *
 * This function is not thread-safe.
 */
void
auth_vas_user_ref(auth_vas_user *user) {
    ++user->refcount;
}

/**
 * Decrements the reference count on the given user object.
 * When the reference count reaches zero, the object is freed.
 *
 * This function is not thread-safe.
 */
void
auth_vas_user_unref(auth_vas_user *user) {

    ASSERT(user->refcount > 0);

    --user->refcount;

    if (user->refcount == 0) {
	vas_ctx_t *vasctx = auth_vas_cache_get_vasctx(user->cache);

	if (user->principal_name)
	    free(user->principal_name);

	if (user->username)
	    free(user->username);

	if (user->password)
	    free(user->password);

	if (user->vas_authctx)
	    vas_auth_free(vasctx, user->vas_authctx);

	if (user->vas_user)
	    vas_user_free(vasctx, user->vas_user);

	if (user->vas_id)
	    vas_id_free(vasctx, user->vas_id);

	free(user);
    }
}

/**
 * Establishes credentials for the given user with the given password and
 * authenticates them (using the cache's server ID). This is effectively the
 * combination of vas_id_establish_cred_password and vas_auth.
 *
 * This function is not thread-safe.
 *
 * @return VAS_ERR_SUCCESS if the password was valid, or nonzero on failure.
 *         Returns VAS_ERR_FAILURE if the password does not match the cached
 *         password, whereas real libvas would return VAS_ERR_KRB5 and set
 *         the error state.
 *
 * @see vas_id_establish_cred_password, vas_auth
 */
vas_err_t
auth_vas_user_authenticate(
	auth_vas_user *user,
	int credflags,
	const char *password)
{
    vas_err_t result; /* Our return code */
    vas_err_t vaserr; /* Temp storage */
    vas_ctx_t *vasctx;
    vas_id_t *serverid;

    vasctx = auth_vas_cache_get_vasctx(user->cache);
    serverid = auth_vas_cache_get_serverid(user->cache);

    if (credflags == user->credflags && user->password != NULL) {
	/* We already know the user's password */
	if (strcmp(user->password, password) == 0)
	    RETURN(VAS_ERR_SUCCESS);
	else
	    RETURN(VAS_ERR_FAILURE);
    }
    
    if (user->password) {
	/* Avoid leaving user passwords in memory. */
	memset(user->password, '\0', strlen(user->password));
	free(user->password);
	user->password = NULL;
    }

    /* Do a real VAS lookup. This causes Kerberos traffic (TGS-REQ, TGS-REP) */
    vaserr = vas_id_establish_cred_password(vasctx, user->vas_id, credflags,
	    password);
    if (vaserr)
	RETURN(vaserr);

    /* Successfully authenticated. Save the auth info */
    user->password = strdup(password);
    user->credflags = credflags;

    /* Authenticate the user to our service. Causes Kerberos traffic. */
    vaserr = vas_auth(vasctx, user->vas_id, serverid, &user->vas_authctx);
    if (vaserr) {
	user->vas_authctx = NULL; /* ensure */
	RETURN(vaserr);
    }

    RETURN(VAS_ERR_SUCCESS);

finish:
    return result;
}

/* vim: ts=8 sw=4 noet tw=80
 */
