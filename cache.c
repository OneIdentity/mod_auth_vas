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
 *   Authors:
 *     Ted Percival <ted.percival@quest.com>
 *
 *   @file
 *   Implements a cache of VAS-related authentication information.
 *
 *   The cache is based around the idea of lots of users authenticating to a
 *   single service - as such each cache object is associated with a single vas
 *   server identity. This simplifies caching by maintaining a one-to-many
 *   (service-to-user) association and should fit most authentication use cases.
 *   In particular it matches the mod_auth_vas use case ;)
 *
 *   The API is vaguely similar to the libvas API so it should be easy to adapt
 *   to, the major differences are:
 *   - Users are represented by an auth_vas_user rather than a vas_id_t.
 *   - Credential establishment and authentication are done in one step, by
 *     auth_vas_user_authenticate.
 *   - User objects are reference counted and shared. Access to them should be
 *     locked, the auth_vas_cache_*lock functions can be used for this purpose.
 *
 *   Most functions are not thread safe. Be careful.
 *
 */

#include "cache.h"

/**
 * A cacheable user object.
 *
 * Can also represent a service (really, anything that can be represented by
 * a vas_id_t -- anything with a userPrincipalName).
 *
 * Operations on the user object are generally NOT THREAD-SAFE so the caller
 * must handle locking.
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
    char	*password;
    int	credflags; /**< Flags used when establishing credentials */
};

/**
 * Per-server structure for caching remote user authentication information.
 */
struct auth_vas_cache {
    /** For locking the cache. */
    apr_thread_mutex_t	*mutex;

    /** The pool to allocate cached user data from. It is destroyed when the
     * cache is destroyed. */
    apr_pool_t	*pool;

    /** Table of auth_vas_user, keyed by username. The username string in the
     * auth_vas_user is used as the key. */
    apr_hash_t	*users;

    /** Convenience pointer to the vas_ctx owned by the server_rec. Do not
     * free. */
    vas_ctx_t	*vas_ctx;

    /** The server ID that all clients will be authenticated to, owned by the
     * server_rec. Do not free. */
    vas_id_t	*vas_serverid;
};

/**
 * Creates a new auth_vas_cache, allocated from the server's memory pool
 * because the vas_ctx_t must be the same. (The server doesn't actually have its
 * own memory pool, but its parent process does. We use that one.)
 */
auth_vas_cache *
auth_vas_cache_new(server_rec *server)
{
    apr_status_t *aprerr;
    auth_vas_cache *cache = NULL;
    auth_vas_server_config *serverconf;

    /* Should we allocate the cache out of the cache subpool instead?
     * Only necessary if caches are destroyed more frequently than processes
     * exit. */
    cache = apr_pcalloc(server->process->pool, sizeof(*cache));
    if (!cache) {
	LOG_P_ERROR(APLOG_ERR, 0, server->process->pool,
		"Failed to allocate cache structure");
	return NULL;
    }

    aprerr = apr_pool_create(&cache->pool, server->process->pool);
    if (aprerr) {
	LOG_P_ERROR(APLOG_ERR, aprerr, server->process->pool,
		"Failed to create cache memory pool");
	return NULL;
    }

    aprerr = apr_thread_mutex_create(&cache->mutex, APR_THREAD_MUTEX_UNNESTED, cache->pool);
    if (aprerr) {
	LOG_P_ERROR(APLOG_ERR, aprerr, cache->pool,
		"Failed to create cache mutex");
	return NULL;
    }

    cache->users = apr_hash_make(cache->pool);

    serverconf = GET_SERVER_CONFIG(request->server->module_config);
    cache->vas_ctx = serverconf->vas_ctx;
    cache->vas_serverid = serverconf->vas_serverid;

    return cache;
}

/**
 * Cleans up the given cache - freeing resources that can be freed (those
 * allocated by libvas, and the userdata_pool).
 * The actual cache structure is allocated from the connection pool (its parent)
 * and cannot be explicitly freed.
 *
 * This function can be used when the cache is no longer required.
 * As it should only be called by the server cleanup function, it won't be run
 * in parallel and does not require locking.
 */
void
auth_vas_cache_cleanup(auth_vas_cache *cache)
{
    apr_pool_destroy(cache->pool);
    cache->pool = NULL;

    /* TODO: Free VAS resources? */

}

/**
 * Locks the cache mutex.
 * Can be used by external code to synchronise access to cached data, such as
 * user objects.
 *
 * @sa auth_vas_cache_unlock
 */
void
auth_vas_cache_lock(auth_vas_cache *cache) {
    apr_status_t aprerr;
    
    aprerr = apr_thread_mutex_lock(&cache->mutex);
    if (aprerr)
	LOG_P_ERROR(LOG_CRIT, aprerr, "Cannot lock cache mutex");
}

/**
 * Unlocks the cache mutex.
 * Can be used by external code to synchronise access to cached data, such as
 * use robjects.
 *
 * @sa auth_vas_cache_lock
 */
void
auth_vas_cache_unlock(auth_vas_cache *cache) {
    apr_status_t aprerr;

    aprerr = apr_thread_mutex_unlock(&cache->mutex);
    if (aprerr)
	LOG_P_ERROR(LOG_ERR, aprerr, "Cannot unlock cache mutex");
}

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

    if (user->vas_authctx == NULL)
	return VAS_ERR_INVALID_PARAM;

    /* No caching, simply a pass-through because
     * vas_auth_check_client_membership does not hit the network. */

    return vas_auth_check_client_membership(user->cache->vas_ctx, user->vas_id,
	    user->vas_authctx, group);
}

#define RETURN(x) do { \
    result = (x); \
    goto finish; \
} while (0)

#if 0 /* Hmm... unnecessary. I'll put the auth stuff in the user creation. */
vas_err_t
auth_vas_auth(auth_vas_user *user, vas_id_t *server) {
    vas_err_t vaserr; /**< Temp storage */
    vas_err_t result; /**< Our return code */

    if (user->vas_authctx) {
	/* Yay, cache! */
	return VAS_ERR_SUCCESS;
    }

    vaserr = vas_auth(user->cache->vas_ctx, user->vas_id, server, &user->vas_authctx);
    if (vaserr) {
	user->vas_authctx = NULL; /* ensure. */
	return vaserr;
    }
}
#endif

/**
 * Get (and cache) the auth_vas_user for the given username.
 * This function locks the cache. Callers must not.
 */
vas_err_t
auth_vas_user_alloc(
	auth_vas_cache *cache,
	const char *username,
	auth_vas_user **user)
{
    vas_err_t result; /**< This function's return code. */
    vas_err_t vaserr; /**< Temp storage */
    apr_status_t aprerr;
    vas_id_t *local_id;
    auth_vas_user *cached_user;

    auth_vas_cache_lock(cache);
    /* Use the RETURN() macro from here on */

    /* User IDs are only dependent on the machine's default_realm, which will
     * not change within the lifetime of the process, so we only need to
     * check that the username matches.
     */
    cached_user = apr_hash_get(cache->users, username, APR_HASH_KEY_STRING);

    if (!cached_user) {
	vaserr = vas_id_alloc(cache->vas_ctx, username, &local_id);
	if (vaserr)
	    RETURN(vaserr);

	cached_user = malloc(sizeof(*cached_user));
	cached_user->cache = cache;
	cached_user->username = strdup(username);
	user->vas_id = local_id;

	auth_vas_user_ref(cached_user); /* For the cache */
	apr_hash_set(cache->users, user->username, APR_HASH_KEY_STRING, user);
    }

    /* Success */
    auth_vas_user_ref(cached_user); /* For the caller */
    *user = cached_user;

    RETURN(VAS_ERR_SUCCESS);

finish:
    auth_vas_cache_unlock(cache);

    return result;
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
	vas_ctx_t *vasctx = user->cache->vas_ctx;

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
    vas_err_t result; /**< Our return code */
    vas_err_t vaserr; /**< Temp storage */

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
    vaserr = vas_id_establish_cred_password(user->cache->vas_ctx, user->vas_id,
	    credflags, password);
    if (vaserr)
	RETURN(vaserr);

    /* Successfully authenticated. Save the auth info */
    user->password = strdup(password);
    user->credflags = credflags;

    /* Authenticate the user to our service. Causes Kerberos traffic. */
    vaserr = vas_auth(user->cache->vas_ctx, user->vas_id,
	    user->cache->vas_serverid, &user->vas_authctx);
    if (vaserr) {
	user->vas_authctx = NULL; /* ensure */
	RETURN(vaserr);
    }

    RETURN(VAS_ERR_SUCCESS);

finish:

    return result;
}

#if 0 /* unnecessary. The server ID is provided at cache creation time */
/**
 * Establishes credentials for the given user using a keytab.
 *
 * This is a pass-through to vas_id_establish_cred_keytab as we can't reliably
 * cache keytab credentials, and there is little benefit because it usually
 * doesn't cause network traffic, and should only be used rarely (in contrast to
 * establishing creds with a password, which may be frequent).
 *
 * This function is not thread-safe.
 *
 * @return VAS_ERR_SUCCESS if credentials were established (or already held) or
 * an error code from vas_id_establish_cred_keytab.
 */
vas_err_t
auth_vas_user_establish_cred_keytab(
	auth_vas_user *user,
	int credflags,
	const char *keytab)
{
    vas_err_t vaserr;

    vaserr = vas_id_establish_cred_keytab(user->cache->vas_ctx, user->vas_id,
	    credflags, keytab);

    if (vaserr == VAS_ERR_SUCCESS)
	user->credflags = credflags; /* In case anyone wants to check them */

    return vaserr;
}
#endif

#if 0 /* old */
/**
 * Authenticate the cached user to the cached service.
 *
 * The auth parameter will only be changed if this function is successful.
 *
 * This breaks the idea of keeping the function signatures the same except for
 * the vas_ctx/auth_vas_cache arg.
 */
vas_err_t
auth_vas_cache_auth(
	auth_vas_cache *cache,
	vas_auth_t **auth)
{
    vas_err_t vaserr;
    vas_auth_t *local_authptr;

    if (!cache->vas_userid || !cache->vas_serverid || !auth)
	return VAS_ERR_INVALID_PARAM;

    if (cache->vas_auth_obj) {
	*auth = cache->vas_auth_obj;
	return VAS_ERR_SUCCESS;
    }

    vaserr = vas_auth(cache->vas_ctx, cache->vas_userid, cache->vas_serverid, &local_authptr);

    if (vaserr == VAS_ERR_SUCCESS) {
	*auth = local_authptr;
	cache->vas_auth_obj = local_authptr;
    }

    return vaserr;
}
#endif /* old */

/**
 *
 * @warn This function is incomplete and might not actually flush the cache.
 *
 * @see auth_vas_cache_cleanup
 */
void
auth_vas_cache_flush(auth_vas_cache *cache)
{
    cache->username = NULL;
    cache->basic_password = NULL;
    /* TODO: Free the cache->vas_userid? */
    /* ... probably. */
    /* And the cache->vas_auth */
}

/* vim: ts=8 sw=4 noet tw=80
 */
