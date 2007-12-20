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
 *   Implements a cache of VAS-related authentication information. Only caches
 *   the information for a single vserver and a single user -- if a request
 *   comes in for a different user then the previously cached user data is
 *   destroyed. Likewise if a request comes in on a different vserver, the
 *   cached user data is destroyed (because the identity that a given username
 *   string refers to may differ across realms, and realms are configured
 *   per-vserver).
 *
 *   The API mimics the libvas API with the intention of making it easy to use.
 *
 *   The code could (probably) be reused in other projects so long as they
 *   link to the Apache Portable Runtime (APR) and provide the parent memory
 *   pool. However the architecture of only caching a single user's credentials
 *   might make it inaffective in many situations.
 *
 *   Future work might include adding more libvas-like error reporting, such as
 *   auth_vas_cached_err_get_string() and having caching functions set an error
 *   string where appropriate.
 */

#include "cache.h"

/**
 * Per-connection structure for caching remote user information.
 * Any of these fields may be NULL, particularly for the first request.
 */
struct auth_vas_cache {
    /** The pool to allocate cached user data from.
     * This pool is cleaned up and re-created when a different user tries to
     * authenticate, ensuring that old user data does not hang around in memory
     * waiting for arbitrary memory disclosure. */
    apr_pool_t	*userdata_pool;

    /** The pool to allocate non-user-specific data from (also the parent of the
     * userdata_pool). */
    apr_pool_t	*parent_pool;

    /** The Virtual Server that the vas_serverid refers to. Don't free this. */
    server_rec *server;

    /************************************************************************
     * Resources that must be explicitly freed.
     ************************************************************************/

    vas_ctx_t	*vas_ctx;
    vas_id_t	*vas_serverid;
    vas_id_t	*vas_userid;
    /* _obj suffix to avoid confusion with the vas_auth() function: */
    vas_auth_t	*vas_auth_obj;

    /************************************************************************
     * Resources allocated from pools that will be freed automatically.
     ************************************************************************/

    /** The username passed in by the client. May be in any format. Allocated
     * from a pool -- do not free. */
    char	*username;

    /** The password passed in by the client for Basic auth. Allocated from a
     * pool -- do not free. */
    char	*basic_password;

    /** credflags argument used in vas_id_establish_cred_password, only
     * meaningful if basic_password is not NULL */
    int		password_credflags;
};

/**
 * Creates a new auth_vas_cache, allocated from the connection pool of the
 * given request.
 */
auth_vas_cache *
auth_vas_cache_new(request_rec *request)
{
    auth_vas_cache *cache = NULL;

    cache = apr_pcalloc(request->connection->pool, sizeof(*cache));
    if (!cache) {
	LOG_P_ERROR(APLOG_ERR, 0, request->connection->pool, "Failed to allocate cache structure");
	return NULL;
    }

    cache->parent_pool = request->connection->pool;

    /* cache->userdata_pool will be created later, by auth_vas_cache_user_id_alloc */

    return cache;
}

/**
 * Cleans up the given cache - freeing resources that can be freed (those
 * allocated by libvas, and the userdata_pool).
 * The actual cache structure is allocated from the connection pool (its parent)
 * and cannot be explicitly freed.
 *
 * This function can be used when the cache is no longer required.
 */
void
auth_vas_cache_cleanup(auth_vas_cache *cache)
{
    apr_pool_destroy(cache->userdata_pool);

    if (cache->vas_auth_obj) {
	vas_auth_free(cache->vas_ctx, cache->vas_auth_obj);
	cache->vas_auth_obj = NULL;
    }

    if (cache->vas_userid) {
	vas_id_free(cache->vas_ctx, cache->vas_userid);
	cache->vas_userid = NULL;
    }

    if (cache->vas_serverid) {
	vas_id_free(cache->vas_ctx, cache->vas_serverid);
	cache->vas_serverid = NULL;
    }

    if (cache->vas_ctx) {
	vas_ctx_free(cache->vas_ctx);
	cache->vas_ctx = NULL;
    }
}

/** Get (and cache) the vas_id_t for the given username.
 * A vas_id_alloc doesn't cause any network traffic, this function exists
 * only as an interface for setting the user ID in the cache structure.
 */
vas_err_t
auth_vas_cached_user_id_alloc(
	auth_vas_cache *cache,
	const char *username)
{
    vas_err_t vaserr; /**< Temp storage */
    vas_err_t our_err = VAS_ERR_SUCCESS; /**< The value returned by this func. */
    apr_status_t aprerr; /**< Temp storage */

    /* User IDs are only dependent on the machine's default_realm, which will
     * not change within the lifetime of the process, so we only need to
     * check that the username matches.
     */
    if (cache->username) {
	if (streq(cache->username, username)) {
	    /* Already cached. */
	    ASSERT(cache->vas_userid != NULL);
	    return VAS_ERR_SUCCESS;
	}

	/* XXX: Separate this out into an auth_vas_cache_destroy_userdata() so
	 * it can be reused (maybe?). */

	/* Different user, free the old data. */
	ASSERT(cache->userdata_pool != NULL);
	apr_pool_destroy(cache->userdata_pool);
	vas_id_free(cache->vas_ctx, cache->vas_userid);

	/* These have now been freed */
	cache->userdata_pool = NULL;
	cache->vas_userid = NULL;
	cache->username = NULL;
	cache->basic_password = NULL;
    }

    if (!cache->userdata_pool) {
	aprerr = apr_pool_create_ex(&cache->userdata_pool, cache->parent_pool, NULL, NULL);
	if (aprerr) {
	    LOG_P_ERROR(APLOG_ERR, aprerr, cache->parent_pool, "Failed to create userdata pool");
	    our_err = VAS_ERR_NO_MEMORY;
	    goto fail;
	}
    }

    /* Allocate the new data */
    vaserr = vas_id_alloc(cache->vas_ctx, username, &cache->vas_userid);
    if (vaserr) {
	/* Probably not worth doing negative caching here because vas_id_alloc
	 * doesn't hit the network. */
	cache->vas_userid = NULL; /* libvas doesn't guarantee this */
	/* Don't destroy the userdata_pool - it contains nothing yet and can be
	 * reused. */
	our_err = vaserr;

	return vaserr;
    }

    cache->username = apr_pstrdup(cache->userdata_pool, username);
    if (!cache->username) {
	our_err = VAS_ERR_NO_MEMORY;
	goto fail;
    }

    /* Success */
    ASSERT(our_err == VAS_ERR_SUCCESS);
    return VAS_ERR_SUCCESS;

fail:
    /* Ensure a failure reason has been set */
    ASSERT(our_err != VAS_ERR_SUCCESS);

    if (cache->vas_userid) {
	vas_id_free(cache->vas_ctx, cache->vas_userid);
	cache->vas_userid = NULL;
    }

    return our_err;
}

/**
 * Establishes credentials using the given password.
 * The identity must already have been set with
 * \c auth_vas_cached_user_id_alloc .
 * This function only does positive caching (correct password), not negative
 * caching (so if the user keeps getting his password wrong, it will keep
 * hitting the krb5 KDC).
 *
 * @return VAS_ERR_SUCCESS if the password was valid, or nonzero on failure.
 *         Returns VAS_ERR_FAILURE if the password does not match the cached
 *         password, whereas real libvas would return VAS_ERR_KRB5 and set
 *         the error state.
 *
 * @see vas_id_establish_cred_password
 */
vas_err_t
auth_vas_cached_id_establish_cred_password(
	auth_vas_cache *cache,
	int credflags,
	const char *password)
{
    vas_err_t vaserr;

    /* If the previous password is set but does not match this one, fail.
     * (The caller can do a periodic cache_flush to ensure stale passwords are
     * not cached.) Only if credflags == cached_credflags, of course. */

    if (cache->basic_password && cache->password_credflags == credflags) {
	if (streq(cache->basic_password, password))
	    return VAS_ERR_SUCCESS;
	/* libvas would return VAS_ERR_KRB5 and set error state. */
	return VAS_ERR_FAILURE;
    }

    vaserr = vas_id_establish_cred_password(cache->vas_ctx, cache->vas_userid,
	    credflags, password);

    if (vaserr == VAS_ERR_SUCCESS) {
	/* Save the current password */
	cache->basic_password = apr_strdup(cache->userdata_pool, password);
	cache->password_credflags = credflags;
    }

    return vaserr;
}

/**
 * Authenticate the cached user to the cached service.
 *
 * The auth parameter will only be changed if this function is successful.
 *
 * This breaks the idea of keeping the function signatures the same except for
 * the vas_ctx/auth_vas_cache arg.
 */
vas_err_t
auth_vas_cached_auth(
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
    /* TODO: Free the cache->vas_userid? What about cache->vas_serverid? */
    /* ... probably. */
    /* And the cache->vas_auth */
}

/* vim: ts=8 sw=4 noet tw=80
 */
