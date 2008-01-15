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
 *   A cache. Designed to be used for caching data retrieved from libvas,
 *   particularly users or groups.
 *
 *   Most functions are not thread safe. Be careful.
 *
 */

#include <apr_hash.h>
#include <httpd.h>
#include <http_log.h>

#include "compat.h"
#include "cache.h"

/**
 * Per-server structure for caching remote user authentication information.
 */
struct auth_vas_cache {
    /** For locking the cache. */
    apr_thread_mutex_t	*mutex;

    /** The pool to allocate data for the cache from. Beware about putting large
     * amounts of data in the pool - it is only cleaned up when the server
     * process exits. See auth_vas_cache_cleanup for cleanup details. */
    apr_pool_t	*pool;

    /** Hashed data. */
    apr_hash_t	*table;

    /** Convenience pointer to the vas_ctx owned by the server_rec. Do not
     * free. */
    vas_ctx_t	*vas_ctx;

    /** The server ID that all clients will be authenticated to, owned by the
     * server_rec. Do not free. */
    vas_id_t	*vas_serverid;

    /** Function to be called after removing an item from the cache. */
    void (*unref_item_cb)(void *item);
};

/**
 * Creates a new auth_vas_cache, allocated from the given memory pool
 * because the vas_ctx_t must be the same.
 *
 * The vas_ctx and vas_serverid are convenience pointers for cache users -- they
 * can be NULL or unused if the cached items don't need them.
 *
 * @param parent_pool Memory pool to be used as the parent of the cache's pool.
 * @param vas_ctx libvas context to be used by cached items.
 * @param vas_serverid Server ID to associate with cached items (optional).
 * @param unref_cb Function to call immediately after removing an item from the
 *                 cache, for example to free or unref an object. May be NULL.
 */
auth_vas_cache *
auth_vas_cache_new(apr_pool_t *parent_pool,
	vas_ctx_t *vas_ctx,
	vas_id_t *vas_serverid,
	void (*unref_cb)(void *))
{
    apr_status_t aprerr;
    auth_vas_cache *cache = NULL;

    /* Should we allocate the cache out of the cache subpool instead?
     * Only necessary if caches are destroyed more frequently than processes
     * exit. */
    cache = apr_pcalloc(parent_pool, sizeof(*cache));
    if (!cache) {
	LOG_P_ERROR(APLOG_ERR, 0, parent_pool,
		"Failed to allocate cache structure");
	return NULL;
    }

    aprerr = apr_pool_create(&cache->pool, parent_pool);
    if (aprerr) {
	LOG_P_ERROR(APLOG_ERR, aprerr, parent_pool,
		"Failed to create cache memory pool");
	return NULL;
    }

    aprerr = apr_thread_mutex_create(&cache->mutex, APR_THREAD_MUTEX_UNNESTED, cache->pool);
    if (aprerr) {
	LOG_P_ERROR(APLOG_ERR, aprerr, cache->pool,
		"Failed to create cache mutex");
	return NULL;
    }

    cache->table = apr_hash_make(cache->pool);

    cache->vas_ctx = vas_ctx;
    cache->vas_serverid = vas_serverid;
    cache->unref_item_cb = unref_cb;

    return cache;
}

/**
 * Cleans up the given cache - freeing resources that can be freed, including
 * the cache's child pool. Anything allocated from a parent pool, such as the
 * cache itself will (of course) not be freed.
 *
 * This function can be used when the cache is no longer required.
 * As it should only be called by the server cleanup function, it won't be run
 * in parallel and does not require locking.
 */
void
auth_vas_cache_cleanup(auth_vas_cache *cache)
{
    apr_hash_index_t *index;

    for (index = apr_hash_first(cache->pool, cache->table);
	    index;
	    index = apr_hash_next(index))
    {
	const void *key;
	apr_ssize_t keylength;
	void *value;

	/* We know the key is a string, but we might as well just keep this
	 * generic and use whatever the hash table says the key length is. */
	apr_hash_this(index, &key, &keylength, &value);

	/* Remove item from cache */
	apr_hash_set(cache->table, key, keylength, NULL);

	/* Remove the cache's reference to the item */
	if (cache->unref_item_cb)
	    cache->unref_item_cb(value);
    }

    /* APR 1.2 doesn't allow us to destroy cache->pool.
     * If we do, it tries to destroy it again later and crashes. */
}

/**
 * Locks the cache mutex.
 * Can be used by external code to synchronise access to cached data.
 *
 * @sa auth_vas_cache_unlock
 */
void
auth_vas_cache_lock(auth_vas_cache *cache) {
    apr_status_t aprerr;
    
    aprerr = apr_thread_mutex_lock(cache->mutex);
    if (aprerr)
	LOG_P_ERROR(APLOG_CRIT, aprerr, cache->pool, "Cannot lock cache mutex");
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

    aprerr = apr_thread_mutex_unlock(cache->mutex);
    if (aprerr)
	LOG_P_ERROR(APLOG_ERR, aprerr, cache->pool, "Cannot unlock cache mutex");
}

void
auth_vas_cache_insert(auth_vas_cache *cache, const char *key, const void *value)
{
    apr_hash_set(cache->table, key, APR_HASH_KEY_STRING, value);
}

void
auth_vas_cache_remove(auth_vas_cache *cache, const char *key)
{
    apr_hash_set(cache->table, key, APR_HASH_KEY_STRING, NULL);
}

void *
auth_vas_cache_get(auth_vas_cache *cache, const char *key)
{
    return apr_hash_get(cache->table, key, APR_HASH_KEY_STRING);
}

vas_ctx_t *
auth_vas_cache_get_vasctx(const auth_vas_cache *cache) {
    return cache->vas_ctx;
}

vas_id_t *
auth_vas_cache_get_serverid(const auth_vas_cache *cache) {
    return cache->vas_serverid;
}

/* vim: ts=8 sw=4 noet tw=80
 */
