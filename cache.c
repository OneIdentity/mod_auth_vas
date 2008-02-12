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
 *   Uses a hash table for fast lookups and a home-brewed doubly-linked,
 *   double-ended queue for expiring old items.
 *
 *   Most functions are not thread safe. Be careful.
 */

#include <httpd.h>
#include <http_log.h>

#include "compat.h"
#include "cache.h"

/* Defaults */
#define DEFAULT_EXPIRE_SECONDS 60
#define DEFAULT_MAX_CACHE_SIZE 200

/**
 * Cache item, mainly for tracking when it was inserted to determine when it
 * should be expired from the cache.
 */
typedef struct auth_vas_cache_item auth_vas_cache_item;
struct auth_vas_cache_item {

    /** For removing items that are stale. */
    apr_time_t expiry;

    /** The user data. */
    void *item;

    /** Pointer for a linked list. Used for removing items if the cache fills.
     */
    auth_vas_cache_item *younger, *older;
};

/**
 * Per-server structure for caching remote user authentication information.
 */
struct auth_vas_cache {
    /** The pool to allocate data for the cache from. Beware about putting large
     * amounts of data in the pool - it is only cleaned up when the server
     * process exits. See auth_vas_cache_cleanup for cleanup details. */
    apr_pool_t	*pool;

    /** Hashed data (hash table of auth_vas_cached_item). */
    apr_hash_t	*table;

    /** Convenience pointer to the vas_ctx owned by the server_rec. Do not
     * free. */
    vas_ctx_t	*vas_ctx;

    /** The server ID that all clients will be authenticated to, owned by the
     * server_rec. Do not free. */
    vas_id_t	*vas_serverid;

    /** Function to be called when an item is added to the cache, and when it is
     * returned in an auth_vas_cache_get call. And any other time that a
     * reference to the item is held. */
    void (*ref_item_cb)(void *item);

    /** Function to be called after removing an item from the cache. */
    void (*unref_item_cb)(void *item);

    /** Linked list of items, for removing cached items efficiently. */
    auth_vas_cache_item *youngest, *oldest;

    /* Limits */
    apr_interval_time_t max_age_us; /**< Max age in µs */
    unsigned int max_size; /**< Max number of elements for the cache to hold. */

    /** Function to retrieve a value's key. Makes cache expiration a lot easier.
     * The cache will only call this for items that it holds a reference to. */
    const char *(*get_key_cb)(void *item);
};


static void
auth_vas_cache_remove_items_from(auth_vas_cache *cache, auth_vas_cache_item *item);

static void
auth_vas_cache_remove_expired_items(auth_vas_cache *cache);


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
 * @param get_key_cb Function to get the item's key. See the auth_vas_cache
 *                   documentation for details.
 */
auth_vas_cache *
auth_vas_cache_new(apr_pool_t *parent_pool,
	vas_ctx_t *vas_ctx,
	vas_id_t *vas_serverid,
	void (*ref_cb)(void *),
	void (*unref_cb)(void *),
	const char *(*get_key_cb)(void *))
{
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

#if defined (APXS1)
    cache->pool = ap_make_sub_pool(parent_pool);
    if (!cache->pool) {
	LOG_P_ERROR(APLOG_ERR, 0, parent_pool,
		"Failed to create cache memory pool");
	return NULL;
    }
#else /* APXS2 */
    {
	apr_status_t aprerr;

	aprerr = apr_pool_create(&cache->pool, parent_pool);
	if (aprerr) {
	    LOG_P_ERROR(APLOG_ERR, aprerr, parent_pool,
		    "Failed to create cache memory pool");
	    return NULL;
	}
    }
#endif /* APXS2 */

    cache->table = apr_hash_make(cache->pool);

    cache->vas_ctx = vas_ctx;
    cache->vas_serverid = vas_serverid;
    cache->ref_item_cb = ref_cb;
    cache->unref_item_cb = unref_cb;
    cache->get_key_cb = get_key_cb;

    cache->max_age_us = apr_time_from_sec(DEFAULT_EXPIRE_SECONDS);
    cache->max_size = DEFAULT_MAX_CACHE_SIZE;

    return cache;
}

/**
 * Flushes the cache.
 * The cache can still be used as normal after a flush.
 */
void
auth_vas_cache_flush(auth_vas_cache *cache)
{
    apr_hash_index_t *index;

    for (index = apr_hash_first(cache->pool, cache->table);
	    index;
	    index = apr_hash_next(index))
    {
	const void *key;
	apr_ssize_t keylength;
	auth_vas_cache_item *item;

	/* We know the key is a string, but we might as well just keep this
	 * generic and use whatever the hash table says the key length is. */
	apr_hash_this(index, &key, &keylength, (void**)&item);

	/* Remove item from cache */
	apr_hash_set(cache->table, key, keylength, NULL);

	/* Remove the cache's reference to the item */
	if (cache->unref_item_cb)
	    cache->unref_item_cb(item->item);

	free(item);
    }

    cache->youngest = NULL;
    cache->oldest = NULL;

    /* APR 1.2 doesn't allow us to destroy cache->pool.
     * If we do, it tries to destroy it again later and crashes. */
}

/**
 * Inserts an item.
 *
 * The caller must increase the ref count on the object before passing it to
 * this function (if ref counting is used).
 *
 * The key should be a string stored in the object. Otherwise you might find the
 * API difficult to work with.
 */
void
auth_vas_cache_insert(auth_vas_cache *cache, const char *key, void *value)
{
    auth_vas_cache_item *new_item;

    new_item = calloc(1, sizeof(*new_item));
    if (!new_item)
	return;

    new_item->expiry = apr_time_now() + cache->max_age_us;
    new_item->item = value;

    /* Make sure there is room for this item */
    if (apr_hash_count(cache->table) == cache->max_size) {

	if (apr_time_now() < cache->oldest->expiry) {
	    /* No expired items. Notify the user and remove the oldest one */
	    LOG_P_ERROR(APLOG_INFO, 0, cache->pool,
		    "%s: Removing unexpired item to make room, "
		    "consider increasing the cache size or decreasing the object lifetime",
		    __func__);
	    auth_vas_cache_remove_items_from(cache, cache->oldest);
	} else {
	    /* At least one expired item. Clean up as many as possible. */
	    auth_vas_cache_remove_expired_items(cache);
	}
    }

    if (cache->youngest) { /* There are other items */
	new_item->older = cache->youngest;
	cache->youngest->younger = new_item;
    } else { /* No other items */
	cache->oldest = new_item;
    }

    cache->youngest = new_item;

    /* Ref the item now that it's going into the cache. */
    if (cache->ref_item_cb)
	cache->ref_item_cb(value);

    apr_hash_set(cache->table, key, APR_HASH_KEY_STRING, new_item);
}

/**
 * Removes all items older than and including the given item.
 */
static void
auth_vas_cache_remove_items_from(auth_vas_cache *cache, auth_vas_cache_item *item)
{
    auth_vas_cache_item *next_item;

    /* Remove the younger item's pointer to this one */
    if (item == cache->youngest) {
	cache->youngest = NULL;
	cache->oldest = NULL;
    } else {
	/* There is a younger item, which is now the oldest. The youngest is unchanged. */
	item->younger->older = NULL;
	cache->oldest = item->younger;
    }

    /* Now all the pointers are fixed up, go on a rampage removing all the items. */

    do {
	next_item = item->older;

	/* Remove from hash table */
	apr_hash_set(cache->table, cache->get_key_cb(item->item), APR_HASH_KEY_STRING, NULL);

	/* Unref the user item */
	if (cache->unref_item_cb)
	    cache->unref_item_cb(item->item);

	/* Free the container object */
	free(item);
    } while (next_item);
}

static void
auth_vas_cache_remove_expired_items(auth_vas_cache *cache)
{
    apr_time_t now;
    auth_vas_cache_item *item;

    if (cache->oldest == NULL)
	return; /* no items */

    now = apr_time_now();

    /* Find the youngest expired item.
     * On loaded servers (where performance matters most) there will be less
     * expired than active objects, so start from the oldest. */
    for (item = cache->oldest; item && item->expiry < now; item = item->younger)
	;

    /* We went too far by one */
    if (item)
	item = item->older;

    if (item)
	auth_vas_cache_remove_items_from(cache, item);
}

void *
auth_vas_cache_get(auth_vas_cache *cache, const char *key)
{
    auth_vas_cache_item *item;

    item = apr_hash_get(cache->table, key, APR_HASH_KEY_STRING);
    if (!item)
	return NULL;

    if (item->expiry <= apr_time_now()) {
	/* Expired */
	auth_vas_cache_remove_expired_items(cache);
	return NULL;
    }

    /* Ref the item for the caller */
    if (cache->ref_item_cb)
	cache->ref_item_cb(item->item);

    return item->item;
}

vas_ctx_t *
auth_vas_cache_get_vasctx(const auth_vas_cache *cache) {
    return cache->vas_ctx;
}

vas_id_t *
auth_vas_cache_get_serverid(const auth_vas_cache *cache) {
    return cache->vas_serverid;
}

unsigned int
auth_vas_cache_get_max_age(const auth_vas_cache *cache) {
    return apr_time_sec(cache->max_age_us);
}

void
auth_vas_cache_set_max_age(auth_vas_cache *cache, unsigned int seconds) {
    cache->max_age_us = apr_time_from_sec(seconds);
}

unsigned int
auth_vas_cache_get_max_size(const auth_vas_cache *cache) {
    return cache->max_size;
}

void
auth_vas_cache_set_max_size(auth_vas_cache *cache, unsigned int new_size) {
    unsigned int num_items;

    if (new_size < 1) /* Some dolt will try it */
	new_size = 1;

    num_items = apr_hash_count(cache->table);

    while (num_items > new_size) {
	auth_vas_cache_remove_items_from(cache, cache->oldest);
	--num_items;
    }

    cache->max_size = new_size;
}

/* vim: ts=8 sw=4 noet tw=80
 */
