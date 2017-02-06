/*
 * mod_auth_vas: VAS authentication module for Apache.
 *
 *   Copyright 2017 Quest Software, Inc.
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
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <unistd.h> /* for sleep(3) */

#include "compat.h"
#include "cache.h"

#define FAIL(msg) \
    do { \
	fprintf(stderr, "%s\n", msg); \
	return 1; \
    } while (0)

/** Exits immediately with a failure code.
 * For functions that need to indicate an error but have no other means to do
 * so. */
#define ABORT(msg) \
    do { \
	fprintf(stderr, "%s\n", msg); \
	exit(1); \
    } while (0)

typedef struct cached_data cached_data;
struct cached_data {
    char *key;
    int value; /* Some arbitrary value, can be assigned incrementally */
    unsigned refcount;
};

/**
 * Return a new cache object.
 * If the object cannot be allocated, this function aborts the process.
 * Ergo it always returns a valid pointer.
 */
static cached_data *
cached_data_new(const char *key, int value) {
    cached_data *d;

    d = calloc(1, sizeof(*d));
    if (!d)
	ABORT("Out of memory allocating a cached data test object");

    d->key = strdup(key);
    d->value = value;
    d->refcount = 1; /* The caller */

    return d;
}

static void
cached_data_ref(void *vobj) {
    cached_data *d = (cached_data*)vobj;

    ++d->refcount;
}

static void
cached_data_unref(void *vobj) {
    cached_data *obj = (cached_data*)vobj;

    if (!obj)
	ABORT("unrefed a NULL pointer");

    if (obj->refcount < 1)
	ABORT("unrefed an object with refcount < 1");

    --obj->refcount;

    if (obj->refcount == 0) {
	free(obj->key);
	free(obj);
    }
}

static const char *
get_cached_data_key_cb(void *vobj) {
    cached_data *obj = (cached_data*)vobj;

    if (!obj)
	ABORT("tried to get key for a NULL object");

    return obj->key;
}

/**
 * Creates an auth_vas_cache for storing cached_data objects.
 * The vasctx and serverid parameters may be NULL.
 */
static auth_vas_cache *
init_cache_or_die(apr_pool_t *parent_pool, vas_ctx_t *vasctx, vas_id_t *serverid)
{
    auth_vas_cache *cache;

    cache = auth_vas_cache_new(parent_pool, vasctx, serverid,
	    &cached_data_ref, &cached_data_unref, &get_cached_data_key_cb);

    if (!cache)
	ABORT("Could not create cache");

    return cache;
}

/**
 * Tests that the cache can be flushed and then continue to be used.
 */
static int
test_flush(apr_pool_t *parent_pool) {
    int failures = 0;
    auth_vas_cache *cache;
    cached_data *obj, *cached_obj;
    int i;

    cache = init_cache_or_die(parent_pool, NULL, NULL);

    /* Create an object. Flush. Try a get on the object and ensure it fails. */
    obj = cached_data_new("foo", 1);

    /* Two iterations of: insert, get, flush, get. */
    for (i = 0; i < 2; ++i) {
	auth_vas_cache_insert(cache, obj->key, obj);
	cached_obj = (cached_data *)auth_vas_cache_get(cache, obj->key);

	if (!cached_obj)
	    FAIL("Failed to get cached object before flushing");

	cached_data_unref(cached_obj);

	auth_vas_cache_flush(cache);

	cached_obj = (cached_data *)auth_vas_cache_get(cache, obj->key);
	if (cached_obj)
	    FAIL("Cache returned an object after flushing");
    }

    cached_data_unref(obj); /* Free our test obj */

    return failures;
}

static int
test_max_age(apr_pool_t *parent_pool) {
    auth_vas_cache *cache;
    unsigned int max_age;

    cache = init_cache_or_die(parent_pool, NULL, NULL);

    max_age = auth_vas_cache_get_max_age(cache);
    ++max_age;
    auth_vas_cache_set_max_age(cache, max_age);
    if (auth_vas_cache_get_max_age(cache) != max_age) {
	fprintf(stderr, "Failed to set max age to %u, instead it remained at %u\n",
		max_age, auth_vas_cache_get_max_age(cache));
	return 1;
    }
    auth_vas_cache_flush(cache);

    return 0;
}

static int
test_max_size(apr_pool_t *parent_pool) {
    auth_vas_cache *cache;
    unsigned int max_size;
    int failures = 0;

    cache = init_cache_or_die(parent_pool, NULL, NULL);

    max_size = auth_vas_cache_get_max_size(cache);

    if (max_size < UINT_MAX)
	++max_size;
    else
	--max_size;

    auth_vas_cache_set_max_size(cache, max_size);
    if (auth_vas_cache_get_max_size(cache) != max_size) {
	fprintf(stderr, "Failed to set max size to %u, instead it remained at %u\n",
		max_size, auth_vas_cache_get_max_size(cache));
	++failures;
    }

    /* The cache code is not designed to operate with size == 0, ensure it gets
     * coerced to something more sensible. */
    auth_vas_cache_set_max_size(cache, 0);
    if (auth_vas_cache_get_max_size(cache) == 0) {
	fprintf(stderr, "Cache max size could be set to zero.");
	++failures;
    }

    auth_vas_cache_flush(cache);

    return failures;
}

/* Only for APLOG_* */
#include <http_log.h>
/* We have to provide ap_log_perror because the cache (stupidly) does its own
 * logging through that function.
 * At some point it won't be so gregarious. */
void ap_log_perror(const char *file, int line, int level,
	apr_status_t status, apr_pool_t *p, const char *fmt, ...)
{
    va_list ap;

    /* Only print errors for ERR and up (actually down in numeric terms) */
    switch(level) {
	case APLOG_EMERG:
	case APLOG_ALERT:
	case APLOG_CRIT:
	case APLOG_ERR:
	    break;

	default:
	    return;
    }

    fprintf(stderr, "%s:%d (%d): ", file, line, status);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

static int
test_full_cache(apr_pool_t *pool) {
    auth_vas_cache *cache;
    cached_data *obj, *fromcache;

    cache = init_cache_or_die(pool, NULL, NULL);
    auth_vas_cache_set_max_size(cache, 1);

    /* The first object is throwaway so that cache has something to push out to
     * make room for the second. We don't hold a ref to the first object. */
    obj = cached_data_new("one", 1);
    auth_vas_cache_insert(cache, obj->key, obj);
    cached_data_unref(obj);

    obj = cached_data_new("two", 2);
    auth_vas_cache_insert(cache, obj->key, obj);

    if (auth_vas_cache_get(cache, "one") != NULL)
	FAIL("Got the first object from the cache, but it should have been forced out.");

    fromcache = auth_vas_cache_get(cache, "two");
    if (!fromcache)
	FAIL("Second item could not be retrieved from the cache");
    if (fromcache != obj)
	FAIL("Second item was not what we expected");

    /* Success, clean up. */
    auth_vas_cache_flush(cache);

    cached_data_unref(fromcache);
    cached_data_unref(obj);

    return 0;
}

/**
 * Tests that the vasctx and vas_serverid can be retrieved and match what was
 * put in. */
static int
test_vasobjs(apr_pool_t *pool) {
    auth_vas_cache *cache;
    static int dummy_vasid, dummy_vasctx;

    cache = init_cache_or_die(pool, (vas_ctx_t*)&dummy_vasctx, (vas_id_t*)&dummy_vasid);
    if (auth_vas_cache_get_vasctx(cache) != (vas_ctx_t*)&dummy_vasctx)
	FAIL("Failed to get the vasctx that the cache was initialised with");

    if (auth_vas_cache_get_serverid(cache) != (vas_id_t*)&dummy_vasid)
	FAIL("Failed to get the serverid that the cache was initialised with");

    auth_vas_cache_flush(cache);
    return 0;
}

/** Tests that multiple items can be added and remove.
 * Exercises the linked list and pointer operations. */
static int
test_multiple_items(apr_pool_t *pool) {
    auth_vas_cache *cache;
    cached_data *obj;

    cache = init_cache_or_die(pool, NULL, NULL);

    obj = cached_data_new("one", 1);
    auth_vas_cache_insert(cache, obj->key, obj);
    cached_data_unref(obj);

    obj = cached_data_new("two", 2);
    auth_vas_cache_insert(cache, obj->key, obj);

    /* If it hasn't segfaulted, I guess that's good enough */
    auth_vas_cache_flush(cache);
    return 0;
}

/**
 * Tests inserting a new item when the cache is full and there are expired items.
 * This might seem silly, but there is a different code path for inserting items
 * when the cache is full and there are expired items to be purged. */
static int
test_insert_with_expired(apr_pool_t *pool) {
    auth_vas_cache *cache;
    cached_data *obj;

    cache = init_cache_or_die(pool, NULL, NULL);

    auth_vas_cache_set_max_age(cache, 1); /* 1 second */
    auth_vas_cache_set_max_size(cache, 1); /* 1 obj */

    obj = cached_data_new("expireme", 1);
    auth_vas_cache_insert(cache, obj->key, obj);
    cached_data_unref(obj);

    sleep(1); /* Expire the old item */

    obj = cached_data_new("cacheme", 2);
    auth_vas_cache_insert(cache, obj->key, obj);
    cached_data_unref(obj);

    if (auth_vas_cache_get(cache, "expireme") != NULL)
	FAIL("Retrieved an item that should have been expired");

    /* Don't bother getting the "cacheme" object, if we're running on a slow
     * machine it might have expired already. */

    auth_vas_cache_flush(cache);

    return 0;
}

static int
test_shrink_cache(apr_pool_t *pool) {
    auth_vas_cache *cache;
    cached_data *obj;
    size_t i;
    const char *const keys[] = { "one", "two", "three" };

    cache = init_cache_or_die(pool, NULL, NULL);

    for (i = 0; i < (sizeof(keys) / sizeof(keys[0])); ++i) {
	obj = cached_data_new(keys[i], i + 1);
	auth_vas_cache_insert(cache, obj->key, obj);
	cached_data_unref(obj);
    }

    auth_vas_cache_set_max_size(cache, 1);

    /* Get the last item */
    obj = auth_vas_cache_get(cache, "three");
    if (!obj)
	FAIL("Last item was not retrievable after shrinking the cache");

    cached_data_unref(obj);

    auth_vas_cache_flush(cache);

    return 0;
}

/** Bug #517: Cache leaks objects if it fills with expired items.
 * This was also covering up a double-free bug, see comment #1 on bug #517. We
 * can't actually test whether the object is leaking, but we can test the code
 * path that would lead to a double-free error. It triggered the "unrefed an
 * object with refcount < 1" error in this test suite.
 */
static int
test_expired_full_cache(apr_pool_t *pool) {
    auth_vas_cache *cache;
    cached_data *obj;

    cache = init_cache_or_die(pool, NULL, NULL);
    auth_vas_cache_set_max_size(cache, 2);
    auth_vas_cache_set_max_age(cache, 1);

    obj = cached_data_new("one", 1);
    auth_vas_cache_insert(cache, obj->key, obj);
    cached_data_unref(obj);

    obj = cached_data_new("two", 2);
    auth_vas_cache_insert(cache, obj->key, obj);
    cached_data_unref(obj);

    sleep(1); /* Let objects expire */

    obj = cached_data_new("three", 3);
    /* This insert triggers the cleanup and exercises the previously-buggy code
     * path */
    auth_vas_cache_insert(cache, obj->key, obj);
    cached_data_unref(obj);

    auth_vas_cache_flush(cache);
    return 0;

}

/* Pool allocator for APXS1. Should probably move this to ap_stub.c
 *
 * Really Dumb Leaky implementation that does not actually do memory pooling,
 * just allocates using malloc and forgets. For use only in test cases where
 * the process is short-lived so tracking memory properly does not really
 * matter.
 */
#if defined(APXS1)

/* This is typedefed to `pool' by ap_alloc.h */
struct pool {
    void *unused;
};

void *ap_palloc(apr_pool_t *mempool, int size) {
    return malloc(size);
}

void *ap_pcalloc(apr_pool_t *mempool, int size) {
    void *mem;

    mem = ap_palloc(mempool, size);
    memset(mem, '\0', size);
    return mem;
}

void ap_log_printf(const server_rec *s, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static int apr_pool_create(apr_pool_t **outpool, apr_pool_t *parent) {
    static apr_pool_t dummy;

    /* Ensure the pool pointer is not NULL, to satisfy callers */
    *outpool = &dummy;

    return OK;
}

apr_pool_t *ap_make_sub_pool(apr_pool_t *parent) {
    apr_pool_t *newp;

    apr_pool_create(&newp, parent);

    return newp;
}

static void apr_pool_destroy(apr_pool_t *dpool) {
    /* Leak. */
}
#endif /* APXS1 */

int main(int argc, char *argv[]) {
    int failures = 0;
    apr_pool_t *pool;

#if !defined(APXS1)
    if (apr_app_initialize(&argc, (const char *const **)&argv, NULL))
	FAIL("apr initialisation");

    atexit(apr_terminate);
#endif /* !APXS1 */

    if (apr_pool_create(&pool, NULL))
	FAIL("creating master test pool");

    failures += test_max_age(pool);
    failures += test_max_size(pool);
    failures += test_flush(pool);
    failures += test_full_cache(pool);
    failures += test_vasobjs(pool);
    failures += test_multiple_items(pool);
    failures += test_insert_with_expired(pool);
    failures += test_shrink_cache(pool);
    failures += test_expired_full_cache(pool);

    apr_pool_destroy(pool);

    return !!failures;
}

/* vim: ts=8 sw=4 noet tw=80
 */
