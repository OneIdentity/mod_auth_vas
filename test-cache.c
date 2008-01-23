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
 */

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

static void
unref_cached_data(void *vobj) {
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
 * Tests that the cache can be flushed and then continue to be used.
 */
static int
test_flush(apr_pool_t *parent_pool) {
    int failures = 0;
    auth_vas_cache *cache;
    cached_data *obj, *cached_obj;
    int i;

    cache = auth_vas_cache_new(parent_pool, NULL, NULL, &unref_cached_data, &get_cached_data_key_cb);
    if (!cache)
	FAIL("Could not create cache for flush test");

    /* Create an object. Flush. Try a get on the object and ensure it fails. */
    obj = calloc(1, sizeof(*obj));
    obj->key = strdup("foo");
    obj->value = 1;
    obj->refcount = 1; /* One ref for this function, so it isn't freed. */

    /* Two iterations of: insert, get, flush, get. */
    for (i = 0; i < 2; ++i) {

	/* XXX: Having to bump the refcount externally is easy to forget. */
	++obj->refcount; /* For the cache. */

	auth_vas_cache_insert(cache, obj->key, obj);
	cached_obj = (cached_data *)auth_vas_cache_get(cache, obj->key);

	if (!cached_obj)
	    FAIL("Failed to get cached object before flushing");

	auth_vas_cache_flush(cache);

	cached_obj = (cached_data *)auth_vas_cache_get(cache, obj->key);
	if (cached_obj)
	    FAIL("Cache returned an object after flushing");
    }

    unref_cached_data(obj); /* Free our test obj */

    return failures;
}

static void
dummy_unref_cb(void *obj MAV_UNUSED) {
    /* no-op */
}

const char *
dummy_get_key_cb(void *obj) {
    return "dummy";
}

/**
 * Initialises a dummy cache.
 * Returns 0 on success, nonzero on failure.
 */
static int
init_dummy_cache(auth_vas_cache **cache, apr_pool_t *parent_pool) {
    auth_vas_cache *newcache;

    newcache = auth_vas_cache_new(parent_pool, NULL, NULL, &dummy_unref_cb, &dummy_get_key_cb);
    if (newcache)
	*cache = newcache;

    return newcache ? 0 : 1;
}

static int
test_max_age(apr_pool_t *parent_pool) {
    auth_vas_cache *cache;
    unsigned int max_age;

    if (init_dummy_cache(&cache, parent_pool))
	return 1;

    max_age = auth_vas_cache_get_max_age(cache);
    ++max_age;
    auth_vas_cache_set_max_age(cache, max_age);
    if (auth_vas_cache_get_max_age(cache) != max_age) {
	fprintf(stderr, "Failed to set max age to %u, instead it remained at %u\n",
		max_age, auth_vas_cache_get_max_age(cache));
	return 1;
    }

    return 0;
}

static int
test_max_size(apr_pool_t *parent_pool) {
    auth_vas_cache *cache;
    unsigned int max_size;
    int failures = 0;

    if (init_dummy_cache(&cache, parent_pool))
	return 1;

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

int main(int argc, char *argv[]) {
    int failures = 0;
    apr_pool_t *pool;

    if (apr_app_initialize(&argc, (const char *const **)&argv, NULL))
	FAIL("apr initialisation");

    atexit(apr_terminate);

    if (apr_pool_create(&pool, NULL))
	FAIL("creating master test pool");

    failures += test_max_age(pool);
    failures += test_max_size(pool);
    failures += test_flush(pool);

    apr_pool_destroy(pool);

    return !!failures;
}

/* vim: ts=8 sw=4 noet tw=80
 */
