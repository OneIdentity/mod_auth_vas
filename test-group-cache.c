#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "compat.h"

#include <stdio.h>
#include "cache.h"
#include "group.h"

#include <http_log.h>

/* Only for APLOG_* */
#include <http_log.h>
/* We have to provide ap_log_perror because the cache (stupidly) does its own
 * logging through that function.
 * At some point it won't be so gregarious. */
void ap_log_perror(const char *file, int line, int level, int module_index,
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

    apr_pool_t *pool;

    if (apr_app_initialize(&argc, (const char *const **)&argv, NULL)) {
        fprintf(stderr, "apr initialisation");
        return 1;
    }

    atexit(apr_terminate);

    if (apr_pool_create(&pool, NULL)) {
        fprintf(stderr, "creating master test pool\n");
        return 1;
    }

    auth_vas_cache *neg_group_cache;

    neg_group_cache = auth_vas_cache_new(pool, NULL, NULL, (void(*)(void*))auth_vas_cached_group_data_ref, (void(*)(void*))auth_vas_cached_group_data_unref, (void(*)(void*))auth_vas_get_cached_group_data_key_cb);

    char *groups[] = {"foobar", "foobar1", "foobar2", "foobar", "foobar1", "foobar2", "foobar3"};
    int i, count = 7;
    cached_group_data *cached_group;

    for(i = 0; i < count; i++) {

      cached_group = (cached_group_data*)auth_vas_cache_get(neg_group_cache, groups[i]);
      if(!cached_group) {

            fprintf(stderr, "%s, Group <%s> is not cached, adding <%s> to negative group cache\n", __FUNCTION__, groups[i], groups[i]);
            cached_group = calloc(1, sizeof(*cached_group));
            cached_group->key = strdup(groups[i]);

            /* Cache refs the user object for itself */
            auth_vas_cache_insert(neg_group_cache, cached_group->key, cached_group);

      }else{
        fprintf(stderr, "%s, Group <%s> has already been added to the cache\n", __FUNCTION__, groups[i]);
        auth_vas_cached_group_data_unref(cached_group);
      }
    }

    if (neg_group_cache) {
        auth_vas_cache_flush(neg_group_cache);
        neg_group_cache = NULL;
    }
    
    apr_pool_destroy(pool);
    

    return 0;
}
