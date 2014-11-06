/*
 * mod_auth_vas: VAS authentication module for Apache.
 *
 *   Copyright 2014 Dell Software, Inc.
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
 *   c. Neither the name of Dell Software, Inc. nor the names of its
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
 *     Jayson Hurst <jayson.hurst@software.dell.com>
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "compat.h"
#include "cache.h"
#include "group.h"

void cached_group_data_ref(void *vobj) {
    cached_group_data *d = (cached_group_data*)vobj;

    ++d->refcount;
}

void cached_group_data_unref(void *vobj) {
    cached_group_data *group = (cached_group_data*)vobj;
    ASSERT(group->refcount > 0);

    --group->refcount;

    if (group->refcount == 0) {
        free(group->key);
        free(group);
    }
}

const char * get_cached_group_data_key_cb(void *vobj)
{
    cached_group_data *group = (cached_group_data*)vobj;

    if (!group)
        return NULL;

    return group->key;

}
