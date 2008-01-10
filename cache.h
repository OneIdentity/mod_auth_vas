#ifndef MAV_CACHE_H
#define MAV_CACHE_H
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
 */

#include <httpd.h>
#include <http_log.h>
#include <vas.h>

#include "compat.h"

#ifdef __cplusplus
extern "C" {
#endif

/* types */
typedef struct auth_vas_cache auth_vas_cache;
typedef struct auth_vas_user auth_vas_user;

/* functions */
auth_vas_cache *
auth_vas_cache_new(request_rec *request);

void
auth_vas_cache_cleanup(auth_vas_cache *cache);

void
auth_vas_cache_lock(auth_vas_cache *cache);

void
auth_vas_cache_unlock(auth_vas_cache *cache);

vas_err_t
auth_vas_cache_user_id_alloc(auth_vas_cache *cache, const char *username);

void
auth_vas_cache_set_serverid(auth_vas_cache *cache, vas_id_t *serverid);

vas_err_t
auth_vas_user_authenticate(
	auth_vas_cache *cache,
	int credflags,
	const char *password);

vas_err_t
auth_vas_cache_auth(auth_vas_cache *cache, vas_auth_t **auth);

void
auth_vas_cache_flush(auth_vas_cache *cache);

#ifdef __cplusplus
} /* extern C */
#endif

#endif /* MAV_CACHE_H */
/* vim: ts=8 sw=4 noet
 */
