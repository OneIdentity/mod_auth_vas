#ifndef MAV_USER_H
#define MAV_USER_H
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
 */

#include <vas.h>
#include <vas_gss.h>

#include "cache.h"

#ifdef __cplusplus
extern "C" {
#endif

/* types */
typedef struct auth_vas_user auth_vas_user;

/* functions */

vas_err_t auth_vas_user_alloc(auth_vas_cache *cache, const char *username, auth_vas_user **outuser);

void auth_vas_user_ref(auth_vas_user *user);

void auth_vas_user_unref(auth_vas_user *user);

const char * auth_vas_user_get_name(const auth_vas_user *user);

const char * auth_vas_user_get_principal_name(const auth_vas_user *user);

const vas_user_t * auth_vas_user_get_vas_user_obj(auth_vas_user *user);

vas_err_t auth_vas_user_authenticate(auth_vas_user *user, int credflags, const char *password);

vas_err_t auth_vas_user_use_gss_result(auth_vas_user *user, gss_cred_id_t cred, gss_ctx_id_t context);

vas_err_t auth_vas_is_user_in_group(auth_vas_user *user, const char *group);

vas_err_t auth_vas_user_get_vas_user(const auth_vas_user *avuser, vas_user_t **vasuserp);

vas_err_t auth_vas_user_set_vas_user_obj(auth_vas_user *vasuser);


#ifdef __cplusplus
} /* extern C */
#endif

#endif /* MAV_USER_H */
/* vim: ts=8 sw=4 noet
 */
