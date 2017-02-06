#ifndef MAV_USER_H
#define MAV_USER_H
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

#include <apr_dso.h>
#include <vas.h>
#include <vas_gss.h>

#include "cache.h"

#ifdef __cplusplus
extern "C" {
#endif

/* types */
typedef struct auth_vas_user auth_vas_user;

/*
 * Contains a list of funtion pointers.
 * Can be used to ensure backwards compatibilty when QAS API changes
 * and defines a new API call we want to use.
 */
typedef struct {
    vas_err_t (*vas_gss_auth_with_server_id_fn)(OM_uint32 *minor_status, vas_ctx_t *ctx, gss_cred_id_t cred, gss_ctx_id_t context, vas_id_t *server_id, vas_auth_t **auth);
    vas_err_t (*vas_log_init_log_fn)(int log_mode, int log_debug_level, const char* log_file);
    void      (*vas_log_deinit_log_fn)(void);
    vas_err_t (*vas_err_set_option_fn)(vas_ctx_t* ctx, int option, ... );
    vas_err_t (*vas_ctx_alloc_with_flags_fn)(vas_ctx_t **ctx, vas_err_info_t **errinfo, int ctx_flags );
    vas_err_t (*vas_auth_check_client_membership_with_server_id_fn)(vas_ctx_t* ctx, vas_id_t* serverid, vas_id_t* clientid, vas_auth_t* auth, const char* group );
    apr_dso_handle_t       *dso_h;
} dso_fn_t;

/* functions */

vas_err_t auth_vas_user_alloc(auth_vas_cache *cache, const char *username, auth_vas_user **outuser);

void auth_vas_user_ref(auth_vas_user *user);

void auth_vas_user_unref(auth_vas_user *user);

const char * auth_vas_user_get_name(const auth_vas_user *user);

const char * auth_vas_user_get_principal_name(const auth_vas_user *user);

const vas_user_t * auth_vas_user_get_vas_user_obj(auth_vas_user *user);

vas_err_t auth_vas_user_authenticate(auth_vas_user *user, int credflags, const char *password);

vas_err_t auth_vas_user_use_gss_result(auth_vas_user *user, gss_cred_id_t cred, gss_ctx_id_t context, const dso_fn_t *dso_fn);

vas_err_t auth_vas_is_user_in_group(auth_vas_user *user, const char *group, const dso_fn_t *dso_fn);

vas_err_t auth_vas_user_get_vas_user(const auth_vas_user *avuser, vas_user_t **vasuserp);

vas_err_t auth_vas_user_set_vas_user_obj(auth_vas_user *vasuser);


#ifdef __cplusplus
} /* extern C */
#endif

#endif /* MAV_USER_H */
/* vim: ts=8 sw=4 noet
 */
