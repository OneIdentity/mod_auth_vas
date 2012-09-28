#ifndef MAV_COMPAT_H
#define MAV_COMPAT_H
/*
 * mod_auth_vas4: VAS4 authentication module for Apache.
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
 * compat.h: various #defines, cross-compatibility macros and convenience
 *           macros.
 */

/* From the GCC 4.1 manual */
#if __STDC_VERSION__ < 19901L
# if __GNUC__ >= 2
#  define __func__ __FUNCTION__
# else
#  define __func__ "<unknown>"
# endif
#endif

/* To determine the version of Apache */
#include <httpd.h>
#include <http_config.h>

#define __APPNAME__ "mod_auth_vas4"

# include <apr_strings.h>
# include <apr_tables.h>
# include <apr_base64.h>
# include <apr_general.h>
# include <apr_hash.h>
# include <apr_lib.h>
/* Always allocate RUSER(r) from RUSER_POOL(r) for the sake of Apache 1.3.
 * see http://httpd.apache.org/docs/1.3/misc/API.html#pools-used */
# define RUSER(r) (r)->user
# define RUSER_POOL(r) (r)->pool
# define RAUTHTYPE(r) (r)->ap_auth_type
# define SERVPOOL(s) (s)->process->pool

/*
 * Diagnostic assertions that may degrade performance.
 * Note: When an assertion fails, it indicates a *logical bug*. Do 
 * not use this macro for checking external-supplied parameters or 
 * preconditions, or for dealing with expected/possible runtime errors.
 */
#if defined(MODAUTHVAS_DIAGNOSTIC)
# define ASSERT(x)	   ap_assert(x)
#else
# define ASSERT(x)	   (void)0
#endif

/*
 * Convenience macros for obtaining per-server and per-dir config info
 * from various configuration vectors.
 */
#define GET_SERVER_CONFIG(cv) (auth_vas_server_config *)ap_get_module_config(cv, &auth_vas4_module)
#define GET_DIR_CONFIG(cv) (auth_vas_dir_config *)ap_get_module_config(cv, &auth_vas4_module)

/*
 * Macros for keeping the VAS context in the request record notes.
 * NB Request notes may not always be available.
 */
# define GET_RNOTE(r) (auth_vas_rnote *)ap_get_module_config((r)->request_config,  &auth_vas4_module)
# define SET_RNOTE(r, note) ap_set_module_config((r)->request_config, &auth_vas4_module, note)

#ifdef __GNUC__
# define MAV_UNUSED __attribute__((__unused__))
#else
# define MAV_UNUSED
#endif

#define streq(a,b) (strcmp((a),(b))==0)

#define IS_FORWARD_PROXY_REQUEST(r) ((r)->proxyreq == PROXYREQ_PROXY)

/** Macro for returning a value from the match functions via a cleanup label
 * (called finish) to make the code read more easily. */
#define RETURN(x) do { \
        result = (x); \
        goto finish; \
} while (0)

#endif /* MAV_COMPAT_H */
