#ifndef MiAV_LOG_H
#define MAV_LOG_H

/*
 * Authors:
 *  Jayson Hurst <jayson.hurst@quest.com>
 *
 */

#include <http_log.h>
#include "compat.h"
#include <vas_gss.h>

#if __GNUC__
#   define MAV_LOG_R(level,request,format,args...) ap_log_rerror(APLOG_MARK, level, OK, request, format, ##args)
#   define MAV_LOG_RERRNO(level,request,error,format,args...) ap_log_rerror(APLOG_MARK, level, error, request, format, ##args)
#   define MAV_LOG_S(level,s,format,args...) ap_log_error(APLOG_MARK, level, OK, s, format, ##args)
#   define MAV_LOG_SERRNO(level,s,error,format,args...) ap_log_error(APLOG_MARK, level, error, s, format, ##args)
#   define MAV_LOG_P(level,pool,format,args...) ap_log_perror(APLOG_MARK, level, OK, pool, format, ##args)
#   define MAV_LOG_PERRNO(level,pool,error,format,args...) ap_log_perror(APLOG_MARK, level, error, pool, format, ##args)
#else /* C99 */
#   define MAV_LOG_R(level, request, ...) ap_log_rerror(APLOG_MARK, level, OK, requst,__VA_ARGS__)
#   define MAV_LOG_RERRNO(level, request, error, ...) ap_log_rerror(APLOG_MARK, level, error, request, __VA_ARGS__)
#   define MAV_LOG_S(level, s, ...) ap_log_error(APLOG_MARK, level, OK, s, __VA_ARGS__)
#   define MAV_LOG_SERRNO(level, s, error,...) ap_log_error(APLOG_MARK, level, error, "%s", s, apr_psprintf(SERVERPOOL(s), __VA_ARGS__))
#   define MAV_LOG_P(level, pool, ...) ap_log_perror(APLOG_MARK, level, OK, pool,  "%s",  apr_psprintf(p, __VA_ARGS__))
#endif /* __GNUC__ */

#   define LOG_R(level,r,fmt,args...) ap_log_rerror(APLOG_MARK,level,OK,r,"%s: %s",__func__,apr_psprintf(RUSER_POOL(r),fmt,##args))
#   define LOG_P(level,p,fmt,args...) ap_log_perror(APLOG_MARK,level,OK,p,"%s: %s",__func__,apr_psprintf(p,fmt,##args))
#   define LOG_S(level,s,fmt,args...) ap_log_error(APLOG_MARK,level, OK, s, "%s: %s", __func__, apr_psprintf(SERVPOOL(s), fmt, ##args))

#if __GNUC__
#   define ERROR_R(r,f,a...)  MAV_LOG_R(APLOG_ERR, r, f, ##a)
#   define WARN_R(r,f,a...)   MAV_LOG_R(APLOG_WARNING,r,f,##a)
#   define DEBUG_R(r,f,a...)  MAV_LOG_R(APLOG_DEBUG, r, f, ##a)
#   define TRACE1_R(r,f,a...) MAV_LOG_R(APLOG_TRACE1, r, f, ##a)
#   define TRACE2_R(r,f,a...) MAV_LOG_R(APLOG_TRACE2, r, f, ##a)
#   define TRACE3_R(r,f,a...) MAV_LOG_R(APLOG_TRACE3, r, f, ##a)
#   define TRACE4_R(r,f,a...) MAV_LOG_R(APLOG_TRACE4, r, f, ##a)
#   define TRACE5_R(r,f,a...) MAV_LOG_R(APLOG_TRACE5, r, f, ##a)
#   define TRACE6_R(r,f,a...) MAV_LOG_R(APLOG_TRACE6, r, f, ##a)
#   define TRACE7_R(r,f,a...) MAV_LOG_R(APLOG_TRACE7, r, f, ##a)
#   define TRACE8_R(r,f,a...) MAV_LOG_R(APLOG_TRACE8, r, f, ##a)

#   define ERROR_S(s,f,a...)  MAV_LOG_S(APLOG_ERR,s,f,##a)
#   define WARN_S(s,f,a...)   MAV_LOG_S(APLOG_WARNING,s,f,##a)
#   define DEBUG_S(s,f,a...)  MAV_LOG_S(APLOG_DEBUG,s,f,##a)
#   define TRACE1_S(s,f,a...) MAV_LOG_S(APLOG_TRACE1,s,f,##a)
#   define TRACE2_S(s,f,a...) MAV_LOG_S(APLOG_TRACE2,s,f,##a)
#   define TRACE3_S(s,f,a...) MAV_LOG_S(APLOG_TRACE3,s,f,##a)
#   define TRACE4_S(s,f,a...) MAV_LOG_S(APLOG_TRACE4,s,f, ##a)
#   define TRACE5_S(s,f,a...) MAV_LOG_S(APLOG_TRACE5,s,f, ##a)
#   define TRACE6_S(s,f,a...) MAV_LOG_S(APLOG_TRACE6,s,f, ##a)
#   define TRACE7_S(s,f,a...) MAV_LOG_S(APLOG_TRACE7,s,f, ##a)
#   define TRACE8_S(s,f,a...) MAV_LOG_S(APLOG_TRACE8,s,f, ##a)

#   define ERROR_P(p,f,a...)  MAV_LOG_P(APLOG_ERR,p,f,##a)
#   define WARN_P(p,f,a...)   MAV_LOG_P(APLOG_WARNING,p,f,##a)
#   define DEBUG_P(p,f,a...)  MAV_LOG_P(APLOG_DEBUG,p,f,##a)
#   define TRACE1_P(p,f,a...) MAV_LOG_P(APLOG_TRACE1,p,f,##a)
#   define TRACE2_P(p,f,a...) MAV_LOG_P(APLOG_TRACE2,p,f,##a)
#   define TRACE3_P(p,f,a...) MAV_LOG_P(APLOG_TRACE3,p,f,##a)
#   define TRACE4_P(p,f,a...) MAV_LOG_P(APLOG_TRACE4,p,f, ##a)
#   define TRACE5_P(p,f,a...) MAV_LOG_P(APLOG_TRACE5,p,f, ##a)
#   define TRACE6_P(p,f,a...) MAV_LOG_P(APLOG_TRACE6,p,f, ##a)
#   define TRACE7_P(p,f,a...) MAV_LOG_P(APLOG_TRACE7,p,f, ##a)
#   define TRACE8_P(p,f,a...) MAV_LOG_P(APLOG_TRACE8,p,f, ##a)

#else /* C99 */
#   define ERROR_R(r,f,...)  MAV_LOG_R(APLOG_ERR, r, __VA_ARGS__)
#   define DEBUG_R(r,f,...)  MAV_LOG_R(APLOG_DEBUG, r, __VA_ARGS__)
#   define TRACE1_R(r,f,...) MAV_LOG_R(APLOG_TRACE1, r, __VA_ARGS__)
#   define TRACE2_R(r,f,...) MAV_LOG_R(APLOG_TRACE2, r, __VA_ARGS__)
#   define TRACE3_R(r,f,...) MAV_LOG_R(APLOG_TRACE3, r, __VA_ARGS__)
#   define TRACE4_R(r,f,...) MAV_LOG_R(APLOG_TRACE4, r, __VA_ARGS__)
#   define TRACE5_R(r,f,...) MAV_LOG_R(APLOG_TRACE5, r, __VA_ARGS__)
#   define TRACE6_R(r,f,...) MAV_LOG_R(APLOG_TRACE6, r, __VA_ARGS__)
#   define TRACE7_R(r,f,...) MAV_LOG_R(APLOG_TRACE7, r, __VA_ARGS__)
#   define TRACE8_R(r,f,...) MAV_LOG_R(APLOG_TRACE8, r, __VA_ARGS__)

#   define ERROR_S(s,f,...)  MAV_LOG_S(APLOG_ERR,s,__VA_ARGS__)
#   define DEBUG_S(s,f,...)  MAV_LOG_S(APLOG_DEBUG,s,__VA_ARGS__)
#   define TRACE1_S(s,f,...) MAV_LOG_S(APLOG_TRACE1,s,__VA_ARGS__)
#   define TRACE2_S(s,f,...) MAV_LOG_S(APLOG_TRACE2,s,__VA_ARGS__)
#   define TRACE3_S(s,f,...) MAV_LOG_S(APLOG_TRACE3,s,__VA_ARGS__)
#   define TRACE4_S(s,f,...) MAV_LOG_S(APLOG_TRACE4,s,__VA_ARGS__)
#   define TRACE5_S(s,f,...) MAV_LOG_S(APLOG_TRACE5,s,__VA_ARGS__)
#   define TRACE6_S(s,f,...) MAV_LOG_S(APLOG_TRACE6,s,__VA_ARGS__)
#   define TRACE7_S(s,f,...) MAV_LOG_S(APLOG_TRACE7,s,__VA_ARGS__)
#   define TRACE8_S(s,f,...) MAV_LOG_S(APLOG_TRACE8,s,__VA_ARGS__)

#   define ERROR_P(p,f,...)  MAV_LOG_P(APLOG_ERR,p,__VA_ARGS__)
#   define DEBUG_P(p,f,...)  MAV_LOG_P(APLOG_DEBUG,p,__VA_ARGS__)
#   define TRACE1_P(p,f,...) MAV_LOG_P(APLOG_TRACE1,p,__VA_ARGS__)
#   define TRACE2_P(p,f,...) MAV_LOG_P(APLOG_TRACE2,p,__VA_ARGS__)
#   define TRACE3_P(p,f,...) MAV_LOG_P(APLOG_TRACE3,p,__VA_ARGS__)
#   define TRACE4_P(p,f,...) MAV_LOG_P(APLOG_TRACE4,p,__VA_ARGS__)
#   define TRACE5_P(p,f,...) MAV_LOG_P(APLOG_TRACE5,p,__VA_ARGS__)
#   define TRACE6_P(p,f,...) MAV_LOG_P(APLOG_TRACE6,p,__VA_ARGS__)
#   define TRACE7_P(p,f,...) MAV_LOG_P(APLOG_TRACE7,p,__VA_ARGS__)
#   define TRACE8_P(p,f,...) MAV_LOG_P(APLOG_TRACE8,p,__VA_ARGS__)

#endif /* __GNUC__ */

/*
 * Trace macros for verbose debugging.
 *  TRACE_P - trace using a memory pool
 *  TRACE_S - trace in a server context
 *  TRACE_R - trace in a request context
 */
#if defined(MODAUTHVAS_VERBOSE)
# if __GNUC__
#  define TRACE_S(s,f,a...) MAV_LOG_S(APLOG_TRACE1,s,f,##a)
#  define TRACE_R(r,f,a...) MAV_LOG_R(APLOG_TRACE1,r,f,##a)
#  define TRACE_P(p,f,a...) MAV_LOG_P(APLOG_TRACE1,p,f,##a)
# else /* C99 */
#  define TRACE_S(s,...)    MAV_LOG_S(APLOG_TRACE1,s,__VA_ARGS__)
#  define TRACE_R(r,...)    MAV_LOG_R(APLOG_TRACE1,r,__VA_ARGS__)
#  define TRACE_P(p,...)    MAV_LOG_P(APLOG_TRACE1,p,__VA_ARGS__)
# endif
#else
# if __GNUC__
#  define TRACE_P(p,f,a...) /* nothing */
#  define TRACE_S(s,f,a...) /* nothing */
#  define TRACE_R(r,f,a...) /* nothing */
# else /* C99 */
#  define TRACE_P(p,...) /* nothing */
#  define TRACE_S(s,...) /* nothing */
#  define TRACE_R(r,...) /* nothing */
# endif
#endif

#define TRACE_DEBUG 1

/*
 * Prints trace messages to traceLogFileName
 */
#ifdef TRACE_DEBUG

    static FILE* traceLogFile = NULL;
    static const char *traceLogFileName = "/tmp/mav_debug_trace.log";

#   define tfprintf(fmt, args...){\
        traceLogFile = fopen( traceLogFileName, "a" );\
        if( traceLogFile ){\
            fprintf(traceLogFile, "%s - %s PID %d LINE %d FILE %s:%s MSG: ", __DATE__, __TIME__, getpid(), __LINE__, __FILE__, __FUNCTION__);\
            fprintf(traceLogFile, fmt, ##args);\
            fprintf(traceLogFile, "\n" );\
            fclose(traceLogFile);\
        }\
    }
#else
#   define tfprintf
#endif

/*
 * Prints a message with a GSS error code to traceLogFileName if TRACE_DEBUG is defined otherwise prints to stderr
 */
static void mav_print_gss_err(const char *prefix, OM_uint32 major_status, OM_uint32 minor_status)
{
    OM_uint32       majErr, minErr  = 0;
    OM_uint32       message_context = 0;
    gss_buffer_desc status_string   = GSS_C_EMPTY_BUFFER;

    if ( GSS_ERROR(major_status) || GSS_SUPPLEMENTARY_INFO(major_status) ) {
        /* First process the Major status code */
        do {
            /* Get the status string associated
 *                with the Major (GSS=API) status code */
            majErr = gss_display_status( &minErr, major_status, GSS_C_GSS_CODE, GSS_C_NO_OID, &message_context, &status_string );
            /* Print the status string */
            #ifdef TRACE_DEBUG
                tfprintf("%s: %.*s\n", prefix, (int)status_string.length, (char*)status_string.value );
            #else
                fprintf(stderr, "%s: %.*s\n", prefix, (int)status_string.length, (char*)status_string.value );
            #endif
            /* Free the status string buffer */
            gss_release_buffer( &minErr, &status_string );
        } while( message_context && !GSS_ERROR( majErr ) );

        /* Then process the Minor status code */
        do {
            /* Get the status string associated
 *                with the Minor (mechanism) status code */
            majErr = gss_display_status( &minErr, minor_status, GSS_C_MECH_CODE, GSS_C_NO_OID, &message_context, &status_string );
            /* Print the status string */
            #ifdef TRACE_DEBUG
                tfprintf(": %.*s\n", (int)status_string.length, (char*)status_string.value );
            #else
                fprintf(stderr, ": %.*s\n", (int)status_string.length, (char*)status_string.value );
            #endif
            /* Free the status string buffer */
            gss_release_buffer( &minErr, &status_string );
        } while( message_context && !GSS_ERROR( majErr ) );
    }
}

#endif /* MAV_LOG_H */
