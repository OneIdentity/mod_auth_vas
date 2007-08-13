# Process this file with autoconf to produce a configure script.
AC_INIT([http-get], [0.1], [David.Leonard@quest.com])
AC_REVISION($Id$)
AC_CONFIG_AUX_DIR([.])
AM_INIT_AUTOMAKE

AC_CONFIG_SRCDIR([get.c])
AC_CONFIG_HEADER([config.h])

AC_PROG_CC

# Checks for libraries.
AC_PATH_PROG(VASCONFIG, [vas-config], [no], 
	     [/opt/quest/bin:/opt/vintela/vas/bin:$PATH])
if test x"$VASCONFIG" != x"no"; then
  LIBS="$LIBS `$VASCONFIG --libs`"
  CPPFLAGS="$CPPFLAGS `$VASCONFIG --cflags`"
fi

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([netdb.h stdlib.h string.h sys/socket.h unistd.h])
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h])
AC_CHECK_HEADERS([vas.h vas_gss.h gssapi.h gssapi_krb5.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
dnl Too recent for some autoconfs
dnl AC_TYPE_SSIZE_T

# Checks for library functions.
dnl Having a malloc that returns a valid pointer for malloc(0) is not
dnl particularly important. (AIX's xlc_r seems to fail this test.)
dnl AC_FUNC_MALLOC
AC_FUNC_VPRINTF
AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(hstrerror, resolv)
AC_CHECK_FUNCS([gethostbyname inet_ntoa memset socket strcasecmp strchr strdup strerror strncasecmp])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

