# (c) 2006 Quest Software. All right reserved.

AC_INIT([mod_auth_vas], 
        [3.5.0.]esyscmd((svnversion . /trunk || echo 0) | tr : _ | tr -d \\012),
	[support@quest.com])
AC_CONFIG_AUX_DIR([.])
AM_INIT_AUTOMAKE

AC_CONFIG_SRCDIR([mod_auth_vas.c])
AC_CONFIG_FILES([Makefile])

AC_PREFIX_DEFAULT([/opt/quest])

AC_CACHE_CHECK([if ${MAKE-make} understands patsubst], [ac_cv_prog_gnu_make], 
[
   cat <<'__EOF' >conftest.mk
Wc=-Wc,
CFLAGS=-foo -bar -Wc,-baz
all:
    test x"$(patsubst $(Wc)$(Wc)%,$(Wc)%,$(CFLAGS:%=$(Wc)%))" = \
	              x"-Wc,-foo -Wc,-bar -Wc,-baz"
__EOF
    AS_IF([(${MAKE-make} -f conftest.mk all) 2>&AS_MESSAGE_LOG_FD 1>&2],
    [ac_cv_prog_gnu_make=yes], 
    [ac_cv_prog_gnu_make=no])])
if test $ac_cv_prog_gnu_make = no; then
    AC_MSG_FAILURE([${MAKE-make} does not understand GNU make patsubst])
fi

dnl -- platform detection
AC_CACHE_CHECK([platform type], [ac_cv_var_platform],
    [ac_cv_var_platform=unknown
     case `uname -s 2>/dev/null` in
       AIX)	ac_cv_var_platform=aix;;
       HP-UX)	ac_cv_var_platform=hpux;;
       Linux)	if rpm -q suse-release >/dev/null 2>&1; then
       		    ac_cv_var_platform=suse
		elif rpm -q redhat-release >/dev/null 2>&1; then
		    ac_cv_var_platform=redhat
		elif rpm -q fedora-release >/dev/null 2>&1; then
		    ac_cv_var_platform=fedora
		fi;;
       SunOS)	ac_cv_var_platform=solaris;;
     esac])

dnl -- APXS is Apache's extension tool.
dnl    We trust it completely to do the right thing.
dnl    If it is busted, then the user is on their own.
AC_ARG_WITH(apxs,
	    AS_HELP_STRING([--with-apxs=program-path],
	    		   [Specify location of Apache extension tool]),,
	    [with_apxs=default])
dnl -- Search path for finding apxs2/apxs
APXS_PATH="$PATH"
APXS_PATH="$APXS_PATH:/opt/hpws/apache/bin"
APXS_PATH="$APXS_PATH:/opt/IBMIHS/bin:/usr/IBMIHS/bin:/opt/freeware/bin"
APXS_PATH="$APXS_PATH:/usr/apache2/bin"
APXS_PATH="$APXS_PATH:/usr/local/bin:/usr/sbin:/usr/bin"
APXS_PATH="$APXS_PATH:/usr/local/apache2:/usr/local/apache"

if test x"$with_apxs" = x"default"; then
    AC_PATH_PROG([APXS2], [apxs2], [no], [$APXS_PATH])
    if test x"$APXS2" = x"no"; then
	AC_PATH_PROG([APXS], [apxs], [no], [$APXS_PATH])
    else
	APXS="$APXS2"
    fi
else
    APXS="$with_apxs"
fi
if test x"$APXS" = x"no"; then
    AC_MSG_FAILURE([no apxs found. Is the Apache developer kit installed?])
fi
AC_SUBST(APXS)

dnl -- use this as a sanity test that apxs is working
AC_MSG_CHECKING([Apache extension target])
apxs_target=`$APXS -q TARGET || echo error`
AC_MSG_RESULT([$apxs_target])

if test x"$apxs_target" = x"error"; then
    AC_MSG_FAILURE([$APXS does not appear to work])
fi

APXSFLAGS=

#other apxs vars:
# CC CFLAGS CFLAGS_SHLIB INCLUDEDIR LDFLAGS_SHLIB LD_SHLIB LIBEXECDIR
# LIBS_SHLIB PREFIX SBINDIR SYSCONFDIR TARGET
AC_CACHE_CHECK([what compiler apxs uses], [ac_cv_var_apxs_cc],
	[ac_cv_var_apxs_cc=`$APXS -q CC`])

#-- Try to use the C compiler APXS recommends
if test x"$ac_cv_var_apxs_cc" != x"" -a x"$CC" = x""; then
    CC="$ac_cv_var_apxs_cc"
    # Try to find this CC if it's not already in the PATH
    # (Include the dir's trailing '/')
    for dir in '' /usr/local/bin/ /usr/vac/bin/ /usr/ccs/bin/ /opt/freeware/bin/; do
	if which "$dir$CC" >/dev/null 2>&1; then
	    # Looks good
	    CC="$dir$CC"
	    break
	fi
    done
fi
AC_PROG_CC

#-- Override CC if we found a different C compiler
if test x"$ac_cv_var_apxs_cc" != x"$CC"; then
    APXSFLAGS="$APXSFLAGS -S CC='$CC'"
fi

#-- check for the -bexpall linker flag (needed on AIX for apache 1.3.31)
LDFLAGS_save="$LDFLAGS"
LDFLAGS="$LDFLAGS -Wl,-bexpall"
AC_CACHE_CHECK([whether -bexpall works], [ac_cv_var_bexpall],
	[AC_TRY_LINK([],[],[ac_cv_var_bexpall=yes],[ac_cv_var_bexpall=no])])
if test x"$ac_cv_var_bexpall" != x"yes"; then
	LDFLAGS="$LDFLAGS_save"
fi

#-- use the +DAportable flag if it is supported
CFLAGS_save="$CFLAGS"
CFLAGS="$CFLAGS +DAportable"
AC_CACHE_CHECK([whether $CC understands +DAPortable], [ac_cv_var_daportable],
    [AC_TRY_LINK([],[],[ac_cv_var_daportable=yes],[ac_cv_var_daportable=no])])
if test x"$ac_cv_var_daportable" != x"yes"; then
    CFLAGS="$CFLAGS_save"
fi

dnl Try to figure out what extension apxs uses by compiling a simple
dnl extension
AC_CACHE_CHECK([apxs intermediate extension], [ac_cv_var_apxs_mod_ext], [
    rm -f conftest.*
    AC_LANG_CONFTEST([int module_conftest;])
    ac_cv_var_apxs_mod_ext=
    AS_IF([_AC_EVAL_STDERR("$APXS" -c $APXSFLAGS $LDFLAGS conftest.c >&AS_MESSAGE_LOG_FD 2>&1)], 
	  [for ext in .la .sl .so; do
	     if test -e conftest$ext; then
	       ac_cv_var_apxs_mod_ext=$ext
	       break
	    fi
           done])
 ])
if test -z "$ac_cv_var_apxs_mod_ext"; then
   AC_MSG_WARN([assuming intermediate .so extension for modules])
   DSOEXT=.so
else
   DSOEXT=$ac_cv_var_apxs_mod_ext
fi
AC_SUBST(DSOEXT)

dnl -- SuSE Linux with apache2
case $ac_cv_var_platform in
  suse)
    AC_MSG_CHECKING([for SuSE loadmodule.conf])
    if test -e `$APXS -q SYSCONFDIR`/sysconfig.d/loadmodule.conf; then
	    APXSFLAGS="$APXSFLAGS -S TARGET=sysconfig.d/loadmodule"
	    AC_MSG_RESULT(yes)
    else
	    AC_MSG_RESULT(no)
    fi
    ;;
esac

AC_SUBST(APXSFLAGS)

#-- check to see whether libgcc is required
AC_MSG_CHECKING([for libgcc])
if $CC -print-libgcc-file-name >/dev/null 2>/dev/null; then
	libgccfilename=`$CC -print-libgcc-file-name`
else
	libgccfilename=no
fi
AC_MSG_RESULT([$libgccfilename])

if test x"$libgccfilename" != x"no" -a x"$libgccfilename" != x""; then
	AC_MSG_CHECKING([whether linking libgcc works])
	CFLAGS_save="$CFLAGS"
	CFLAGS="$CFLAGS -Wl,$libgccfilename"
	AC_TRY_LINK([],[],
		    [ac_cv_var_libgccfilename=yes],
		    [ac_cv_var_libgccfilename=no])
	AC_MSG_RESULT([$ac_cv_var_libgccfilename])
	if test x"$ac_cv_var_libgccfilename" != x"yes"; then
		CFLAGS="$CFLAGS_save"
	fi
fi

# xxx - should test SUEXEC
CPPFLAGS="$CPPFLAGS -DHAVE_UNIX_SUEXEC"
#-- --enable-debug
AC_ARG_ENABLE(debug,
	    AS_HELP_STRING([--disable-debug],
			   [Disable debugging (default enabled)]),,
	    [enable_debug=yes])
case $enable_debug in
    yes)
	CPPFLAGS="$CPPFLAGS -DMODAUTHVAS_DIAGNOSTIC"
	CPPFLAGS="$CPPFLAGS -DMODAUTHVAS_VERBOSE"
	;;
esac

#-- --enable-developer
AC_ARG_ENABLE(developer,
	    AS_HELP_STRING([--enable-developer],
			   [Enable developer flags (default disabled)]),,
	    [enable_developer=no])
case $enable_developer in
   yes)
	AC_MSG_CHECKING([whether -Wall and -pedantic work])
	CFLAGS_save="$CFLAGS"
	CFLAGS="$CFLAGS -Wall -pedantic"
	AC_TRY_COMPILE([],[],[ac_cv_cc_wall_ok=yes],[ac_cv_cc_wall_ok=yes])
	AC_MSG_RESULT([$ac_cv_cc_wall_ok])
	if test x"$ac_cv_cc_wall_ok" != x"yes"; then
	    CFLAGS="$CFLAGS_save"
	fi
	;;
esac

#-- --enable-tests
AC_ARG_ENABLE(tests,
	    AS_HELP_STRING([--enable-tests],
			   [Enable tests (default auto)]),,
	    [enable_tests=auto])

if test x"$enable_tests" = x"auto"; then
    AC_CACHE_CHECK([whether tests are available], [quest_cv_opt_havetests],
	   [quest_cv_opt_havetests=no
	    test -d $srcdir/test && quest_cv_opt_havetests=yes])
    enable_tests=$quest_cv_opt_havetests
fi

case $enable_tests in
   yes)	
	if test ! -d "$srcdir/test/http-get"; then
	    AC_MSG_ERROR([tests not available])
	fi
	AC_CONFIG_FILES([test/Makefile])
	AC_CONFIG_SUBDIRS([test/http-get])
	TESTDIR=test
	;;
   *)
	TESTDIR=
	;;
esac
AC_SUBST(TESTDIR)

#-- --with-vas
AC_ARG_WITH(vas,
	    AS_HELP_STRING([--with-vas=path],
			   [Specify location of VAS (default /opt/quest)]),,
	    [with_vas=default])
if test x"$with_vas" = x"default"; then
    AC_PATH_PROG([VASCONFIG], [vas-config], [no], [/opt/quest/bin:$PATH])
else
    AC_PATH_PROG([VASCONFIG], [vas-config], [no], [$with_vas/bin])
fi
if test x"$VASCONFIG" = x"no"; then
    AC_MSG_FAILURE([vas-config not found; is vasdev installed?])
fi

VAS_CFLAGS=`$VASCONFIG --cflags vasapi`
# Note: can't have -rpath in linker flags when apxs is using libtool
VAS_LIBS=`$VASCONFIG --libs vasapi | sed -e 's/-Wl,-rpath/-Wl,-R/g'`
AC_SUBST(VAS_CFLAGS)
AC_SUBST(VAS_LIBS)

# Try vasapi functions
CFLAGS_save="$CFLAGS" LIBS_save="$LIBS"
CFLAGS="$CFLAGS $VAS_CFLAGS" LIBS="$LIBS $VAS_LIBS"
AC_CHECK_FUNC([vas_ctx_alloc],,[
	       # Prevent the cached "no" being reused
	       $as_unset ac_cv_func_vas_ctx_alloc
	       # Try adding libgcc_s (VAS bug #12950)
	       LIBS="$LIBS -L/opt/quest/lib/support -lgcc_s"
	       AC_CHECK_FUNC([vas_ctx_alloc],
			     [VAS_LIBS="$VAS_LIBS -L/opt/quest/lib/support -lgcc_s"],
			     [AC_MSG_FAILURE([VAS 3 SDK required])])
	       ])
CFLAGS="$CFLAGS_save" LIBS="$LIBS_save"

AC_CHECK_FUNCS([getgrnam_r memset strcasecmp strchr strtol])
AC_CHECK_HEADERS([string.h])
AC_C_CONST
AC_FUNC_MEMCMP
AC_HEADER_STDC
AC_TYPE_SIZE_T
# Too recent for some autoconfs
#AC_TYPE_UINT32_T

AC_OUTPUT
