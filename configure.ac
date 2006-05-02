# (c) 2006 Quest Software. All right reserved.

AC_INIT([mod_auth_vas], 
        [3.2.1.]esyscmd(svnversion -n . /trunk),
	[apache@rc.vintela.com])
AM_INIT_AUTOMAKE

AC_CONFIG_SRCDIR([mod_auth_vas.c])
AC_CONFIG_FILES([Makefile])

AC_PROG_CC


dnl -- APXS is Apache's extension tool.
dnl    We trust it completely to do the right thing.
dnl    If it is busted, then the user is on their own.
AC_ARG_WITH(apxs,
	    AS_HELP_STRING([--with-apxs=path],
	    		   [Specify location of Apache extension tool]),
	    [ac_cv_with_apxs=$withval],
	    [ac_cv_with_apxs=default])
AC_CACHE_CHECK([where to find Apache extension tool], 
	       [ac_cv_with_apxs], 
	       [ac_cv_with_apxs=default])

dnl -- Search path for finding apxs2/apxs
APXS_PATH="$PATH"
APXS_PATH="$APXS_PATH:/opt/hpws/apache/bin"
APXS_PATH="$APXS_PATH:/opt/IBMIHS/bin"
APXS_PATH="$APXS_PATH:/usr/local/bin:/usr/sbin:/usr/bin"

if test x"$ac_cv_with_apxs" = x"default"; then
    AC_PATH_PROG([APXS2], [apxs2], [no], [$APXS_PATH])
    if test x"$APXS2" = x"no"; then
	AC_PATH_PROG([APXS], [apxs], [no], [$APXS_PATH])
    else
	APXS="$APXS2"
    fi
else
    AC_PATH_PROG([APXS], [$ac_cv_with_apxs], [no])
fi
if test x"$APXS" = x"no"; then
    AC_MSG_FAILURE([no apxs found. Is the Apache developer kit installed?])
fi
AC_SUBST(APXS)


dnl -- SuSE Linux with apache2
AC_MSG_CHECKING([for SuSE loadmodule.conf])
if test -e `$APXS -q SYSCONFDIR`/sysconfig.d/loadmodule.conf; then
	APXSFLAGS="$APXSFLAGS -S TARGET=sysconfig.d/loadmodule"
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi
AC_SUBST(APXSFLAGS)

#-- check for the -bexpall linker flag (needed on AIX for apache 1.3.31)
CFLAGS_save="$CFLAGS"
CFLAGS="$CFLAGS -Wl,-bexpall"
AC_CACHE_CHECK([whether -bexpall works], [ac_cv_var_bexpall],
	[AC_TRY_LINK([],[],[ac_cv_var_bexpall=yes],[ac_cv_var_bexpall=no])])
if test x"$ac_cv_var_bexpall" != x"yes"; then
	CFLAGS="$CFLAGS_save"
fi

#-- check to see whether libgcc is required
AC_MSG_CHECKING([for libgcc])
if $CC -print-libgcc-file-name >/dev/null 2>/dev/null; then
	libgccfn=no
else
	libgccfn=`$CC -print-libgcc-file-name`
fi
AC_MSG_RESULT([$libgccfn])

if test x"$libgccfn" != x"no" -a x"$libgccfn" != x""; then
	AC_MSG_CHECKING([whether linking libgcc works])
	CFLAGS_save="$CFLAGS"
	CFLAGS="$CFLAGS -Wl,$libgccfn"
	AC_TRY_LINK([],[],[ac_cv_var_libgccfn=yes],[ac_cv_var_libgccfn=no])
	AC_MSG_RESULT([$ac_cv_var_libgccfn])
	if test x"$ac_cv_var_libgccfn" != x"yes"; then
		CFLAGS="$CFLAGS_save"
	fi
fi

# xxx - should test SUEXEC
CPPFLAGS="$CPPFLAGS -DHAVE_UNIX_SUEXEC"
TEST_SUBDIRS=

#-- --enable-debug
AC_ARG_ENABLE(debug,
	    AS_HELP_STRING([--disable-debug],
			   [Disable debugging (default enabled)]),
	    [ac_cv_enable_debug=$withval],
	    [ac_cv_enable_debug=default])
case "$ac_cv_enable_debug" in
    yes|default)
	CPPFLAGS="$CPPFLAGS -DMODAUTHVAS_DIAGNOSTIC"
	CPPFLAGS="$CPPFLAGS -DMODAUTHVAS_VERBOSE"
	;;
esac

#-- --enable-developer
AC_ARG_ENABLE(developer,
	    AS_HELP_STRING([--enable-developer],
			   [Enable developer flags (default disabled)]),
	    [ac_cv_enable_developer=$withval],
	    [ac_cv_enable_developer=default])
case "$ac_cv_enable_developer" in
   yes)
	AC_MSG_CHECKING([whether -Wall and -pedantic work])
	CFLAGS_save="$CFLAGS"
	CFLAGS="$CFLAGS -Wall -pedantic"
	AC_TRY_COMPILE([],[],[ac_cv_cc_wall_ok=yes],[ac_cv_cc_wall_ok=yes])
	AC_MSG_RESULT([$ac_cv_cc_wall_ok])
	if test x"$ac_cv_cc_wall_ok" != x"yes"; then
	    CFLAGS="$CFLAGS_save"
	fi
	AC_CONFIG_SUBDIRS(test/http-get)
	TEST_SUBDIRS="test"
	;;
esac

#-- --with-vas
AC_ARG_WITH(vas,
	    AS_HELP_STRING([--with-vas=path],
			   [Specify location of VAS (default /opt/quest)]),
	    [ac_cv_with_vas=$withval],
	    [ac_cv_with_vas=default])
AC_CACHE_CHECK([where to find VAS], [ac_cv_with_vas], [ac_cv_with_vas=default])
if test x"$ac_cv_with_vas" = x"default"; then
    AC_PATH_PROG([VASCONFIG], [vas-config], [no], [/opt/quest/bin:$PATH])
else
    AC_PATH_PROG([VASCONFIG], [vas-config], [no], [$ac_cv_with_vas/bin])
fi
if test x"$VASCONFIG" = x"no"; then
    AC_MSG_FAILURE([vas-config not found; is vasdev installed?])
fi

VAS_CFLAGS=`$VASCONFIG --cflags vasapi`
VAS_LIBS=`$VASCONFIG --libs vasapi`
AC_SUBST(VAS_CFLAGS)
AC_SUBST(VAS_LIBS)
AC_SUBST(TEST_SUBDIRS)

AC_OUTPUT
