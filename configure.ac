# (c) 2017 Quest Software. All right reserved.

dnl For exported trees, the version is derived from the NEWS file.
AC_INIT([mod_auth_vas], 
	esyscmd(if test -d .git && which git >/dev/null 2>&1; then echo -n `git describe``if ! git diff --quiet || ! git diff --cached --quiet; then echo M; fi`; else
	     echo -n `head -n1 NEWS | cut -f1`.exp; fi),
	[support@quest.com])
AC_PREREQ(2.55)
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_MACRO_DIR([m4])

m4_pattern_allow([AM_PROG_AR])
AM_PROG_AR

AM_INIT_AUTOMAKE([foreign -Wall])

AC_CONFIG_SRCDIR([mod_auth_vas.c])
AC_CONFIG_FILES([Makefile pkg/Makefile])

AC_PREFIX_DEFAULT([/opt/quest])

AC_LANG([C])

AH_BOTTOM([/* Bug 718: Compilation error with Oracle on RHEL if string.h
 * comes after httpd.h. */
#ifdef HAVE_STRING_H
#include <string.h>
#endif])

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
APXS_PATH="$APXS_PATH:/usr/apache/bin"
APXS_PATH="$APXS_PATH:/usr/local/bin:/usr/sbin:/usr/bin"
APXS_PATH="$APXS_PATH:/usr/local/apache2/bin:/usr/local/apache/bin"
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
AC_SUBST([APXS])

dnl -- use this as a sanity test that apxs is working
AC_MSG_CHECKING([Apache extension target])
apxs_target=`$APXS -q TARGET || echo error`
AC_MSG_RESULT([$apxs_target])

if test x"$apxs_target" = x"error"; then
    AC_MSG_FAILURE([$APXS does not appear to work])
fi

# The httpd binary is required to find out the Apache minor version number
AC_MSG_CHECKING([whether the Apache server is installed])
if test -x `$APXS -q SBINDIR`/`$APXS -q TARGET`; then
    AC_MSG_RESULT(yes)
else
    AC_MSG_RESULT(no)
    AC_MSG_ERROR([please install the Apache server (not just the devel package)])
fi

AC_MSG_CHECKING([what the Apache version is])
apache_version=$(`$APXS -q SBINDIR`/`$APXS -q TARGET` -V | grep '^Server version' | cut -d/ -f2)
AC_MSG_RESULT([$apache_version])
APACHE_MAJOR_VERSION=`echo $apache_version | cut -d. -f1`
APACHE_MINOR_VERSION=`echo $apache_version | cut -d. -f2`
AC_SUBST([APACHE_MAJOR_VERSION])
AC_SUBST([APACHE_MINOR_VERSION])

if test $APACHE_MAJOR_VERSION = 1; then
    case `$APXS -q CFLAGS` in
	*-DEAPI*) ;;
	*)
	AC_MSG_ERROR([Your server does not support EAPI. $PACKAGE_NAME 3.6 and later require EAPI, please use $PACKAGE_NAME 3.5])
	;;
    esac
fi

AM_CONDITIONAL(APXS1, [test $APACHE_MAJOR_VERSION = 1])

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
AC_PROG_LIBTOOL

#-- Override CC if we found a different C compiler
if test x"$ac_cv_var_apxs_cc" != x"$CC"; then
    APXSFLAGS="$APXSFLAGS -S CC='$CC'"
fi

AM_PROG_CC_C_O

dnl -- Flags to make GCC complain about your bugs
dnl Originally from Stallone <http://tedp.id.au/stallone/>, copied with permission.
if test "x$GCC" = "xyes"; then
    DESIRED_CFLAGS="-Wall -g"

    # Avoid requiring libraries unnecessarily
    # and use the common sysv symbol hash rather than new GNU_HASH (bug #636)
    DESIRED_LDFLAGS="-Wl,--as-needed -Wl,--hash-style=sysv"

    # Add stricter flags in developer mode
    if test "$enable_developer_mode" = "yes"; then
        DESIRED_CFLAGS="$DESIRED_CFLAGS -Wextra"
    fi

    for flag in $DESIRED_CFLAGS; do
        AC_MSG_CHECKING([whether ${CC} accepts ${flag}])
        orig_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS $flag"

        AC_COMPILE_IFELSE([AC_LANG_PROGRAM],
                          [AC_MSG_RESULT([yes])],
                          [AC_MSG_RESULT([no])
                           CFLAGS="$orig_CFLAGS"])
    done

    for flag in $DESIRED_LDFLAGS; do
        AC_MSG_CHECKING([whether ${CC} accepts ${flag}])
        orig_LDFLAGS="$LDFLAGS"
        LDFLAGS="$LDFLAGS $flag"

        AC_LINK_IFELSE([AC_LANG_PROGRAM],
                       [AC_MSG_RESULT([yes])],
                       [AC_MSG_RESULT([no])
                        LDFLAGS="$orig_LDFLAGS"])
    done
fi

#-- check for the -bexpall linker flag (needed on AIX for apache 1.3.31)
LDFLAGS_save="$LDFLAGS"
LDFLAGS="$LDFLAGS -Wl,-bexpall"
AC_CACHE_CHECK([whether -Wl,-bexpall works], [ac_cv_var_bexpall],
	[AC_TRY_LINK([],[],[ac_cv_var_bexpall=yes],[ac_cv_var_bexpall=no])])
if test x"$ac_cv_var_bexpall" != x"yes"; then
	LDFLAGS="$LDFLAGS_save"
fi

#-- use the +DAportable flag on HP-UX if it is supported
# Feel free to find a more reliable way to detect HP-UX
if test `uname -s` = "HP-UX"; then
    CFLAGS_save="$CFLAGS"
    CFLAGS="$CFLAGS +DAportable"
    AC_CACHE_CHECK([whether $CC understands +DAportable], [ac_cv_var_daportable],
	[AC_TRY_LINK([],[],[ac_cv_var_daportable=yes],[ac_cv_var_daportable=no])])
    if test x"$ac_cv_var_daportable" != x"yes"; then
	CFLAGS="$CFLAGS_save"
    fi
fi

AC_MSG_CHECKING([what the module's final file extension will be])
# The file extension that the module will be installed with.
# Usually .so. Sometimes libtool is not installed, in which case we assume .so
if which libtool >/dev/null 2>&1; then
    eval `libtool --config | grep ^shrext_cmds`
else
    shrext_cmds=.so
fi
AC_MSG_RESULT([$shrext_cmds])
AC_SUBST([FINAL_DSOEXT], [$shrext_cmds])

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

AC_SUBST([APXSFLAGS])

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
	LIBS_save="$LIBS"
	LIBS="$LIBS -l$libgccfilename"
	AC_TRY_LINK([],[],
		    [ac_cv_var_libgccfilename=yes],
		    [ac_cv_var_libgccfilename=no])
	AC_MSG_RESULT([$ac_cv_var_libgccfilename])
	if test x"$ac_cv_var_libgccfilename" != x"yes"; then
		LIBS="$LIBS_save"
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
AC_SUBST([TESTDIR])

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

# The APR_CONFIG variable shows up in apache 2.2
AC_MSG_CHECKING([whether $APXS defines APR_CONFIG])
if $APXS -q APR_CONFIG >/dev/null 2>&1; then # APXS 2.2
    AC_MSG_RESULT([yes])
    APR_CONFIG=`$APXS -q APR_CONFIG`
elif $APXS -q APR_BINDIR >/dev/null 2>&1; then # APXS 2.0
    AC_MSG_RESULT([no, but found APR_BINDIR])
    APR_CONFIG=`$APXS -q APR_BINDIR`/apr-config
else
    AC_MSG_RESULT([no])
fi

if test -n "$APR_CONFIG"; then
    APR_INCLUDES=`$APR_CONFIG --includes`
    APR_LIBS=`$APR_CONFIG --link-libtool --libs`
    APR_CFLAGS=`$APR_CONFIG --cflags`
    APR_CPPFLAGS=`$APR_CONFIG --cppflags`
    APR_LDFLAGS=`$APR_CONFIG --ldflags`
fi

AC_SUBST([APR_INCLUDES])
AC_SUBST([APR_LIBS])
AC_SUBST([APR_CFLAGS])
AC_SUBST([APR_CPPFLAGS])
AC_SUBST([APR_LDFLAGS])

AP_MODULEDIR=`"$APXS" -q LIBEXECDIR`
AP_SYSCONFDIR=`"$APXS" -q SYSCONFDIR`
AC_SUBST([AP_MODULEDIR])
AC_SUBST([AP_SYSCONFDIR])

# See whether the module info file should go in a directory like
# /etc/httpd/conf.d . It really depends on whether the config file has an
# Include directive but this should be reliable enough.
# Deb platforms don't use this.
AC_MSG_CHECKING([for a conf.d directory for the module info file])
if test -d ${AP_SYSCONFDIR}.d; then
    AP_CONF_D_DIR=${AP_SYSCONFDIR}.d
    AC_MSG_RESULT([yes, "$AP_CONF_D_DIR"])
else
    # Somewhere sane
    AP_CONF_D_DIR=$AP_SYSCONFDIR
    AC_MSG_RESULT([no])
fi
AC_SUBST([AP_CONF_D_DIR])

# Trust apxs' notion of where the files should go
libdir=$AP_MODULEDIR
sysconfdir=$AP_SYSCONFDIR

# APXS1 only has CFLAGS. APXS2 has the gamut of flags
APXS_CFLAGS=`$APXS -q CFLAGS`
if test $APACHE_MAJOR_VERSION = 2; then
    APXS_CPPFLAGS=`$APXS -q CPPFLAGS`
    APXS_LDFLAGS=`$APXS -q LDFLAGS`
fi
APXS_CPPFLAGS="-I`$APXS -q INCLUDEDIR` $APXS_CPPFLAGS"
AC_SUBST([APXS_CFLAGS])
AC_SUBST([APXS_CPPFLAGS])
AC_SUBST([APXS_LDFLAGS])

VAS_CFLAGS=`$VASCONFIG --cflags vasapi`
# Convert a GNU ld search path (-rpath) into a libtool search path (-R)
VAS_LIBS=`$VASCONFIG --libs vasapi | sed -e 's/-Wl,-rpath/-Wl,-R/g'`
# Remove libgcc_s flags. libgcc_s is a complicated affair:
# - on most GCC-based systems, libgcc_s is unnecessary and could cause errors
#   if other libraries require more recent versioned symbols than those
#   provided by VAS' libgcc_s (VAS bug #14342).
# - Building 32-bit binaries on x86_64, libgcc_s *must not* be specified because
#   VAS does not provide a 32-bit libgcc_s. (As seen on Solaris.) Otherwise
#   ./configure bombs saying it can't find the VAS SDK.
# - on AIX with Xlc, libgcc_s *must* be specified to avoid undefined symbols
#   when linking with libvas (VAS bug #12950). This is handled below where
#   if the link fails initially, we retry with -lgcc_s.
# This would be solved if:
# - libvas was compiled with -static-libgcc; or
# - VAS' libgcc_s was only installed if it contained *newer* versioned symbols
#   than the system's libgcc_s
# VAS bug #14342 has most of the details.
VAS_LIBS=`echo "$VAS_LIBS" | sed -e 's/-lgcc_s//g'`
AC_SUBST([VAS_CFLAGS])
AC_SUBST([VAS_LIBS])

# Try vasapi functions
LIBS_save="$LIBS"
CFLAGS="$CFLAGS $VAS_CFLAGS $APXS_CFLAGS" LIBS="$LIBS $VAS_LIBS"
CPPFLAGS="$CPPFLAGS $APXS_CPPFLAGS" LIBS="$LIBS $VAS_LIBS"
AC_CHECK_FUNC([vas_ctx_alloc],,[
	       # Prevent the cached "no" being reused
	       $as_unset ac_cv_func_vas_ctx_alloc
	       # Try adding libgcc_s (VAS bug #12950)
	       LIBS="$LIBS -L/opt/quest/lib/support -lgcc_s"
	       AC_CHECK_FUNC([vas_ctx_alloc],
			     [VAS_LIBS="$VAS_LIBS -L/opt/quest/lib/support -lgcc_s"],
			     [AC_MSG_FAILURE([VAS 3 SDK required])])
	       ])
LIBS="$LIBS_save"

AC_ARG_ENABLE([rcdev-tests],
	      [AS_HELP_STRING([--enable-rcdev-tests],
			      [Enable tests that rely on the Resource Central dev network])],
	      [case "${enableval}" in
	        yes) ENABLE_RCDEV_TESTS=yes ;;
		no)  ENABLE_RCDEV_TESTS=no ;;
		*) AC_MSG_ERROR([bad value ${enableval} for --enable-rcdev-tests]) ;;
	       esac],
	      [ENABLE_RCDEV_TESTS=no])
AM_CONDITIONAL(ENABLE_RCDEV_TESTS, test "x$ENABLE_RCDEV_TESTS" = "xyes")

# Solaris 8 provides an incompatible getgrnam_r by default (bug #587)
# Solution from http://article.gmane.org/gmane.comp.apache.logging.log4cxx.user/1664
AC_DEFINE(_POSIX_PTHREAD_SEMANTICS, 1, [For a compatible getgrnam_r on Solaris])

AC_CHECK_FUNCS([getgrnam_r memset strcasecmp strchr strtol])
AC_CHECK_HEADERS([string.h mod_auth.h ap_provider.h])
AC_C_CONST
AC_FUNC_MEMCMP
AC_FUNC_STRERROR_R
AC_HEADER_STDC
AC_TYPE_SIZE_T
dnl Added in autoconf 2.59c
dnl AC_TYPE_UINT32_T

# See if the compiler & linker understand --coverage
old_CFLAGS=$CFLAGS
old_LDFLAGS=$LDFLAGS
CFLAGS="--coverage $CFLAGS"
LDFLAGS="--coverage $LDFLAGS"
AC_MSG_CHECKING([whether $CC understands --coverage])
AC_LINK_IFELSE([AC_LANG_PROGRAM],
	[have_coverage_flags=yes
	 AC_SUBST([COVERAGE_CFLAGS], [--coverage])
	 AC_SUBST([COVERAGE_LDFLAGS], [--coverage])],
	[have_coverage_flags=no])
AC_MSG_RESULT([$have_coverage_flags])
AM_CONDITIONAL([HAVE_COVERAGE], [test "$have_coverage_flags" = "yes"])
# Restore flags, we don't want coverage information in the regular binaries
CFLAGS=$old_CFLAGS
LDFLAGS=$old_LDFLAGS

# This does not determine the package type, but how the module should be
# enabled automatically when the package is installed.
AC_MSG_CHECKING([which distribution type to build for])
AC_ARG_WITH(distro,
	    [AS_HELP_STRING([--with-distro=NAME], [Distribution type to generate auxiliary config files for (deb, rpm, none)])],
	    [distro="$with_distro"],
	    [# Try to detect distro
	     if `which lsb_release >/dev/null 2>&1`; then
		 distro=`lsb_release -is`
	     elif test -r /etc/debian_version; then
		 distro=deb
	     elif test -r /etc/redhat-release; then
		 distro=rpm
	     elif test -r /etc/SuSE-release; then
		 distro=rpm
	     fi
	     ])

# Ensure distro is lowercase for matching
distro=`echo "$distro" | tr '[[:upper:]]' '[[:lower:]]'`

case "$distro" in
    deb|debian|ubuntu)
	distro=deb;;
    rpm|centos|fedora*|suse*|redhat*)
	distro=rpm;;
    *)
	distro=none;;
esac
AC_MSG_RESULT([$distro])

# DISTRO_DEB is for a Debian-like config system (mods-available/mods-enabled)
AM_CONDITIONAL([DISTRO_DEB], [test "$distro" = 'deb'])
# DISTRO_RPM is for an Fedora-like config system (conf.d directory for module loading)
AM_CONDITIONAL([DISTRO_RPM], [test "$distro" = 'rpm'])

# The 32-bit hack should be done after everything else so that all the tests
# are done natively, then we just make some adjustments
AC_ARG_ENABLE([32bit-on-64bit],
	      [AS_HELP_STRING([--enable-32bit-on-64bit],
			      [Build a 32-bit module even if the machine is 64-bit (experimental)])])
if test "$enable_32bit_on_64bit" = "yes"; then
    VAS_LIBS=`echo $VAS_LIBS | sed -e 's,lib64,lib,g' | sed -e 's,-lgcc_s,,g'`
    CFLAGS="$CFLAGS -m32"
fi

AC_OUTPUT
