# (c) 2008, Quest Software, Inc. All rights reserved.

abs_builddir=		@abs_builddir@

lib_LTLIBRARIES = mod_auth_vas.la

mod_auth_vas_la_SOURCES = \
			  mod_auth_vas.c \
			  cache.c cache.h \
			  user.c user.h \
			  mav_apr_hash.c mav_apr_hash.h \
			  #

mod_auth_vas_la_CFLAGS = $(VAS_CFLAGS) $(CFLAGS)
mod_auth_vas_la_CPPFLAGS = $(CPPFLAGS) $(DEFS) $(DEFAULT_INCLUDES) \
			   -DMODAUTHVAS_VERSION=\"$(PACKAGE_VERSION)\"
mod_auth_vas_la_LDFLAGS = $(VAS_LIBS) $(LDFLAGS) \
			  -module -avoid-version -export-dynamic

# Ensure the module does not leak symbols
if APXS1
check-local: mod_auth_vas$(LIBTOOL_DSOEXT)
	$(top_srcdir)/check-symbols.sh auth_vas $^
else # APXS2
check-local: mod_auth_vas$(LIBTOOL_DSOEXT)
	$(top_srcdir)/check-symbols.sh auth_vas .libs/mod_auth_vas$(FINAL_DSOEXT)
endif # APXS2

# setup-mod_auth_vas is a setup wizard 
sbin_SCRIPTS=  setup-mod_auth_vas

EXTRA_DIST=	NEWS README LICENCE NOTICE examples
EXTRA_DIST+=	$(sbin_SCRIPTS) auth_vas.conf check-symbols.sh
CLEANFILES=	setup-mod_auth_vas *.gcno *.gcda *.gcov

EXTRA_DIST+=	setup-mod_auth_vas.in
CLEANFILES+=	setup-mod_auth_vas
setup-mod_auth_vas: setup-mod_auth_vas.in
	sed -e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g' \
	    -e 's,[@]APXS[@],$(APXS),g' \
	    < $^ > $@
	chmod +x $@

install-conf: auth_vas.conf
	test -z "$(confdir)" || $(mkdir_p) "$(DESTDIR)$(confdir)"
	$(INSTALL_DATA) $^ "$(DESTDIR)$(confdir)/auth_vas.conf"

#EXTRA_DIST+=	ChangeLog
#CLEANFILES+=	ChangeLog
#ChangeLog:
#	svn2cl || echo No changelog > $@

SUBDIRS=	. $(TESTDIR) pkg
DISTCHECK_CONFIGURE_FLAGS= --disable-tests

#-- targets needed for automated test/build
print-dist-archives:; echo $(DIST_ARCHIVES)
print-dist-name:;     echo $(distdir)

check_PROGRAMS = \
		 test-cache \
		 #

TESTS = $(check_PROGRAMS)

test_cache_SOURCES = test-cache.c cache.c cache.h compat.h mav_apr_hash.c mav_apr_hash.h
test_cache_CPPFLAGS = $(CPPFLAGS) $(APR_CPPFLAGS) $(APR_INCLUDES)
test_cache_CFLAGS = $(VAS_CFLAGS) $(COVERAGE_CFLAGS)
#test_cache_LIBS = $(VAS_LIBS) $(APR_LIBS) $(APR_LINK_LIBTOOL)
test_cache_LDFLAGS = $(APR_LDFLAGS) $(APR_LINK_LD) $(COVERAGE_LDFLAGS)

if HAVE_COVERAGE

# Produces a code coverage report
coverage: check
	gcov *.gcda

else # !HAVE_COVERAGE

# No-op
coverage:

endif # !HAVE_COVERAGE

package:
	$(MAKE) -C $(top_builddir)/pkg package
