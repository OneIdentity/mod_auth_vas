# (c) 2008, Quest Software, Inc. All rights reserved.

abs_builddir=		@abs_builddir@

lib_LTLIBRARIES = mod_auth_vas4.la

AM_CFLAGS = $(VAS_CFLAGS) $(APR_CFLAGS) $(APR_INCLUDES) $(APXS_CFLAGS)
AM_CPPFLAGS = $(APXS_CPPFLAGS) $(APR_CPPFLAGS)
AM_LDFLAGS = $(VAS_LIBS) $(APR_LDFLAGS) $(APR_LIBS) $(APXS_LDFLAGS)
ACLOCAL_AMFLAGS=-I m4

mod_auth_vas4_la_SOURCES = \
			  mod_auth_vas4.c \
			  cache.c cache.h \
			  user.c user.h \
              group.c group.h \
			  log.h \
			  #

mod_auth_vas4_la_CPPFLAGS = $(AM_CPPFLAGS) \
			   -DMODAUTHVAS_VERSION=\"$(PACKAGE_VERSION)\"

mod_auth_vas4_la_LDFLAGS = $(AM_LDFLAGS) \
			  -module -avoid-version -export-dynamic

# Ensure the module does not leak symbols
check-local: mod_auth_vas4.la
	$(top_srcdir)/check-symbols.sh auth_vas .libs/mod_auth_vas4$(FINAL_DSOEXT)

# setup-mod_auth_vas4 is a setup wizard 
sbin_SCRIPTS=  setup-mod_auth_vas4

EXTRA_DIST=	NEWS README LICENCE NOTICE examples
EXTRA_DIST+=	$(sbin_SCRIPTS) check-symbols.sh
CLEANFILES=	setup-mod_auth_vas4 *.gcno *.gcda *.gcov

EXTRA_DIST+=	setup-mod_auth_vas4.in
CLEANFILES+=	setup-mod_auth_vas4
setup-mod_auth_vas4: setup-mod_auth_vas4.in
	sed -e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g' \
	    -e 's,[@]APXS[@],$(APXS),g' \
	    < $^ > $@
	chmod +x $@

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
         test-group-cache \
		 #

TESTS = $(check_PROGRAMS)

test_cache_SOURCES = test-cache.c cache.c cache.h compat.h
test_cache_CFLAGS = $(AM_CFLAGS) $(COVERAGE_CFLAGS)
test_cache_LDFLAGS = $(AM_LDFLAGS) $(COVERAGE_LDFLAGS)

test_group_cache_SOURCES = test-group-cache.c cache.c cache.h compat.h group.c group.h
test_group_cache_CFLAGS = $(AM_CFLAGS) $(COVERAGE_CFLAGS)
test_group_cache_LDFLAGS = $(AM_LDFLAGS) $(COVERAGE_LDFLAGS)


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
	@echo Package built successfully:
	@ls pkg/*.deb pkg/*.rpm pkg/*.pkg 2>/dev/null || true
