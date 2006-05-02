
# $Id$

AUTOMAKE_OPTIONS=	no-dependencies foreign

libexec_PROGRAMS= 	mod_auth_vas.so
mod_auth_vas_so_SOURCES=	mod_auth_vas.c
mod_auth_vas.so: $(mod_auth_vas_so_SOURCES)
	$(APXS) -c \
		$(CPPFLAGS) \
		$(CFLAGS:%=-Wc,%) \
		$(VAS_CFLAGS) \
		$(LDFLAGS) \
		$(VAS_LIBS) \
		$^
apxs-install:
	$(SUDO) $(APXS) -i $(APXSFLAGS) -a $(MODSO)

sbin_SCRIPTS=  setup-mod_auth_vas

EXTRA_DIST=	ChangeLog NEWS README
CLEANFILES=	ChangeLog

ChangeLog:
	svn2cl || echo No changelog > $@

SUBDIRS=	$(TEST_SUBDIRS)

#-- targets needed for automated test/build
print-dist-archives:; echo $(DIST_ARCHIVES)
print-dist-name:;     echo $(distdir)
