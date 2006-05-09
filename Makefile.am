# $Id$

AUTOMAKE_OPTIONS=	foreign

# We make the module noinst here, and install with apxs-install target
noinst_DATA= 		mod_auth_vas$(DSOEXT)
mod_auth_vas_SRCS=	mod_auth_vas.c

# Use -Wc and -Wl to protect linker options that aren't already protected
Wc:=-Wc,
Wl:=-Wl,

# NB: copy the sources locally so that apxs doesn't get confused
mod_auth_vas$(DSOEXT): $(mod_auth_vas_SRCS)
	test "$(srcdir)" = "$(builddir)" || cp $(srcdir)/mod_auth_vas.c .
	$(APXS) -c $(APXSFLAGS) \
		$(CPPFLAGS) \
		-DPACKAGE_VERSION='\"$(PACKAGE_VERSION)\"' \
		$(patsubst $(Wc)$(Wc)%,$(Wc)%,$(CFLAGS:%=$(Wc)%)) \
		$(patsubst $(Wc)$(Wc)%,$(Wc)%,$(VAS_CFLAGS:%=$(Wc)%)) \
		$(patsubst $(Wl)$(Wl)%,$(Wl)%,$(LDFLAGS:%=$(Wl)%)) \
		$(patsubst $(Wl)$(Wl)%,$(Wl)%,$(VAS_LIBS:%=$(Wl)%)) \
		-o $@ \
		-n auth_vas \
		mod_auth_vas.c

clean-local:
	-rm -rf .libs mod_auth_vas.*o mod_auth_vas.l?

# use apxs to install the module, inserting DESTDIR as best we can
install-data-local:
	mkdir -p $(DESTDIR)`$(APXS) -q LIBEXECDIR`
	mkdir -p $(DESTDIR)`$(APXS) -q SYSCONFDIR`
	$(APXS) -i -S LIBEXECDIR=$(DESTDIR)`$(APXS) -q LIBEXECDIR` \
		   -S SYSCONFDIR=$(DESTDIR)`$(APXS) -q SYSCONFDIR` \
		$(APXSFLAGS) -a -n auth_vas \
		mod_auth_vas$(DSOEXT)

# setup-mod_auth_vas is a setup wizard 
sbin_SCRIPTS=  setup-mod_auth_vas

EXTRA_DIST=	NEWS README $(mod_auth_vas_SRCS) $(sbin_SCRIPTS)

#EXTRA_DIST+=	ChangeLog
#CLEANFILES=	ChangeLog
#ChangeLog:
#	svn2cl || echo No changelog > $@

DIST_SUBDIRS=	test
SUBDIRS=	. $(TESTDIR)
DISTCHECK_CONFIGURE_FLAGS= --disable-tests

#-- targets needed for automated test/build
print-dist-archives:; echo $(DIST_ARCHIVES)
print-dist-name:;     echo $(distdir)
