# (c) 2006, Quest Software, Inc. All rights reserved.

AUTOMAKE_OPTIONS=	foreign

#-- set this to -a to cause 'make install' to activate the module (unreliable)
APXS_ACTIVATE=		# -a

# We make the module noinst here, and install with apxs-install target
noinst_DATA= 		mod_auth_vas$(DSOEXT)
mod_auth_vas_SRCS=	mod_auth_vas.c
abs_builddir=		@abs_builddir@

# Use -Wc and -Wl to protect linker options that aren't already protected
Wc=-Wc,
Wl=-Wl,

# NB: copy the sources locally so that apxs doesn't get confused
mod_auth_vas$(DSOEXT): $(mod_auth_vas_SRCS)
	cmp $(srcdir)/mod_auth_vas.c ./mod_auth_vas.c 2>/dev/null || \
	  cp $(srcdir)/mod_auth_vas.c .
	$(APXS) -c $(APXSFLAGS) \
		$(CPPFLAGS) \
		-DMODAUTHVAS_VERSION='\"$(PACKAGE_VERSION)\"' \
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
		$(APXSFLAGS) $(APXS_ACTIVATE) -n auth_vas \
		mod_auth_vas$(DSOEXT)

# setup-mod_auth_vas is a setup wizard 
sbin_SCRIPTS=  setup-mod_auth_vas

EXTRA_DIST=	NEWS README LICENCE
EXTRA_DIST+=	$(mod_auth_vas_SRCS) $(sbin_SCRIPTS) auth_vas.conf
CLEANFILES=	setup-mod_auth_vas


setup-mod_auth_vas: setup-mod_auth_vas.in
	sed -e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g' \
	    < $^ > $@
	chmod +x $@

install-conf: auth_vas.conf
	test -z "$(confdir)" || $(mkdir_p) "$(DESTDIR)$(confdir)"
	$(INSTALL_DATA) $^ "$(DESTDIR)$(confdir)/auth_vas.conf"

#EXTRA_DIST+=	ChangeLog
#CLEANFILES+=	ChangeLog
#ChangeLog:
#	svn2cl || echo No changelog > $@

DIST_SUBDIRS=	$(TESTDIR)
SUBDIRS=	. $(TESTDIR)
DISTCHECK_CONFIGURE_FLAGS= --disable-tests

#-- targets needed for automated test/build
print-dist-archives:; echo $(DIST_ARCHIVES)
print-dist-name:;     echo $(distdir)

#-- targets for RPM building
EXTRA_DIST+= suse.spec.in redhat.spec.in
CLEANFILES+= suse.spec redhat.spec .rpmmacros

subst=  sed -e 's,[@]VERSION[@],$(VERSION),g' \
	    -e 's,[@]abs_builddir[@],$(abs_builddir),g' \
	    -e 's,[@]sbindir[@],$(sbindir),g' \
	    -e 's,[@]APXS[@],$(APXS),g' 

.rpmmacros: Makefile
	echo '%_rpmdir $(abs_builddir)' > .rpmmacros
	echo '%_builddir $(abs_builddir)' >> .rpmmacros

suse-rpm: suse.spec .rpmmacros
	HOME=$(abs_builddir) rpmbuild -bb suse.spec

suse.spec: suse.spec.in
	    $(subst) < $^ > $@

redhat-ap1-rpm: redhat.spec .rpmmacros
	HOME=$(abs_builddir) rpmbuild -bb \
	     	--define='apxs1 1' \
		--define="apache_libdir `$(APXS) -q LIBEXECDIR`" \
		--define="apache_sysconfdir `$(APXS) -q SYSCONFDIR`" \
		redhat.spec

redhat-ap2-rpm: redhat.spec .rpmmacros
	HOME=$(abs_builddir) rpmbuild -bb \
		--define="apache_libdir `$(APXS) -q LIBEXECDIR`" \
		--define="apache_sysconfdir `$(APXS) -q SYSCONFDIR`" \
		redhat.spec

redhat.spec: redhat.spec.in
	    $(subst) < $^ > $@


