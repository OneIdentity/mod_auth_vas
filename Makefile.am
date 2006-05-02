
# $Id$

AUTOMAKE_OPTIONS=	no-dependencies foreign

aplibexecdir = @aplibexecdir@
aplibexec_DATA= 	mod_auth_vas$(DSO)
aplibexecDATA_INSTALL=	i () { $(apxs_install); } ; i
apxs_install = echo $(APXS) -i -S LIBEXECDIR=`dirname $$2 2>/dev/null` -a -n `basename $$1 $(DSO)` $$1 

mod_auth_vas_SRCS=	mod_auth_vas.c

Wc:=-Wc,
Wl:=-Wl,
mod_auth_vas$(DSO): $(mod_auth_vas_SRCS)
	$(APXS) -c $(APXSFLAGS) \
		$(CPPFLAGS) \
		$(patsubst $(Wc)$(Wc)%,$(Wc)%,$(CFLAGS:%=$(Wc)%)) \
		$(patsubst $(Wc)$(Wc)%,$(Wc)%,$(VAS_CFLAGS:%=$(Wc)%)) \
		$(patsubst $(Wl)$(Wl)%,$(Wl)%,$(LDFLAGS:%=$(Wl)%)) \
		$(patsubst $(Wl)$(Wl)%,$(Wl)%,$(VAS_LIBS:%=$(Wl)%)) \
		-o $@ \
		$^
apxs-install:
	$(SUDO) $(APXS) -i $(APXSFLAGS) -a mod_auth_vas$(DSO)

sbin_SCRIPTS=  setup-mod_auth_vas

EXTRA_DIST=	ChangeLog NEWS README $(mod_auth_vas_SRCS)
CLEANFILES=	ChangeLog

ChangeLog:
	svn2cl || echo No changelog > $@

DIST_SUBDIRS=	test
if ENABLE_TESTS
SUBDIRS=	. test
endif

#-- targets needed for automated test/build
print-dist-archives:; echo $(DIST_ARCHIVES)
print-dist-name:;     echo $(distdir)
