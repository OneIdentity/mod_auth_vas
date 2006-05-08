# $Id$

AUTOMAKE_OPTIONS=	foreign

# We make the module noinst here, and install with apxs-install target
noinst_DATA= 		mod_auth_vas$(DSO)
mod_auth_vas_SRCS=	mod_auth_vas.c

# Use -Wc and -Wl to protect linker options that aren't already protected
Wc:=-Wc,
Wl:=-Wl,
mod_auth_vas$(DSO): $(mod_auth_vas_SRCS)
	test -r mod_auth_vas.c || ln -s $(srcdir)/mod_auth_vas.c .
	$(APXS) -c $(APXSFLAGS) \
		$(CPPFLAGS) \
		$(patsubst $(Wc)$(Wc)%,$(Wc)%,$(CFLAGS:%=$(Wc)%)) \
		$(patsubst $(Wc)$(Wc)%,$(Wc)%,$(VAS_CFLAGS:%=$(Wc)%)) \
		$(patsubst $(Wl)$(Wl)%,$(Wl)%,$(LDFLAGS:%=$(Wl)%)) \
		$(patsubst $(Wl)$(Wl)%,$(Wl)%,$(VAS_LIBS:%=$(Wl)%)) \
		-o $@ \
		$(mod_auth_vas_SRCS)

clean-local:
	-rm -rf .libs mod_auth_vas.*o mod_auth_vas.l?

# Install the module using APXS
apxs-install:
	mkdir -p $(DESTDIR)`$(APXS) -q LIBEXECDIR`
	$(APXS) -i -S LIBEXECDIR=$(DESTDIR)`$(APXS) -q LIBEXECDIR` \
		$(APXSFLAGS) -a -n mod_auth_vas mod_auth_vas$(DSO)

# A handy shell script that performs setup checks
sbin_SCRIPTS=  setup-mod_auth_vas

EXTRA_DIST=	NEWS README $(mod_auth_vas_SRCS) $(sbin_SCRIPTS)

#EXTRA_DIST+=	ChangeLog
#CLEANFILES=	ChangeLog
#ChangeLog:
#	svn2cl || echo No changelog > $@

#DIST_SUBDIRS=	test

#-- targets needed for automated test/build
print-dist-archives:; echo $(DIST_ARCHIVES)
print-dist-name:;     echo $(distdir)
