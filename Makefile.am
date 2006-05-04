# $Id$

AUTOMAKE_OPTIONS=	no-dependencies foreign

# We make the module noinst here, and install with apxs-install target
noinst_DATA= 		mod_auth_vas$(DSO)
mod_auth_vas_SRCS=	mod_auth_vas.c

# Use -Wc and -Wl to protect linker options that aren't already protected
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

# Install the module using APXS
apxs-install:
	$(SUDO) $(APXS) -i $(APXSFLAGS) -a mod_auth_vas$(DSO)

# A handy shell script that performs setup checks
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
