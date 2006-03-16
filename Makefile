# $Vintela: Makefile,v 1.12 2005/09/15 04:14:14 davidl Exp $
# (c) 2005 Quest Software, Inc. All rights reserved.

#-- Uncomment the following for SuSE linux with apache2
#APXS=		/usr/sbin/apxs2
#APXSFLAGS=	-S TARGET=sysconfig.d/loadmodule

#-- Uncomment the following for AIX 5.1 with gcc and apache 1.3.31
#APXS=		/usr/sbin/apxs
#APXSFLAGS=	-S CC=gcc -Wl,-bexpall

#-- Uncomment the following for HPUX using hpuxwsApache and gcc
#APXS=           /opt/hpws/apache/bin/apxs
#APXSFLAGS=      -S CC=gcc

#-- Uncomment the following for Solaris with IBM HTTP Server 6
#   using gcc. (You will also need to remove the later MODSO definition
#CC=             /usr/local/bin/gcc
#APXS=           /opt/IBMIHS/bin/apxs
#APXSFLAGS=      -S CC=$(CC) -Wl,`$(CC) -print-libgcc-file-name`
#MODSO=          $(MOD).la

MOD=		mod_auth_vas
SRCS=		$(MOD).c
MODSO=		$(MOD).so
CPPFLAGS=	`/opt/vintela/vas/bin/vas-config --cflags` \
		-DHAVE_UNIX_SUEXEC
LDFLAGS=	`/opt/vintela/vas/bin/vas-config --libs`
DEBUG=		-DMODAUTHVAS_DIAGNOSTIC \
          	-DMODAUTHVAS_VERBOSE

#-- enable AP_DEBUG only if your apache was compiled with -DAP_DEBUG
#DEBUG+=	-DAP_DEBUG -Wc,-g -Wc,-Wall

all: $(MODSO)

# apxs bug: apxs will do the wrong thing when given options "-o $@"
$(MODSO): $(SRCS)
	@if test ! -n "$(APXS)"; then \
		echo "** Please define APXS in the Makefile" >&2; exit 1; fi
	rm -f $(MODSO)
	$(APXS) -c $(APXSFLAGS) \
	    $(CPPFLAGS) $(LDFLAGS) $(LDADD) $(DEBUG) $(SRCS)
	#-- the following line may be needed if libtool is broken
	#gcc -shared -o $(MODSO) $(LDFLAGS) $(LDADD) $(MOD).o

install: $(MODSO)
	$(SUDO) $(APXS) -i $(APXSFLAGS) -a $(MODSO)

clean:
	rm -rf .libs $(MOD).la $(MOD).slo $(MOD).lo $(MOD).so $(MOD).o

# Simple dist, used by davidl
DISTFILES = $(SRCS) Makefile README ChangeLog NEWS auth_vas.conf setup.sh
dist:
	PKG=$(MOD)-`sed -ne \
	    '/^#define MODAUTHVAS_VERSION/s/.*"\([^"]*\)"/\1/p' <$(MOD).c`;\
	echo "** package name: $$PKG" \
	&& echo "** updating changelog" \
	&& cvs2cl -t \
	&& echo "** copying dist files to /tmp/$$PKG" \
	&& mkdir -p "/tmp/$$PKG" \
	&& cp $(DISTFILES) "/tmp/$$PKG" \
	&& echo "** creating $$PKG.tar.gz" \
	&& (cd /tmp && tar zfc - "$$PKG") > "$$PKG.tar.gz" \
	&& rm -rf "/tmp/$$PKG" \
	&& ls -l "$$PKG.tar.gz"

