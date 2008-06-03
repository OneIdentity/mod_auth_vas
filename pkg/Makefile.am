# (c) 2008 Quest Software, Inc.
# License at end of file.

AP1_MODINFO=500mod_auth_vas.info
AP2_MODLOAD=auth_vas.load
POLYPKGFILE=/data/rc/pub/rc/polypkg/pp
POLYPKGURI=http://rc.quest.com/pub/rc/polypkg/pp

EXTRA_DATA = $(AUXINFO_FILES)
EXTRA_DIST = pp mav.pp.in

CLEANFILES = $(AUXINFO_FILES)
DISTCLEANFILES = pp

if DISTRO_DEBIAN

# Module info file used by Apache 1 on Debian
# Only the LoadModule line is actually used (by apache-modconf)
$(AP1_MODINFO): ../mod_auth_vas.c
	echo "LoadModule: auth_vas_module $(AP_MODULEDIR)/mod_auth_vas$(FINAL_DSOEXT)" > $@
	echo "Directives:" >> $@
	@: 'Grab the list of directives from the source file'
	grep '^#define CMD_' $^ | sed -e 's,[^"]*"\([^"]*\).*, \1,' >> $@
	echo "Description: Negotiate & Basic authentication using Vintela Authentication Services" >> $@

# Module load file used by Apache 2 on Debian
$(AP2_MODLOAD):
	echo "LoadModule auth_vas_module $(AP_MODULEDIR)/mod_auth_vas$(FINAL_DSOEXT)" > $@

if  APXS1

AUXINFO_FILES = $(AP1_MODINFO)
POSTINST_ENABLECMD = apache-modconf apache enable mod_auth_vas
PRERM_DISABLECMD = apache-modconf apache disable mod_auth_vas

install-data-local: $(AP1_MODINFO)
	@: 'Module info file goes with module (/usr/lib/...)'
	$(mkdir_p) $(DESTDIR)/`$(APXS) -q LIBEXECDIR`
	cp $(AP1_MODINFO) $(DESTDIR)/`$(APXS) -q LIBEXECDIR`

else  # APXS2

AUXINFO_FILES = $(AP2_MODLOAD)
POSTINST_ENABLECMD = a2enmod auth_vas
PRERM_DISABLECMD = a2dismod auth_vas

install-data-local: $(AP2_MODLOAD)
	@: 'Module load file goes under sysconfdir (/etc/apache2/...)'
	$(mkdir_p) $(DESTDIR)/$(AP_SYSCONFDIR)/mods-available
	cp $(AP2_MODLOAD) $(DESTDIR)/$(AP_SYSCONFDIR)/mods-available

endif  # APXS2

endif # DISTRO_DEBIAN

pp:
	if [ -r "$(POLYPKGFILE)" ]; then \
	    ln -s $(POLYPKGFILE) $@; \
	elif which wget >/dev/null 2>&1; then \
	    wget -O $@ "$(POLYPKGURI)"; \
	elif which curl >/dev/null 2>&1; then \
	    curl -o $@ "$(POLYPKGURI)"; \
	else \
	    echo "Cannot figure out how to get polypkg"; \
	    exit 1; \
	fi

if APXS1
DEB_APACHE_VERSION = apache
RPM_APACHE_VERSION = ap1
else
# Append the minor version because 2.0 modules are not binary-compatible
# with 2.2 and vice-versa. This way the packages can be in the same directory
# without clashes.
DEB_APACHE_VERSION = apache2$(APACHE_MINOR_VERSION)
RPM_APACHE_VERSION = ap2$(APACHE_MINOR_VERSION)
endif

CLEANFILES += mav.pp

mav.pp: mav.pp.in
	sed \
	    -e 's,@DEBPKGNAME@,lib$(DEB_APACHE_VERSION)-mod-auth-vas,g' \
	    -e 's,@RPMPKGNAME@,mod_auth_vas-$(RPM_APACHE_VERSION),g' \
	    -e 's,@MODULEDIR@,$(AP_MODULEDIR),g' \
	    -e 's,@POSTINST_ENABLECMD@,$(POSTINST_ENABLECMD),g' \
	    -e 's,@PRERM_DISABLECMD@,$(PRERM_DISABLECMD),g' \
	    < $^ > $@

pkgdestdir=$(top_builddir)/pkg/destdir

package: pp mav.pp
	rm -rf "$(pkgdestdir)"
	$(mkdir_p) "$(pkgdestdir)"
	: Install from the parent dir to get the right paths
	$(MAKE) -C $(top_builddir) install DESTDIR=`(cd "$(pkgdestdir)" && pwd)`
	./pp \
	    --destdir=`(cd "$(pkgdestdir)" && pwd)` \
	    mav.pp \
	    version=`$(top_srcdir)/configure --version | head -n1 | cut -d' ' -f3 | sed -e 's,-,+,' -e 's,-,,g' -e 's,g,git,'` \
	    sbindir=$(sbindir) \
	    #
	rm -rf $(pkgdestdir)

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# a. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# b. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# c. Neither the name of Quest Software, Inc. nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
# OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
