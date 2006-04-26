#! /bin/sh
# (c) 2005 Quest Software, Inc. All rights reserved.
# $Id$
#
# This helper script is provided to simplify setting up mod_auth_vas
# on a basic web server. It creates the HTTP service for the computer
# (if not done), and changes ownerships on the resulting keytab.
#

KEYTAB=/etc/opt/quest/vas/HTTP.keytab
PKGNAME=apache2-mod_auth_vas
VASTOOL=/opt/quest/bin/vastool
KTUTIL=/opt/quest/bin/ktutil
LOGFILE=/tmp/mod_auth_vas-setup.log

echo1 () { echo -n "$*"; }
echo2 () { echo "$*\\c"; }
echo3 () { echo "$* +"; }

if test "x`echo1 y`z" = "xyz"; then
    echon() { echo1 "$*"; }
elif test "x`echo2 y`z" = "xyz"; then
    echon () { echo2 "$*"; }
else
    echon () { echo3 "$*"; }
fi

umask 077

#-- prints a label with dots after it, and no newline
label () {
    echon "  `echo $* ............................................... | cut -c -40`  "
}

#-- prints an error message and dies
die () {
    echo "  -> Failed: $1" >&2
    exit 1
}

#-- prompt user for information
#   usage: query prompt varname [default]
query () {
    eval $2=
    while eval "test ! -n \"\$$2\""; do
	if read xx?yy <$0 2>/dev/null; then
	    eval "read \"$2?$1${3+ [$3]}: \"" || die "(end of file)"
	else
	    eval "read -p \"$1${3+ [$3]}: \" $2" || die "(end of file)"
	fi
	eval : "\${$2:=\$3}"
    done
}

yesorno () {
    echo "";
    while :; do
	query "$1" YESORNO y
	case "$YESORNO" in
	    Y*|y*) echo; return 0;;
	    N*|n*) echo; return 1;;
	    *) echo "Please enter 'y' or 'n'" >&2;;
	esac
    done
}

logfile_written=false
recordcmd () {
    (echo "# `date`";
    echo "$*";
    echo ) >> $LOGFILE
    "$@"
    logfile_written=true
}

#-- intro
cat <<-.

	This script checks your local configuration for properly using mod_auth_vas.
	It will prompt you to create a web service object in Active Directory
	if one is needed, and it will correct permissions on certain files.
	Commands executed will be recorded in $LOGFILE

.

#-- tests
label "checking privileges"
id -un
if test `id -u` -ne 0; then
    checkroot () { 
	echo ""
	echo "WARNING: This script may need superuser privileges to proceed"
	echo ""
    }
else
    checkroot () { : ; }
fi


#label "version of mod_auth_vas"
#rpm -q $PKGNAME >/dev/null 2>&1 && rpm -q $PKGNAME || echo "rpm not found"

label "looking for apache conf"
AP_CF=
for apxs in apxs2 apxs /usr/sbin/apxs2 /usr/sbin/apxs; do
    AP_CF=`($apxs -q SYSCONFDIR) 2>/dev/null`/httpd.conf
    test -f "$AP_CF" && break
    AP_CF=
done
if test -f "$AP_CF"; then
    echo "$AP_CF"
    #echo "found"
    label "looking for apache daemon user"
    APACHE_USER=`(sed -ne 's/^User //p' < "$AP_CF"|sed -e 1q) 2>/dev/null`
    if test ! -n "$APACHE_USER"; then
	#-- try harder 
	for path in `sed -ne 's/^Include //p' < "$AP_CF"` /dev/null; do
	    APACHE_USER=`(sed -ne 's/^User //p' < "$path"|sed -e 1q) 2>/dev/null`
	    test -n "$APACHE_USER" && break
	done
    fi

    if test -n "$APACHE_USER"; then
	echo "$APACHE_USER"
    else
	echo "not found"
    fi
else
    APACHE_USER=
    echo "not found"
fi

label "looking for HTTP/ keytab"
if test -f "$KEYTAB"; then
    echo "$KEYTAB"
else
    echo "keytab not found"
    cat <<-.

	This step creates a service object in Active Directory so 
	that browsers can authenticate with this web server.
	You will need to know an account password that has
	sufficient privileges to create the new service object.
	Contact your systems administration staff if you do not.
.
    if yesorno "Create the HTTP/ service account?"; then
        echo "Please login with a domain account to create the HTTP/ service:"
        checkroot
        query "Username" USER Administrator
        recordcmd $VASTOOL -u "$USER" service create HTTP/ || \
	    die "Cannot create HTTP/ service key: contact your IT support"

	label "looking for HTTP/ keytab"
	if test -f "$KEYTAB"; then 
	    echo "found"
	else
	    echo "still not found"
	    die "Cannot find $KEYTAB"
	fi
	echo ""
	$KTUTIL -k "$KEYTAB" list
	echo ""
    else
	echo "(Not creating HTTP/ service account)"
    fi
fi

if test -f "$KEYTAB"; then
  if test ! -n "$APACHE_USER"; then
    echo ""
    echo "The apache server process must be able to access the keytab."
    echo "Tell me what username it will run as, and I'll correct the"
    echo "keytab file permissions so that it is readable."
    echo ""
    query "User for apache process" APACHE_USER nobody
    echo ""
  fi

  label "checking keytab is readable by $APACHE_USER"
  set -- `/bin/ls -l "$KEYTAB"`
  case "$1:$3" in
    -??????r??:*) echo "yes" ;;
    -r????????:$APACHE_USER) echo "yes" ;;
    *) echo "no"
       if yesorno "Change ownership of $KEYTAB to $APACHE_USER?"; then
           label " -> fixing file mode and ownership"
           checkroot
           recordcmd chown "$APACHE_USER" "$KEYTAB" || 
	       die "Could not change file owner"
           recordcmd chmod 400 "$KEYTAB" || 
	   	die "Could not change file mode"
           echo "fixed"
       else
	   echo "(Not changing ownership)"
       fi 
       ;;
  esac
fi

echo ""
$logfile_written && echo "(Log written to $LOGFILE)"
echo "Finished."
exit 0
