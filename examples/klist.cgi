#! /bin/sh
#
# This script can be used to easily test the effect of the
# AuthVasExportDelegated and AuthVasRemoteUserMap options.
#

echo 'Content-type: text/plain'
echo

exec 2>&1

echo You are $REMOTE_USER

if test -z $KRB5CCNAME; then
    echo "No credentials were delegated. Possible causes are:"
    echo " - the 'AuthVasExportDelegated' option is not enabled in your config;"
    echo " - this service is not trusted for delegation in Active Directory;"
    echo " - your TGT is not forwardable; or"
    echo " - your browser is not configured to delegate to this server."
    exit 1
fi

echo "Your TGT was delegated to this server."
echo

/opt/quest/bin/vastool klist -v
exit 0
