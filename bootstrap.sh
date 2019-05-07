#! /bin/sh
# (c) 2017 Quest Software, Inc. All rights reserved.
# Initialises the directory with autoconf after a respoitory check-out.

bootstrap () { 
    (set -x; cd "$1"
     rm -rf autom4te.cache install-sh missing Makefile.in configure aclocal.m4 config.h.in
     autoreconf --force --install
    )

    # uncomment PACKAGE_* variables to prevent redefine warnings
    # because apache headers redefines these unfortunately to empty - but fortunately we do not use them
    sed -i~ -e '/#undef PACKAGE_/ s|^/*|//|' -i config.h.in
}

set -e
if [ ! -d "./m4" ]; then
    echo "creating m4 directory"
    mkdir "m4"
fi
bootstrap .
bootstrap test/http-get
