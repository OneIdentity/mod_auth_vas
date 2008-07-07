#! /bin/sh
# (c) 2008 Quest Software, Inc. All rights reserved.
# Initialises the directory with autoconf after a respoitory check-out.

bootstrap () { 
    (set -x; cd "$1"
     rm -rf autom4te.cache install-sh missing Makefile.in configure aclocal.m4 config.h.in
     autoreconf --force --install
    )
}

set -e
bootstrap .
bootstrap test/http-get
