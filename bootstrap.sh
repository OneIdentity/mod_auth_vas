#! /bin/sh
# $Id$
# 

bootstrap () { 
    rm -rf autom4te.cache install-sh missing Makefile.in configure aclocal.m4
    autoreconf --install
}

(cd test/http-get && bootstrap && autoheader)
bootstrap
