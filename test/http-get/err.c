/* $Vintela: err.c,v 1.1 2005/04/10 07:03:55 davidl Exp $ */
/* Copyright 2005, David Leonard, Vintela. */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include "err.h"

void err(int exitcode, const char *fmt, ...) {
    int saverrno = errno;
    va_list ap;
    fprintf(stderr, "error: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, ": %s\n", strerror(saverrno));
    exit(exitcode);
}

void errx(int exitcode, const char *fmt, ...) {
    va_list ap;
    fprintf(stderr, "error: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    exit(exitcode);
}

void warn(const char *fmt, ...) {
    int saverrno = errno;
    va_list ap;
    fprintf(stderr, "warning: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, ": %s\n", strerror(saverrno));
}

void warnx(const char *fmt, ...) {
    va_list ap;
    fprintf(stderr, "warning: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}
