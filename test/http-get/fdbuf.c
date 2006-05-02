/* $Vintela: fdbuf.c,v 1.1 2005/04/10 07:03:55 davidl Exp $ */
/* Copyright 2005, David Leonard, Vintela. */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "fdbuf.h"
#include "err.h"

extern int debug;

/* Initialise a file descriptor buffer to empty */
void
fdbuf_init(f, fd)
    struct fdbuf *f;
    int fd;
{
    f->wpos = f->rpos = 0;
    f->fd = fd;
    f->f = fd < 0 ? NULL : fdopen(fd, "wb");
    if (debug) fprintf(stderr, "fdbuf_init: fd=%d f=%p\n", f->fd, f->f);
}

/*
 * Copies data from the file desc buffer. If the buffer is exhausted, reads
 * from the file descriptor to re-fill the buffer. Returns -1 on EOF.
 */
int
fdbuf_read(f, buf, bufsz)
    struct fdbuf *f;
    char *buf;
    int bufsz;
{
    int len;
    int rlen;

    if (bufsz <= 0)
	return 0;
    if (f->fd == -1)
	return -1;
    fflush(f->f);
    if (f->wpos == f->rpos) {
	f->wpos = f->rpos = 0;
	/* rlen = bufsz > sizeof f->buf ? sizeof f->buf : bufsz; */
	rlen = sizeof f->buf - f->wpos;
	len = read(f->fd, f->buf + f->wpos, rlen);
	if (debug) 
	    fprintf(stderr, "fdbuf_read: read(%d) -> %d\n", rlen, len);
	if (len <= 0) {
	    close(f->fd);
	    fclose(f->f);
	    f->fd = -1;
	    f->f = NULL;
	    return len;
	}
	f->wpos += len;
    }
    len = f->wpos - f->rpos;
    if (len > bufsz)
	len = bufsz;
    if (len < 0)
	abort();
    else if (len > 0)
	memcpy(buf, f->buf + f->rpos, len);
    f->rpos += len;
    return len;
}

/* Reads one char from the file */
int
fdbuf_getc(f)
    struct fdbuf *f;
{
    char ch;
    int len;
   
    len = fdbuf_read(f, &ch, 1);
    if (len <= 0)
	return EOF;
    else
	return (unsigned char)ch;
}

/* Places a character back on the buffer which will be returns
 * by the next read ahead of other data. 
 */
void
fdbuf_ungetc(f, ch)
    struct fdbuf *f;
    int ch;
{
    if (f->rpos == f->wpos) {
	f->rpos = 8;
	f->wpos = 8;
    } 
    if (f->rpos > 0) {
	f->rpos--;
	f->buf[f->rpos] = ch;
    } else 
	errx(1, "no room to fdbuf_ungetc");
}

/* Returns true if the file descriptor and buffer are exhausted */
int
fdbuf_feof(f)
    struct fdbuf *f;
{
    int ch;
   
    if (f->fd < 0)
	return 1;
    ch = fdbuf_getc(f);
    if (ch == EOF)
	return 1;
    else {
	fdbuf_ungetc(f, ch);
	return 0;
    }
}

/* Reads a CR-terminated line from the buffered file descriptor */
char *
fdbuf_fgets(buf, bufsz, f)
    char *buf;
    int bufsz;
    struct fdbuf *f;
{
    int len = 0;
    int ch;

    while (len < bufsz - 1 && (ch = fdbuf_getc(f)) != EOF) {
	buf[len++] = ch;
	if (ch == '\n')
	    break;
    }
    buf[len] = '\0';
    return buf;
}

