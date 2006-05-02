/* $Vintela: fdbuf.h,v 1.1 2005/04/10 07:03:55 davidl Exp $ */
#include <stdio.h>
#define FDBUFSZ 8192

/* Buffered I/O (more flexible than stdio) */
struct fdbuf {
    FILE *f;
    int fd;
    int wpos,rpos;
    char buf[FDBUFSZ];
};

void  fdbuf_init(struct fdbuf *f, int fd);
int   fdbuf_read(struct fdbuf *f, char *buf, int bufsz);
int   fdbuf_getc(struct fdbuf *f);
void  fdbuf_ungetc(struct fdbuf *f, int ch);
int   fdbuf_feof(struct fdbuf *f);
char *fdbuf_fgets(char *buf, int bufsz, struct fdbuf *f);
