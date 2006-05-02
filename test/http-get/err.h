/* $Vintela: err.h,v 1.2 2005/04/10 07:09:38 davidl Exp $ */

#define err compat_err
#define errx compat_errx
#define warn compat_warn
#define warnx compat_warnx

void err(int exitcode, const char *fmt, ...);
void errx(int exitcode, const char *fmt, ...);
void warn(const char *fmt, ...);
void warnx(const char *fmt, ...);
