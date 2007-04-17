/* $Vintela: get.c,v 1.8 2006/03/25 11:46:41 davidl Exp $ */
/* Copyright 2005, David Leonard, Vintela */
/*
 * A small HTTP client that uses SPNEGO Authenticate with VAS.
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#if STDC_HEADERS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#endif

#include <errno.h>
#include <netdb.h>

#if HAVE_VAS_H
# include <vas.h>
#endif
#if HAVE_VAS_GSS_H
# include <vas_gss.h>
#endif
#if HAVE_GSSAPI_H
# include <gssapi.h>
#endif
#if HAVE_GSSAPI_KRB5_H
# include <gssapi_krb5.h>
#endif

#include "err.h"
#include "fdbuf.h"
#include "base64.h"

#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>

int debug = 0;
int use_gssapi = 0;
const char *spn = NULL;	/* service principal name override */
int print_body = 1;
const char *header_outfile_name = NULL;

/* A URL, split into its component parts, and maybe with a FILE* attachment */
struct url {
    char buf[2048];
    char *scheme, *host, *port, *object, *hash;
    struct fdbuf fdbuf;
};

/* A singly linked list of MIME headers (name/value pairs) */
struct header {
    char *name;
    char *value;
    struct header *next;
};

/* A response from a HTTP request */
struct response {
    char version[16];		/* version following "HTTP/" */
    unsigned int result;	/* three-digit response code e.g. 200 */
    struct header *headers;	/* headers read after response */
    struct url *url;		/* request url, and i/o stream */
};

/* Prototypes */
int	parseurl(struct url *url, const char *str);
void	closeurl(struct url *url);
int	connect_to(char *host, char *port);
struct	header *findheader(const struct header *h, const char *name);
void	appendheader(struct header **hp, const char *name, const char *value);
void	setheader(struct header **hp, const char *name, const char *value);
void	freeheaders(struct header **hp);
struct header *readheaders(struct fdbuf *);
int	readresponse(struct response *response, struct url *url);
void	freeresponse(struct response *response);
void	sendrequest(char *method, struct url *url, struct header *headers);
void	readbody(struct response *response, FILE *out);
static void	dumpheaders(const struct response *response);

/*------------------------------------------------------------
 * URL functions
 */

/**
 * Parses an URL into an URL structure. 
 * Also initialises the file descriptor buffer associated with the URL.
 * Quick and nasty.
 * @param url     Pointer to an URL structure to be erased and filled in
 * @param str     The string form of an URL to read.
 * @return zero on success.
 */
int
parseurl(url, str)
    struct url *url;
    const char *str;
{
    const char *s = str;
    char *b = url->buf;

    url->scheme = b;
    while (*s && *s != ':') *b++ = *s++;
    *b++ = '\0';
    if (*s == ':') s++;

    if (s[0] == '/' && s[1] == '/')
	s+=2;
    url->host = b;
    while (*s && *s != ':' && *s != '/') *b++ = *s++;
    *b++ = '\0';

    if (*s == ':') {
	s++;
	url->port = b;
	while (*s && *s != '/') *b++ = *s++;
	*b++ = '\0';
    } else
	url->port = NULL;

    url->object = b;
    while (*s && *s != '#') *b++ = *s++;
    *b++ = '\0';

    if (*s == '#') {
	s++;
	url->hash = b;
	while (*s) *b++ = *s++;
	*b++ = '\0';
    }
    fdbuf_init(&url->fdbuf, -1);
    return 0;
}

/**
 * Closes the file descriptor buffer associated with an opened URL
 */
void
closeurl(url)
    struct url *url;
{
    if (url->fdbuf.fd >= 0) {
	close(url->fdbuf.fd);
	fclose(url->fdbuf.f);
	fdbuf_init(&url->fdbuf, -1);
    }
}

/**
 * Connects a TCP/IP socket to some host/port.
 * @return a unix file descriptor to the socket, or a negative
 * number on failure.
 * [Can't use getaddrinfo() because of compat reasons]
 */
int
connect_to(host, port)
    char *host, *port;
{
    int s = -1;
    struct hostent *he;
    struct servent *se, se0;
    struct sockaddr_in sin;

    he = gethostbyname(host);
    if (!he) 
	errx(1, "gethostbyname(%s): %s", host, hstrerror(h_errno));

    if (isdigit(port[0])) {
	se = &se0;
	se->s_port = htons(atoi(port));
    } else {
	se = getservbyname(port, "tcp");
	if (!se) errx(1, "getservbyname(%s): not known", port);
    }

    s = socket(he->h_addrtype, SOCK_STREAM, 0);
    if (s < 0) 
	err(1, "socket");

    memset(&sin, 0, sizeof sin);
    sin.sin_family = PF_INET;
    memcpy(&sin.sin_addr, he->h_addr, sizeof sin.sin_addr);
    sin.sin_port = se->s_port;

    if (debug)
	fprintf(stderr, "sin.sin_addr=%s sin.sin_port=%u\n",
		(char *)inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
    if (connect(s, (struct sockaddr *)&sin, sizeof sin) < 0)
	err(1, "connect");

    return s;
}

/*------------------------------------------------------------
 * MIME header functions
 */

/** 
 * Finds a header in a list with the same name, with an O(n) search.
 * The names are checked in a case-insensitive fashion.
 */
struct header *
findheader(h, name)
    const struct header *h;
    const char *name;
{
    while (h) {
	if (strcasecmp(name, h->name) == 0)
	    return (struct header *)h;
	h = h->next;
    }
    return NULL;
}

/*
 * Adds a new header element to the beginning of a linked list of headers.
 * The contents of the name and value strings are copied by this call.
 */
void
appendheader(hp, name, value)
    struct header **hp;
    const char *name;
    const char *value;
{
    struct header *h = (struct header *)malloc(sizeof *h);
    if (h == NULL)
	errx(1, "malloc");
    h->name = strdup(name);
    h->value = strdup(value);
    h->next = *hp;
    *hp = h;
}

/**
 * Replaces, or adds a header into an existing list.
 * The contents of the value string are copied by this call.
 */
void
setheader(hp, name, value)
    struct header **hp;
    const char *name;
    const char *value;
{
    struct header *h = findheader(*hp, name);
    if (h) {
	free(h->value);
	h->value = strdup(value);
    } else
	appendheader(hp, name, value);
}

/* Releases all storage used for a linked list of headers. */
void
freeheaders(hp)
    struct header **hp;
{
    struct header *h = *hp;
    while (h) {
	struct header *hn = h->next;
	free(h->name);
	free(h->value);
	free(h);
	h = hn;
    }
    *hp = NULL;
}

/**
 * Reads headers from a HTTP stream, finishing when a blank line is read.
 * @return a linked list of headers.
 */
struct header *
readheaders(f)
    struct fdbuf *f;
{
    char buf[8192];
    char *s, *e, *t;
    struct header *h = NULL;

    for (;;) {
	if (fdbuf_fgets(buf, sizeof buf, f) == NULL) {
	    warn("fgets");
	    return h;
	}
	e = buf + strlen(buf);
	while (e > buf && (e[-1] == '\n' || e[-1] == '\r')) *--e = '\0';
	if (e == buf)
	    return h;
	if (isspace(buf[0])) {
	    /* Append to the last header's value */
	    if (!h) { warn("bad header"); return NULL; }
	    t = (char *)malloc(strlen(h->value) + strlen(buf) + 1);
	    if (t == NULL) errx(1, "malloc");
	    strcpy(t, h->value);
	    strcat(t, buf);
	    free(h->value);
	    h->value = t;
	    if (debug) fprintf(stderr, "<+ %s: %s\n", h->name, h->value);
	} else {
	    /* Append a new header entry */
	    char *colon = strchr(buf, ':');
	    if (!colon) { warn("bad header"); return h; }
	    *colon = '\0';
	    s = colon;
	    while (s > buf && isspace(s[-1])) *--s = '\0';
	    s = colon + 1;
	    while (*s && isspace(*s)) s++;
	    appendheader(&h, buf, s);
	    if (debug) fprintf(stderr, "S: %s: %s\n", h->name, h->value);
	}
    }
}

/*------------------------------------------------------------
 * HTTP protocol functions
 */

/*
 * Reads the headers of a HTTP response. Note that the body must
 * be read separately. Note that the URL should outlive the response.
 * @param response The response structure to be filled in.
 * @param url      The URL used in the request.
 * @return zero on success
 */
int
readresponse(response, url)
    struct response *response;
    struct url *url;
{
    char buf[1024];

    if (fdbuf_fgets(buf, sizeof buf, &url->fdbuf) == NULL) {
	warn("fgets");
	closeurl(url);
	return -1;
    }
    if (sscanf(buf, "HTTP/%[0-9.] %3u ", response->version,
	       	&response->result) != 2) {
	warnx("malformed response");
	return -1;
    }
    if (debug) fprintf(stderr, "S: %s", buf);
    response->headers = readheaders(&url->fdbuf);
    response->url = url;
    return 0;
}

/** Releases storage used in reading a response, but does not close the URL. */
void
freeresponse(response)
    struct response *response;
{
    freeheaders(&response->headers);
}


/**
 * Sends the headers of a HTTP request. Note that no body is sent.
 * May create an I/O stream and attach it to the URL.
 * @param method  One of  "GET", "HEAD", etc.
 * @param url     The URL to request
 * @param headers A linked list of headers to send in the request
 */
void
sendrequest(method, url, headers)
    char *method;
    struct url *url;
    struct header *headers;
{
    struct header *h;

    if (strcmp(url->scheme, "http") != 0)
	errx(1, "scheme %s not supported", url->scheme);
    if (url->port == NULL) {
	if (strcmp(url->scheme, "http") == 0)
	    url->port = "80";
	else
	    url->port = url->scheme;
    }

    /* Open a connection to the web server */
    if (fdbuf_feof(&url->fdbuf)) {
	int s;
	if (debug) fprintf(stderr, "[connecting to host %s port %s]\n",
		url->host, url->port);
	if ((s = connect_to(url->host, url->port)) < 0)
	    errx(1, "connect_to");
	fdbuf_init(&url->fdbuf, s);
    }

    if (debug) fprintf(stderr, "C: %s %s HTTP/1.1\n", method, url->object);
    fprintf(url->fdbuf.f, "%s %s HTTP/1.1\r\n", method, url->object);


    if (debug) fprintf(stderr, "C: Host: %s\n", url->host);
    fprintf(url->fdbuf.f, "Host: %s\r\n", url->host);

    for (h = headers; h; h = h->next) {
	if (debug) fprintf(stderr, "C: %s: %s\n", h->name, h->value);
	fprintf(url->fdbuf.f, "%s: %s\r\n", h->name, h->value);
    }

    if (debug) fprintf(stderr, "C: \n");
    fprintf(url->fdbuf.f, "\r\n");

    if (debug) fprintf(stderr, "[request header sent]\n");
}

/**
 * Prints the headers to a given file stream.
 * The output is not from the server's response verbatim, it is reconstructed.
 * The output will be finished with an empty line.
 *
 * @param response  The response to read headers from. Must not be NULL.
 */
void
dumpheaders(response)
    const struct response *response;
{
    const struct header *hdr;
    FILE *header_outfile;

    assert(response);

    if (!header_outfile_name)
	return;

    if (strcmp(header_outfile_name, "-") == 0) {
	header_outfile = stdout;
    } else {
	header_outfile = fopen(header_outfile_name, "w");
	if (!header_outfile) {
	    fprintf(stderr, "Cannot open header output file %s: %s\n",
		    header_outfile_name, strerror(errno));
	    return;
	}
    }

    for (hdr = response->headers; hdr; hdr = hdr->next)
	fprintf(header_outfile, "%s: %s\n", hdr->name, hdr->value);

    fprintf(header_outfile, "\n");

    if (header_outfile != stdout)
	fclose(header_outfile);
}

/**
 * Reads the body from the URL stream, and writes it to out if its not NULL.
 * @param response  The response to read from. The URL's i/o stream is
 *                  used for data, and the headers are searched for a
 *                  Content-Length header.
 * @param out       A stdio file where to copy the data, or NULL if
 *                  the body data is to be discarded.
 */
void
readbody(response, out)
    struct response *response;
    FILE *out;
{
    unsigned int length = 0;
    int rdlen;
    struct header *h;
    char buf[8192];
    struct fdbuf *f = &response->url->fdbuf;

    if (!print_body)
	out = NULL;

    /* half-shutdown the socket now to speed up transfer completion */
    if (shutdown(f->fd, SHUT_WR) < 0)
	warn("shutdown(SHUT_WR)");

    /* Try doing a chunked transfer */
    h = findheader(response->headers, "transfer-encoding");

    if (h && strcmp(h->value, "chunked") == 0) {
	if (debug > 1) fprintf(stderr, "reading chunked data\n");
	while (1) {
	    int chunklen = 0;
	    char *p;
	    int ch;
	    int value;

	    ch = fdbuf_getc(f);
	    while (ch != EOF && isspace(ch))
		ch = fdbuf_getc(f);
	    while (ch != EOF && !isspace(ch)) {
		if (ch >= '0' && ch <= '9') value = ch - '0';
		else if (ch >= 'a' && ch <= 'f') value = ch - 'a' + 10;
		else if (ch >= 'A' && ch <= 'F') value = ch - 'A' + 10;
		else break;
		chunklen = chunklen * 16 + value;
		ch = fdbuf_getc(f);
	    }
	    if (ch == '\r') {
		ch = fdbuf_getc(f);
		if (ch != '\n' && ch != EOF)
		    fdbuf_ungetc(f, ch);
	    }
	    if (debug > 1) fprintf(stderr, "chunklen=%d\n", chunklen);
	    if (chunklen == 0)
		break;
	    while (chunklen > 0) {
		if (chunklen < sizeof buf)
		    rdlen = fdbuf_read(f, buf, chunklen);
		else
		    rdlen = fdbuf_read(f, buf, sizeof buf);
		if (rdlen < 0) {
		    warn("read");
		    break;
		}
		if (rdlen == 0) break;
		if (out)
		    fwrite(buf, rdlen, 1, out);
		chunklen -= rdlen;
		if (debug > 2)
		    fprintf(stderr, "wrote %d, remaining %d\n", 
			    rdlen, chunklen);
	    }
	}
    }

    /* Try doing a content-length transfer */
    else if ((h = findheader(response->headers, "content-length")) != NULL)
    {
	sscanf(h->value, "%u", &length);
	if (debug > 1)
	    fprintf(stderr, "reading %s (%u) bytes\n", h->value, length);
	while (length > 0) {
	    if (length < sizeof buf)
		rdlen = fdbuf_read(f, buf, length);
	    else
		rdlen = fdbuf_read(f, buf, sizeof buf);
	    if (rdlen < 0)
		warn("read");
	    if (rdlen <= 0)
		break;
	    if (out)
		fwrite(buf, rdlen, 1, out);
	    length -= rdlen;
	}
	if (length > 0)
	    closeurl(response->url);
    }
   
    /* Try reading until the channel closes */
    else {
	if (debug > 1) fprintf(stderr, "reading bytes till eof from %d\n", f->fd);
	length = 0;
	while ((rdlen = fdbuf_read(f, buf, sizeof buf)) > 0) {
	    length += rdlen;
	    if (debug > 1) fprintf(stderr, "got %u bytes\n", rdlen);
	    if (out)
		fwrite(buf, rdlen, 1, out);
	}
	if (debug) fprintf(stderr, "read %u bytes\n", length);
	if (rdlen < 0)
	    warn("read");
	closeurl(response->url);
    }

    if (out)
	fflush(out);
}

/* Prints a GSS error message and exits */
void
err_gss(ec, major, minor, msg)
    int ec;
    OM_uint32 major, minor;
    const char *msg;
{
    OM_uint32 ctx = 0;
    gss_buffer_desc buf;
    OM_uint32 emajor, eminor;

    fprintf(stderr, "%s", msg);
    do {
	emajor = gss_display_status(&eminor, major, GSS_C_GSS_CODE,
		GSS_C_NO_OID, &ctx, &buf);
	if (GSS_ERROR(emajor))
	    errx(1, "gss_display_status");
	fprintf(stderr, "; %.*s", buf.length, (const char *)buf.value);
	gss_release_buffer(&eminor, &buf);
    } while (ctx);
    do {
	emajor = gss_display_status(&eminor, major, GSS_C_MECH_CODE,
		GSS_C_NO_OID, &ctx, &buf);
	if (GSS_ERROR(emajor))
	    errx(1, "gss_display_status");
	fprintf(stderr, "; %.*s", buf.length, (const char *)buf.value);
	gss_release_buffer(&eminor, &buf);
    } while (ctx);
    fprintf(stderr, "\n");
    exit(ec);
}

/* Get an HTTP resource using RFC2478 (Authenticate: Negotiate) */
int
get_nego(urlarg, principal)
    char *urlarg;
    char *principal;
{
    struct url url;
    struct header *h;
    struct header *sendheaders = NULL;
    struct response response;
#if VAS_API_VERSION_MAJOR >= 4
    vas_ctx_t *vas;
    vas_id_t *vasid;
#else
    vas_t *vas;
#endif
    gss_name_t target_name;
    OM_uint32 major, minor;
    gss_buffer_desc gssbuf;
    gss_ctx_id_t gssctx;
    char tokbuf[8192];

    if (debug) fprintf(stderr, "[principal given: %s]\n", 
	    	       principal ? principal : "(none)");

    /* Get a VAS context */
    if (use_gssapi) {
	if (debug) fprintf(stderr, "[using gssapi]\n");
    } else {
#if VAS_API_VERSION_MAJOR >= 4
	if (vas_ctx_alloc(&vas))
	    errx(1, "vas_ctx_alloc");
	if (vas_id_alloc(vas, NULL, &vasid))
	    errx(1, "vas_id_alloc: %s", 
		    vas_err_get_string(vas, 1));
	if (debug) {
	    char *upn;
	    if (vas_id_get_name(vas, vasid, &upn, NULL))
		errx(1, "vas_id_get_name: %s", 
			vas_err_get_string(vas, 1));
	    fprintf(stderr, "[using identity: %s]\n", upn);
	    free(upn);
	}
	if (vas_gss_initialize(vas, vasid))
	    errx(1, "vas_gss_initialize: %s", 
		    vas_err_get_string(vas, 1));
#else
	if (vas_alloc(&vas, principal))
	    err(1, "vas_alloc");
	if (debug) {
	    char *upn;
	    if (vas_info_identity(vas, NULL, &upn))
	        errx(1, "vas_info_identity: %s", vas_error_str(vas));
	    fprintf(stderr, "[using principal name: %s]\n", upn);
	    free(upn);
	}
#endif
    }


    parseurl(&url, urlarg);

again:
    gssctx = GSS_C_NO_CONTEXT;
again_spnego:

    /* Send the HTTP request */
    sendrequest("GET", &url, sendheaders);
    if (readresponse(&response, &url) < 0)
	errx(1, "readresponse");

    /* Handle 302 redirects */
    if (response.result == 302) {
	h = findheader(response.headers, "location");
	if (!h) errx(1, "302 redirect, but no location");
	closeurl(&url);
	parseurl(&url, h->value);
	freeresponse(&response);
	goto again;
    }

    /* Handle 401 denied */
    if (response.result == 401) {
	for (h = response.headers; 
	     (h = findheader(h, "www-authenticate")) != NULL;
             h = h->next)
	{

	    if (strncasecmp(h->value, "negotiate", 9) == 0) {
		char *token = h->value + 9;
		unsigned char *out_token;
		size_t out_token_size = 0;
		OM_uint32 ret;
		char name[5+256+1+256+1];
		char buf[8192];

		/* Skip body */
		readbody(&response, NULL); 

		if (!*token && gssctx != GSS_C_NO_CONTEXT)
		    errx(1, "server ignored first token");

		if (spn == NULL)
		    snprintf(name, sizeof name, "HTTP/%s", url.host);
		else
		    snprintf(name, sizeof name, "%s", spn);

		if (debug) fprintf(stderr, "[using target principal '%s']\n",
		       name);

		if (use_gssapi) {
		    gss_buffer_desc inbuf, outbuf, namebuf;
		    int len;

		    namebuf.value = name;
		    namebuf.length = strlen(name);
		    major = gss_import_name(&minor, &namebuf, 
				GSS_KRB5_NT_PRINCIPAL_NAME, &target_name);
		    if (GSS_ERROR(major))
			err_gss(1, major, minor, "gss_import_name");

		    if (*token) {
			len = base64_decode(token, strlen(token),
				buf, sizeof buf);
			if (len < 0) errx(1, "bad base64 in input token");
			if (len >= sizeof buf - 1) errx(1, "input too big");
			inbuf.value = buf;
			inbuf.length = len;
		    }

		    outbuf.value = NULL;
		    major = gss_init_sec_context(
			&minor,
			GSS_C_NO_CREDENTIAL,
			&gssctx,
			target_name,
			GSS_C_NO_OID,
			0, /* GSS_C_DELEG_FLAG */
			GSS_C_INDEFINITE,
			GSS_C_NO_CHANNEL_BINDINGS,
			*token ? &inbuf : NULL,
			NULL,
			&outbuf,
			NULL,
			NULL);
		    if (GSS_ERROR(major))
			err_gss(1, major, minor, "gssinit_sec_context");
		    if (!outbuf.value)
			out_token_size = 0;
		    else {
			out_token_size = base64_encode(outbuf.value, 
				outbuf.length, tokbuf, sizeof tokbuf);
			out_token = tokbuf;
			gss_release_buffer(&minor, &outbuf);
		    }
		} 
		else
#if VAS_API_VERSION_MAJOR >= 4
		{
		    /* VAS 3.0 */
		    gss_buffer_desc inbuf, outbuf;

		    if (*token) {
			inbuf.value = token;
			inbuf.length = strlen(token);
		    }
		    ret = vas_gss_spnego_initiate(vas, vasid, NULL, 
			    &gssctx, 
			    name,
			    0 /* GSS_C_DELEG_FLAG */,
			    VAS_GSS_SPNEGO_ENCODING_BASE64,
			    &inbuf,
			    &outbuf);
		    if (GSS_ERROR(ret))
			errx(1, "vas_gss_spnego_initiate: %s", 
			    vas_err_get_string(vas, 1));
		    out_token_size = outbuf.length;
		    out_token = (char *)outbuf.value;
		    /* XXX outbuf is not released */
		}
#else
		{
		    /* VAS 2.6 */
		    ret = vas_gss_spnego_initiate(vas, 
			&gssctx,
			name, 
			0 /* GSS_C_DELEG_FLAG */,
			VAS_GSS_SPNEGO_ENCODING_BASE64,
			*token ? (unsigned char *)token : NULL,
			strlen(token),
			&out_token, &out_token_size);

		    if (GSS_ERROR(ret))
			errx(1, "vas_gss_spnego_initiate: %s", 
				vas_error_str(vas));
		    if (debug) 
			fprintf(stderr, "[vas_gss_spnego_initiate -> %#x]\n", 
				ret);
		}
#endif

		/* Add an appropriate header to the sendheaders list */
		if (out_token_size + 11 > sizeof buf)
		    errx(1, "token bigger than buf[]");
		snprintf(buf, sizeof buf, "Negotiate %.*s",
			(int)out_token_size, out_token);
		setheader(&sendheaders, "Authorization", buf);

		closeurl(&url);
		goto again_spnego;
	    }
	} 
    }

    if (!use_gssapi) {
#if VAS_API_VERSION_MAJOR >= 4
	if (vas_gss_deinitialize(vas))
	    errx(1, "vas_gss_deinitialize: %s", 
		    vas_err_get_string(vas, 1));
	vas_id_free(vas, vasid);
	vas_ctx_free(vas);
#endif
    }

    dumpheaders(&response);
    readbody(&response, stdout);
    return response.result;
}

/* Use simple (unauthenticated) GET */
int
get_simple(urlarg)
    char *urlarg;
{
    struct url url;
    struct header *h;
    struct header *sendheaders = NULL;
    struct response response;

    parseurl(&url, urlarg);

again:

    /* Send the HTTP request */
    sendrequest("GET", &url, sendheaders);
    if (readresponse(&response, &url) < 0)
	errx(1, "readresponse");

    /* Handle 302 redirects */
    if (response.result == 302) {
	h = findheader(response.headers, "location");
	if (!h) errx(1, "302 redirect, but no location");
	closeurl(&url);
	parseurl(&url, h->value);
	freeresponse(&response);
	goto again;
    }

    dumpheaders(&response);
    readbody(&response, stdout);
    return response.result;
}

/* Use basic authentication to fetch an URL  - RFC2617 */
int
get_basic(urlarg, userpass)
    char *urlarg, *userpass;
{
    struct url url;
    struct header *h;
    struct header *sendheaders = NULL;
    struct response response;
    char basic_auth[1024];
    int basic_auth_added = 0;
    int base64len;

    parseurl(&url, urlarg);

    /* Make the "Basic <creds>" header */
    memcpy(basic_auth, "Basic ", 6); 
    base64len = base64_encode(userpass, strlen(userpass),
		basic_auth + 6, sizeof basic_auth - 6);
    if (base64len < 0 || base64len > sizeof basic_auth - 6 - 1)
	errx(1, "username:password too long");
    basic_auth[6 + base64len] = '\0';

again:

    /* Send the HTTP request */
    sendrequest("GET", &url, sendheaders);
    if (readresponse(&response, &url) < 0)
	errx(1, "readresponse");

    /* Handle 302 redirects */
    if (response.result == 302) {
	h = findheader(response.headers, "location");
	if (!h) errx(1, "302 redirect, but no location");
	closeurl(&url);
	parseurl(&url, h->value);
	freeresponse(&response);
	goto again;
    }

    /* Handle 401 denied */
    if (response.result == 401) {
	for (h = response.headers; 
	     (h = findheader(h, "www-authenticate")) != NULL;
             h = h->next)
	{

	    if (strncasecmp(h->value, "basic", 5) == 0 && !basic_auth_added) {
		/* Skip body */
		readbody(&response, NULL); 

		if (debug) fprintf(stderr, "[adding basic auth credentials]\n");
		setheader(&sendheaders, "Authorization", basic_auth);
		basic_auth_added = 1;

		closeurl(&url);
		goto again;
	    }
	} 
    }

    dumpheaders(&response);
    readbody(&response, stdout);
    return response.result;
}

void
usage(char *prog)
{
    fprintf(stderr, "usage: %s [options] -s url\n"
	    	    "       %s [options] -n [-S spn] [-g] url\n"
		    "       %s [options] -b user:pass url\n"
		    "  where the authentication modes are\n"
		    "       -s - simple (no authentication)\n"
		    "       -n - Negotiate (SPNEGO)\n"
		    "       -b - Basic\n"
		    "  The generic options are:\n"
		    "       -e outfile    - where to write HTTP response code\n"
		    "       -d            - enable debugging\n"
		    "       -H outfile    - where to write the HTTP headers ('-' for stdout)\n"
		    "       -B            - supress output of the response body\n"
		    "  The negotiate-specific (-n) options are:\n"
		    "       -u user       - use principal name override\n"
		    "       -S spn        - service principal name override\n"
		    "       -g            - use GSSAPI internally (not VAS)\n"
	    ,prog,prog,prog);
    exit(1);
}

int
main(argc, argv)
    int argc;
    char *argv[];
{
    int optind;
    int ret;
    FILE *codef = NULL;
    enum { UNSET, NEGOTIATE, BASIC, SIMPLE } mode = UNSET;
    char *principal = NULL;

    /* Can't use getopt; it's not portable :( */
    if (argc == 1) usage(argv[0]);
    for (optind = 1; optind < argc; optind++)
	if (argv[optind][0] != '-')
	    break;
	else if (strcmp(argv[optind], "-e") == 0) {
	    optind++;
	    if (optind >= argc) usage(argv[0]);
	    codef = fopen(argv[optind], "wb");
	    if (!codef) err(1, "%s", argv[optind]);
	} else if (strcmp(argv[optind], "-d") == 0) {
	    debug++;
	} else if (strcmp(argv[optind], "-g") == 0) {
	    if (mode != NEGOTIATE) usage(argv[0]);
	    use_gssapi++;
	} else if (strcmp(argv[optind], "-n") == 0) {
	    if (mode != UNSET) usage(argv[0]);
	    mode = NEGOTIATE;
	} else if (strcmp(argv[optind], "-b") == 0) {
	    if (mode != UNSET) usage(argv[0]);
	    mode = BASIC;
	} else if (strcmp(argv[optind], "-s") == 0) {
	    if (mode != UNSET) usage(argv[0]);
	    mode = SIMPLE;
	} else if (strcmp(argv[optind], "-S") == 0) {
	    if (mode != NEGOTIATE) usage(argv[0]);
	    optind++;
	    if (optind >= argc) usage(argv[0]);
	    spn = argv[optind];
	} else if (strcmp(argv[optind], "-B") == 0) {
	    print_body = 0;
	} else if (strcmp(argv[optind], "-H") == 0) {
	    optind++;
	    if (optind >= argc) usage(argv[0]);
	    header_outfile_name = argv[optind];
	} else if (strcmp(argv[optind], "-u") == 0) {
	    optind++;
	    if (optind >= argc) usage(argv[0]);
	    principal = argv[optind];
	} else if (strcmp(argv[optind], "--") == 0) {
	    optind++;
	    break;
	} else {
	    fprintf(stderr, "unknown option %s\n", argv[optind]);
	    usage(argv[0]);
	}

    switch (mode) {
	default:
	case UNSET:
	    usage(argv[0]);
	    ret = -1;
	    break;
	case NEGOTIATE:
	    if (optind + 1 != argc) usage(argv[0]);
	    ret = get_nego(argv[optind], principal);
	    break;
	case BASIC:
	    if (optind + 2 != argc) usage(argv[0]);
	    ret = get_basic(argv[optind+1], argv[optind]);
	    break;
	case SIMPLE:
	    if (optind + 1 != argc) usage(argv[0]);
	    ret = get_simple(argv[optind]);
	    break;
    }

    if (codef && ret >= 0) {
	fprintf(codef, "%03d\n", ret);
	fclose(codef);
    }
    if (!codef && ret != 200 && ret >= 0)
	fprintf(stderr, "Server response: %03d\n", ret);

    exit(ret == 200 ? 0 : 1);
}
