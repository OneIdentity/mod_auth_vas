/* (c) 2005 Quest Software, Inc. All rights reserved. */
/* David Leonard */

/*
 * RFC2045 base64 encoding and decoding 
 *
 * If compiled with -DBASE64_MAIN, this module becomes
 * a small base64 encoder/decoder.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "base64.h"

int base64_debug = 0;

/* Encoding table: value to digit */
static char enctab[] =  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz"
			"0123456789+/";

/* Decoding table: digit to value */
static char dectab[128] = {
    -1,-1,-1,-1,-1,-1,-1,-1,   /* -1: invalid */
    -1,-2,-2,-2,-2,-2,-1,-1,   /* -2: whitespace */
    -1,-1,-1,-1,-1,-1,-1,-1,   /* 0..63: base64 digit */
    -1,-1,-1,-1,-1,-1,-1,-1,
    -2,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,
    60,61,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6,
     7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,
    23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,
    33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,
    49,50,51,-1,-1,-1,-1,-1
};

int
base64_encode(inbuf, inbuflen, outbuf, outbuflen)
    const char *inbuf;
    int inbuflen;
    char *outbuf;
    int outbuflen;
{
    int len;
    base64_enc_state_t state;

    base64_encode_init(&state);
    len = base64_encode_sub(&state, inbuf, inbuflen, 
	    outbuf, outbuflen);
    len += base64_encode_fini(&state,
	    outbuf + len, outbuflen - len);
    return len;
}

void
base64_encode_init(state)
    base64_enc_state_t *state;
{
    state->inpos = 0;
}

int
base64_encode_sub(state, inbuf, inbuflen, outbuf, outbuflen)
    base64_enc_state_t *state;
    const char *inbuf;
    int inbuflen;
    char *outbuf;
    int outbuflen;
{
    int inpos = 0;
    int outpos = 0;

    /* Encode as many whole input triples into 4 output chars as possible */
    while (inpos < inbuflen) {
	state->grp[(state->inpos + inpos) % 3] = inbuf[inpos]; inpos++;
	if ((state->inpos + inpos) % 3 == 0) {
	    if (outpos < outbuflen)
		outbuf[outpos] = enctab[(state->grp[0] & 0xfc) >> 2 & 0x3f];
	    outpos++;
	    if (outpos < outbuflen)
		outbuf[outpos] = enctab[((state->grp[0] & 0x03) << 4 |
				      (state->grp[1] & 0xf0) >> 4) & 0x3f];
	    outpos++;
	    if (outpos < outbuflen)
		outbuf[outpos] = enctab[((state->grp[1] & 0x0f) << 2 | 
				      (state->grp[2] & 0xc0) >> 6) & 0x3f];
	    outpos++;
	    if (outpos < outbuflen)
		outbuf[outpos] = enctab[state->grp[2] & 0x3f];
	    outpos++;
	}
    }
    state->inpos = state->inpos + inpos;
    return outpos;
}

int
base64_encode_fini(state, outbuf, outbuflen)
    base64_enc_state_t *state;
    char *outbuf;
    int outbuflen;
{
    int outpos = 0, i;

    /* Handle remaining characters that don't fit into a triple */
    if (state->inpos % 3 != 0) {
	for (i = state->inpos % 3; i < 3; i++)
	    state->grp[i] = 0;
	if (outpos < outbuflen)
	    outbuf[outpos] = enctab[(state->grp[0] & 0xfc) >> 2 & 0x3f];
	outpos++;
	if (outpos < outbuflen)
	    outbuf[outpos] = enctab[((state->grp[0] & 0x03) << 4 |
				  (state->grp[1] & 0xf0) >> 4) & 0x3f];
	outpos++;
	if (outpos < outbuflen)
	    outbuf[outpos] = (state->inpos % 3 > 1) 
		? enctab[((state->grp[1] &0x0f) << 2) & 0x3f]
		: '=';
	outpos++;
	if (outpos < outbuflen)
	    outbuf[outpos] = '=';
	outpos++;
    }

    return outpos;
}

int
base64_decode(inbuf, inbuflen, outbuf, outbuflen)
    const char *inbuf;
    int inbuflen;
    char *outbuf;
    int outbuflen;
{
    base64_dec_state_t state;
    int len;

    base64_decode_init(&state);
    len = base64_decode_sub(&state, inbuf, inbuflen, outbuf, outbuflen);
    if (len < 0)
	return -1;
    if (base64_decode_fini(&state) < 0)
	return -1;
    return len;
}

void
base64_decode_init(state)
    base64_dec_state_t *state;
{
    state->pad = 0;
    state->inpos = 0;
    state->n = 0;
}

int
base64_decode_sub(state, inbuf, inbuflen, outbuf, outbuflen)
    base64_dec_state_t *state;
    const char *inbuf;
    int inbuflen;
    char *outbuf;
    int outbuflen;
{
    int inpos = 0;
    int outpos = 0;

    if (state->n || !state->pad)
	while (inpos < inbuflen) {
	    unsigned char c = (unsigned char)inbuf[inpos++];

	    /* Classify input bytes as padding, ignorable or codes */
	    if (c == '=') {
		if (state->n < 2) {
		    if (base64_debug)
			fprintf(stderr, "spurious '=' at index %d\n", inpos-1);
		    return -1;
		}
		state->pad++;
		state->grp[state->n++] = 0;
	    } else if ((c & 0x80) || dectab[(unsigned int)c] == -1) {
		if (base64_debug)
		    fprintf(stderr, "INVALID CHARACTER '%c' #%x"
		       	" at index %d of %d\n", c, c, inpos - 1, inbuflen);
		return -1;
	    } else if (dectab[(unsigned int)c] == -2) 
		continue;
	    else {
		if (state->pad) {
		    if (base64_debug)
			fprintf(stderr, "bad char '%c' #%x after padding"
			       " at index %d\n", c, c, inpos - 1);
		    return -1;
		}
		state->grp[state->n++] = dectab[(unsigned int)c];
	    }

	    /* When a group of 4 has been filled, convert to 3 output bytes */
	    if (state->n == 4) {
		if (state->pad > 2) {
		    if (base64_debug)
		       	fprintf(stderr, "too many padding =s\n");
		    return -1;	
		}
		if (outpos < outbuflen)
		    outbuf[outpos] = state->grp[0] << 2 | state->grp[1] >> 4;
		outpos++;
		if (state->pad < 2) {
		  if (outpos < outbuflen)
		    outbuf[outpos] = (state->grp[1] << 4 | state->grp[2] >> 2) 
			& 0xff;
		  outpos++;
		}
		if (state->pad < 1) {
		  if (outpos < outbuflen)
		    outbuf[outpos] = (state->grp[2] << 6 | state->grp[3]) 
			& 0xff;
		  outpos++;
		}
		state->n = 0;
		if (state->pad)
		    break;
	    }
	}

    /* Return -1 if there is non-whitespace after any padding */
    while (state->pad && inpos < inbuflen) {
	char c = inbuf[inpos++];
	if (dectab[(unsigned int)c] != -2) {
	    if (base64_debug)
		fprintf(stderr, "EXTRA CHARACTER '%c' #%x at index %d of %d\n",
		    c, c, inpos - 1, inbuflen);
	    return -1;
	}
    }

    return outpos;
}

int
base64_decode_fini(state)
    base64_dec_state_t *state;
{

    /* Return -1 if there are undecodable characters remaining */
    if (state->n != 0) {
	if (base64_debug)
	    fprintf(stderr, "%d leftover characters\n", state->n);
	return -1;
    }

    return 0;
}

char *
base64_string_decode(const char *in, int *outlenp)
{
    char *out;
    int outlen;
    int inlen = strlen(in);

    outlen = base64_decode(in, inlen, NULL, 0);
    if (outlen == -1)
	return NULL;
    out = malloc(outlen);
    if (out) {
	base64_decode(in, inlen, out, outlen);
	if (base64_debug)
	    fprintf(stderr, "[decoded %d bytes]\n", outlen);
	*outlenp = outlen;
    }
    return out;
}

char *
base64_string_encode(const char *in, int inlen)
{
    int outlen;
    char *out;

    outlen = base64_encode(in, inlen, NULL, 0);
    if (outlen == -1)
	return NULL;
    out = malloc(outlen + 1);
    if (out) {
	base64_encode(in, inlen, out, outlen);
	if (base64_debug)
	    fprintf(stderr, "[encoded %d bytes]\n", inlen);
	out[outlen] = '\0';
    }
    return out;
}

#ifdef BASE64_MAIN
/* This is a simple test harness. Invoke with -d to decode stdin */
#include <string.h>
int main(int argc, char **argv) {
    int encoding = 1;
    int ch, len;
    char out[4];

    base64_debug = 1;

    if (argc > 1 && strcmp(argv[1], "-d") == 0)
	encoding = 0;
    if (encoding) {
	base64_enc_state_t state;
	base64_encode_init(&state);
	while ((ch = getchar()) != EOF) {
	    char in = ch;
	    len = base64_encode_sub(&state, &in, 1, out, sizeof out);
	    if (len > 0) printf("%.*s", len, out);
	    if (len < 0) exit(1);
	}
	len = base64_encode_fini(&state, out, sizeof out);
	if (len > 0) printf("%.*s", len, out);
	if (len < 0) exit(1);
	printf("\n");
    } else {
	base64_dec_state_t state;
	base64_decode_init(&state);
	while ((ch = getchar()) != EOF) {
	    char in = ch;
	    len = base64_decode_sub(&state, &in, 1, out, sizeof out);
	    if (len > 0) printf("%.*s", len, out);
	    if (len < 0) exit(1);
	}
	if (base64_decode_fini(&state) < 0) exit(1);
    }
    fflush(stdout);
    exit(0);
}
#endif
