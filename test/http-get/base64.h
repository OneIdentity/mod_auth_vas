/* (c) 2005 Quest Software, Inc. All rights reserved */
/* David Leonard */

#ifndef _h_base64_

/*
 * Encodes characters from inbuf into outbuf.
 *   inbuf - characters to encode
 *   inbuflen - number of characters to encode
 *   outbuf - storage for resulting base64-encoded characters
 *   outbuflen - maximum size of storage
 * Returns the number of characters stored in outbuf, including a 
 * trailing nul. If the outbuf was too small, returns the number of
 * characters that would have been stored.
 */
int base64_encode(const char *inbuf, int inbuflen, char *outbuf, int outbuflen);

/*
 * Decodes characters in inbuf into outbuf.
 *   inbuf - characters to decode (may include whitespace)
 *   inbuflen - number of characters in inbuf
 *   outbuf - storage for resulting base64-decoded characters
 *   outbuflen - maximum size of storage
 * Non-BASE64 characters in the inbuf are ignored.
 * Returns the number of characters stored in outbuf. If the outbuf
 * was too small, returns the number of characters that would have been
 * stored had it been big enough.
 * Returns -1 if there are spurious characters.
 */
int base64_decode(const char *inbuf, int inbuflen, char *outbuf, int outbuflen);

/*
 * Returns a malloc'd buffer containing decoded binary from the 
 * input, or NULL.
 *   in - input C string containing base64 data
 *   outlen - pointer to store length of decoded buffer
 * Returns allocated buffer containing decoded data, or NULL if there
 * was an error. Caller must free the buffer.
 */
char *base64_string_decode(const char *in, int *outlen);

/*
 * Returns a C-string containing the base-64 encoding of the input. 
 *   in - input binary buffer
 *   inlen - length of input binary buffer
 * Returns a nul-terminated string containing base64 ASCII characters,
 * or NULL if there was an error. Caller must free the string.
 */
char *base64_string_encode(const char *in, int inlen);

/* State type for the base64 stream encoder functions. */
typedef struct base64_enc_state {
    char grp[3];
    int  inpos;
} base64_enc_state_t;

/* State type for the base64 stream decoder functions. */
typedef struct base64_dec_state {
    char grp[4];
    int inpos;
    int pad;
    int n;
} base64_dec_state_t;

/*
 * Initialises an encoder state.
 * This function creates a valid encoder state with no history.
 *   state - pointer to state storage
 */
void base64_encode_init(base64_enc_state_t *state);

/*
 * Encodes partial input into BASE64.
 * This function can be called repeatedly to generate BASE64 encoded
 * output. Every 4 bytes of input will generate exactly 3 bytes of output.
 * If the input is not a multiple of 4 bytes, the state structure
 * will be used to record the remainder to act as a prefix for later
 * encoding calls.
 *   state - a valid encoder state
 *   inbuf - a binary input buffer
 *   inlen - length of the binary input buffer
 *   outbuf - an output buffer
 *   outbuflen - size of the output buffer
 * Returns the number of bytes that were written to the output buffer,
 * or, if the output buffer was too small, the number of bytes that
 * would have been written if it were not too small. Returns -1 if
 * there was an error.
 */
int base64_encode_sub(base64_enc_state_t *state, const char *inbuf, int inlen,
	char *outbuf, int outbuflen);

/*
 * Finishes encoding partial input into BASE64.
 * This function must be called to finalise decoding. It will
 * generate zero or four bytes of output. Once called, the state
 * variable must not be used again without re-initialising.
 *   state - a valid encoder state
 *   outbuf - an output buffer
 *   outbuflen - size of the output buffer.
 * Returns the number of bytes that were (or would have been) written
 * to the output buffer, or -1 if there was an error. (See the return
 * code description for base64_encode_sub().)
 */
int base64_encode_fini(base64_enc_state_t *state,
	char *outbuf, int outbuflen);

/* Initialises a decoder state */
void base64_decode_init(base64_dec_state_t *state);

/* Decodes partial BASE64 input into binary output */
int base64_decode_sub(base64_dec_state_t *state, const char *inbuf, int inlen,
	char *outbuf, int outbuflen);
/*
 * Finishes decoding partial BASE64 input into binary output.
 * Failure occurs only when there is more BAS64 input expected.
 * Once called, the state variable should not be used again without
 * re-initializing.
 * Returns 0 on success, or -1 if more BASE64 characters were expected.
 */
int base64_decode_fini(base64_dec_state_t *state);

extern int base64_debug;

#endif /* _h_base64_ */
