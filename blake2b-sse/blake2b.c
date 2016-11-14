/*
 * BLAKE2 reference source code package - optimized C implementations
 * Written in 2012 by Samuel Neves <sneves@dei.uc.pt>
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "blake2b.h"
#include "blake2-impl.h"

#include "blake2-config.h"

#include <emmintrin.h>
#if defined(HAVE_SSSE3)
#include <tmmintrin.h>
#endif
#if defined(HAVE_SSE41)
#include <smmintrin.h>
#endif
#if defined(HAVE_AVX)
#include <immintrin.h>
#endif
#if defined(HAVE_XOP)
#include <x86intrin.h>
#endif

#include "blake2b-round.h"

ALIGN (64) static const uint64_t	blake2b_IV[8] = {
	0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
	0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
	0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
	0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

/* init xors IV with input parameter block */
int
blake2b_init_param (blake2b_state *S, const blake2b_param *P) {
	const uint8_t	*v = (const uint8_t *)(blake2b_IV);
	const uint8_t	*p = (const uint8_t *)(P);
	uint8_t		*h = (uint8_t *) (S->h);

	/* IV XOR ParamBlock */
	memset (S, 0, sizeof (blake2b_state));

	for (int i = 0; i < BLAKE2B_OUTBYTES; ++i)
		h[i] = v[i] ^ p[i];

	return 0;
}

static inline int 
blake2b_compress (blake2b_state *S, const uint8_t block[BLAKE2B_BLOCKBYTES]) {
	__m128i		row1l, row1h,
			row2l, row2h,
			row3l, row3h,
			row4l, row4h,
			b0, b1,
			t0, t1;

#if defined(HAVE_SSSE3) && !defined(HAVE_XOP)
	const __m128i	r16 =
	    _mm_setr_epi8 (2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);
	const __m128i	r24 =
	    _mm_setr_epi8 (3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10);
#endif
#if defined(HAVE_SSE41)
	const __m128i	m0 = LOADU (block + 00);
	const __m128i	m1 = LOADU (block + 16);
	const __m128i	m2 = LOADU (block + 32);
	const __m128i	m3 = LOADU (block + 48);
	const __m128i	m4 = LOADU (block + 64);
	const __m128i	m5 = LOADU (block + 80);
	const __m128i	m6 = LOADU (block + 96);
	const __m128i	m7 = LOADU (block + 112);
#else
	const uint64_t	m0 = ((uint64_t *) block)[0];
	const uint64_t	m1 = ((uint64_t *) block)[1];
	const uint64_t	m2 = ((uint64_t *) block)[2];
	const uint64_t	m3 = ((uint64_t *) block)[3];
	const uint64_t	m4 = ((uint64_t *) block)[4];
	const uint64_t	m5 = ((uint64_t *) block)[5];
	const uint64_t	m6 = ((uint64_t *) block)[6];
	const uint64_t	m7 = ((uint64_t *) block)[7];
	const uint64_t	m8 = ((uint64_t *) block)[8];
	const uint64_t	m9 = ((uint64_t *) block)[9];
	const uint64_t	m10 = ((uint64_t *) block)[10];
	const uint64_t	m11 = ((uint64_t *) block)[11];
	const uint64_t	m12 = ((uint64_t *) block)[12];
	const uint64_t	m13 = ((uint64_t *) block)[13];
	const uint64_t	m14 = ((uint64_t *) block)[14];
	const uint64_t	m15 = ((uint64_t *) block)[15];
#endif

	row1l = LOADU (&S->h[0]);
	row1h = LOADU (&S->h[2]);
	row2l = LOADU (&S->h[4]);
	row2h = LOADU (&S->h[6]);
	row3l = LOADU (&blake2b_IV[0]);
	row3h = LOADU (&blake2b_IV[2]);
	row4l = _mm_xor_si128 (LOADU (&blake2b_IV[4]),
	    _mm_set_epi32 (0, 0, 0, S->counter));
	row4h = _mm_xor_si128 (LOADU (&blake2b_IV[6]),
	    _mm_set_epi32 (0, 0, 0L - S->lastblock, 0L - S->lastblock));
	ROUND (0);
	ROUND (1);
	ROUND (2);
	ROUND (3);
	ROUND (4);
	ROUND (5);
	ROUND (6);
	ROUND (7);
	ROUND (8);
	ROUND (9);
	ROUND (10);
	ROUND (11);
	row1l = _mm_xor_si128 (row3l, row1l);
	row1h = _mm_xor_si128 (row3h, row1h);
	STOREU (&S->h[0], _mm_xor_si128 (LOADU (&S->h[0]), row1l));
	STOREU (&S->h[2], _mm_xor_si128 (LOADU (&S->h[2]), row1h));
	row2l = _mm_xor_si128 (row4l, row2l);
	row2h = _mm_xor_si128 (row4h, row2h);
	STOREU (&S->h[4], _mm_xor_si128 (LOADU (&S->h[4]), row2l));
	STOREU (&S->h[6], _mm_xor_si128 (LOADU (&S->h[6]), row2h));
	return 0;
}

int 
blake2b_update (blake2b_state *S, const uint8_t *in, uint16_t inlen) {
	while (inlen > 0) {
		uint8_t		left = S->buflen;
		uint8_t		fill = BLAKE2B_BLOCKBYTES - left;

		if (inlen > fill) {
			memcpy (S->buf + left, in, fill);
			in += fill;
			inlen -= fill;
			S->counter += BLAKE2B_BLOCKBYTES;
			blake2b_compress (S, S->buf);
			S->buflen = 0;
		} else {
			memcpy (S->buf + left, in, inlen);
			S->buflen += inlen;
			in += inlen;
			inlen = 0;
		}
	}
	return 0;
}

int 
blake2b_final (blake2b_state *S, uint8_t *out, uint8_t outlen) {
	if (out == NULL || S->lastblock || outlen > BLAKE2B_OUTBYTES)
		return -1;

	if (S->buflen > BLAKE2B_BLOCKBYTES) {
		S->counter += BLAKE2B_BLOCKBYTES;
		blake2b_compress (S, S->buf);
		S->buflen -= BLAKE2B_BLOCKBYTES;
		memcpy (S->buf, S->buf + BLAKE2B_BLOCKBYTES, S->buflen);
	}
	S->counter += S->buflen;
	S->lastblock = 1;
	memset (S->buf + S->buflen, 0, BLAKE2B_BLOCKBYTES - S->buflen);
	blake2b_compress (S, S->buf);
	memcpy (out, S->h, outlen);
	return 0;
}

char *
blake2b_info (void) {
#if defined(HAVE_SSE41)
	return "sse41";
#else
	return "sse2";
#endif
}
