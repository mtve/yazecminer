/*
 * Copyright 2012, Samuel Neves <sneves@dei.uc.pt>
 */

#include "blake2b.h"

#define UNROLL			0
#define UNROLL_OPT		1

static const uint64_t		blake2b_IV[8] = {
	0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
	0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
	0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
	0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint8_t		blake2b_sigma[12][16] = {
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}
};

static uint64_t
rotr64 (const uint64_t w, const unsigned c) {
	return (w >> c) | (w << (64 - c));
}

static uint64_t 
load64 (const void *src) {
	const uint8_t  *p = (const uint8_t *)src;

	return	((uint64_t) p[0] <<  0) |
		((uint64_t) p[1] <<  8) |
		((uint64_t) p[2] << 16) |
		((uint64_t) p[3] << 24) |
		((uint64_t) p[4] << 32) |
		((uint64_t) p[5] << 40) |
		((uint64_t) p[6] << 48) |
		((uint64_t) p[7] << 56);
}

static void 
store64 (void *dst, uint64_t w) {
	uint8_t        *p = (uint8_t *) dst;

	p[0] = (uint8_t) (w >>  0);
	p[1] = (uint8_t) (w >>  8);
	p[2] = (uint8_t) (w >> 16);
	p[3] = (uint8_t) (w >> 24);
	p[4] = (uint8_t) (w >> 32);
	p[5] = (uint8_t) (w >> 40);
	p[6] = (uint8_t) (w >> 48);
	p[7] = (uint8_t) (w >> 56);
}

int 
blake2b_init_param (blake2b_state *S, const blake2b_param *P) {
	const uint8_t  *p = (const uint8_t *)(P);
	int		i;

	memset (S, 0, sizeof (blake2b_state));
	for (i = 0; i < 8; i++)
		S->h[i] = blake2b_IV[i] ^ load64 (p + sizeof (S->h[i]) * i);

	return 0;
}

#define G(r,i,a,b,c,d)					\
	do {						\
		a = a + b + m[blake2b_sigma[r][2*i+0]];	\
		d = rotr64 (d ^ a, 32);			\
		c = c + d;				\
		b = rotr64 (b ^ c, 24);			\
		a = a + b + m[blake2b_sigma[r][2*i+1]];	\
		d = rotr64 (d ^ a, 16);			\
		c = c + d;				\
		b = rotr64 (b ^ c, 63);			\
	} while(0)

#define ROUND(r)					\
	do {						\
		G (r, 0, v[ 0], v[ 4], v[ 8], v[12]);	\
		G (r, 1, v[ 1], v[ 5], v[ 9], v[13]);	\
		G (r, 2, v[ 2], v[ 6], v[10], v[14]);	\
		G (r, 3, v[ 3], v[ 7], v[11], v[15]);	\
		G (r, 4, v[ 0], v[ 5], v[10], v[15]);	\
		G (r, 5, v[ 1], v[ 6], v[11], v[12]);	\
		G (r, 6, v[ 2], v[ 7], v[ 8], v[13]);	\
		G (r, 7, v[ 3], v[ 4], v[ 9], v[14]);	\
	} while(0)

static void
round (int r, uint64_t *v, uint64_t *m) {
	G (r, 0, v[ 0], v[ 4], v[ 8], v[12]);
	G (r, 1, v[ 1], v[ 5], v[ 9], v[13]);
	G (r, 2, v[ 2], v[ 6], v[10], v[14]);
	G (r, 3, v[ 3], v[ 7], v[11], v[15]);
	G (r, 4, v[ 0], v[ 5], v[10], v[15]);
	G (r, 5, v[ 1], v[ 6], v[11], v[12]);
	G (r, 6, v[ 2], v[ 7], v[ 8], v[13]);
	G (r, 7, v[ 3], v[ 4], v[ 9], v[14]);
}

static void 
blake2b_compress (blake2b_state *S, const uint8_t block[BLAKE2B_BLOCKBYTES]) {
	uint64_t	m[16];
	uint64_t	v[16];
	int		i;

	for (i = 0; i < 16; i++)
		m[i] = load64 (block + i * sizeof (m[i]));

	for (i = 0; i < 8; i++)
		v[i] = S->h[i];

	v[8] = blake2b_IV[0];
	v[9] = blake2b_IV[1];
	v[10] = blake2b_IV[2];
	v[11] = blake2b_IV[3];
	v[12] = blake2b_IV[4] ^ S->counter;
	v[13] = blake2b_IV[5];
	v[14] = blake2b_IV[6] ^ (S->lastblock ? -1LL : 0);
	v[15] = blake2b_IV[7];

#if UNROLL
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
#else
	for (i = 0; i < 12; i++)
		round (i, v, m);
#endif

	for (i = 0; i < 8; i++)
		S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
}

void 
blake2b_zcash (blake2b_state *S, uint32_t w3, uint8_t *out) {
	uint64_t	m[16];
	uint64_t	v[16];
	int		i;

	m[0] = 0;
	m[1] = (uint64_t)w3 << 32;
	for (i = 2; i < 16; i++)
		m[i] = 0;

	for (i = 0; i < 8; i++)
		v[i] = S->h[i];

	v[8] = blake2b_IV[0];
	v[9] = blake2b_IV[1];
	v[10] = blake2b_IV[2];
	v[11] = blake2b_IV[3];
	v[12] = blake2b_IV[4] ^ 144;
	v[13] = blake2b_IV[5];
	v[14] = blake2b_IV[6] ^ -1LL;
	v[15] = blake2b_IV[7];

#if UNROLL_OPT
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
#else
	for (i = 0; i < 12; i++)
		round (i, v, m);
#endif

	for (i = 0; i < 6; i++)
		((uint64_t *)out)[i] = S->h[i] ^ v[i] ^ v[i + 8];
	*(uint16_t *)(out + 48) = (uint16_t)S->h[6] ^ v[6] ^ v[14];
}

#undef G
#undef ROUND

int 
blake2b_update (blake2b_state *S, const uint8_t *in, uint16_t inlen) {
	if (inlen > 0) {
		uint32_t	left = S->buflen;
		uint32_t	fill = BLAKE2B_BLOCKBYTES - left;

		if (inlen > fill) {
			S->buflen = 0;
			memcpy (S->buf + left, in, fill);
			S->counter += BLAKE2B_BLOCKBYTES;
			blake2b_compress (S, S->buf);
			in += fill;
			inlen -= fill;
			while (inlen > BLAKE2B_BLOCKBYTES) {
				S->counter += BLAKE2B_BLOCKBYTES;
				blake2b_compress (S, in);
				in += BLAKE2B_BLOCKBYTES;
				inlen -= BLAKE2B_BLOCKBYTES;
			}
		}
		memcpy (S->buf + S->buflen, in, inlen);
		S->buflen += inlen;
	}
	return 0;
}

int 
blake2b_final (blake2b_state *S, uint8_t *out, uint8_t outlen) {
	uint8_t		buffer[BLAKE2B_OUTBYTES] = { 0 };
	int		i;

	if (outlen > BLAKE2B_OUTBYTES || S->lastblock)
		return -1;

	S->counter += S->buflen;
	S->lastblock = 1;
	memset (S->buf + S->buflen, 0, BLAKE2B_BLOCKBYTES - S->buflen);
	blake2b_compress (S, S->buf);

	for (i = 0; i < 8; i++)
		store64 (buffer + sizeof (S->h[i]) * i, S->h[i]);

	memcpy (out, buffer, outlen);
	return 0;
}
