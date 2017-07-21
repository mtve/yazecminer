/*
 * BLAKE2 reference source code package - optimized C implementations
 * Written in 2012 by Samuel Neves <sneves@dei.uc.pt>
 */

#ifndef __BLAKE2_H__
#define __BLAKE2_H__

#include "util.h"

#define BLAKE2B_BLOCKBYTES	128
#define BLAKE2B_OUTBYTES	64
#define BLAKE2B_KEYBYTES	64
#define BLAKE2B_SALTBYTES	16
#define BLAKE2B_PERSONALBYTES	16

typedef struct __blake2b_param {
	uint8_t		digest_length;	/* 1 */
	uint8_t		key_length;	/* 2 */
	uint8_t		fanout;		/* 3 */
	uint8_t		depth;		/* 4 */
	uint32_t	leaf_length;	/* 8 */
	uint64_t	node_offset;	/* 16 */
	uint8_t		node_depth;	/* 17 */
	uint8_t		inner_length;	/* 18 */
	uint8_t		reserved[14];	/* 32 */
	uint8_t		salt[BLAKE2B_SALTBYTES];		/* 48 */
	uint8_t		personal[BLAKE2B_PERSONALBYTES];	/* 64 */
} blake2b_param;

typedef char blake2b_dummy_t[1 / (sizeof (blake2b_param) == BLAKE2B_OUTBYTES)];

typedef struct __blake2b_state {
	uint64_t	h[8];
	uint8_t		buf[BLAKE2B_BLOCKBYTES];
	uint16_t	counter;
	uint8_t		buflen;
	uint8_t		lastblock;
} blake2b_state;

int	blake2b_init_param (blake2b_state *S, const blake2b_param *P);
int	blake2b_update (blake2b_state *S, const uint8_t *in, uint16_t inlen);
int	blake2b_final (blake2b_state *S, uint8_t *out, uint8_t outlen);
void 	blake2b_zcash (blake2b_state *S, uint32_t w3, uint8_t *out);

#endif
