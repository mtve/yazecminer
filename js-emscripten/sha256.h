/*
 * https://github.com/ckolivas/cgminer/
 * Copyright (C) 2013, Con Kolivas <kernel@kolivas.org>
 * Copyright (C) 2005, 2007 Olivier Gay <olivier.gay@a3.epfl.ch>
 */

#ifndef SHA256_H
#define SHA256_H

#include "util.h"

#define SHA256_DIGEST_SIZE (256 / 8)
#define SHA256_BLOCK_SIZE  (512 / 8)

typedef struct {
	unsigned int	tot_len;
	unsigned int	len;
	uint8_t		block[2 * SHA256_BLOCK_SIZE];
	uint32_t	h[8];
} sha256_ctx;

void		sha256_init (sha256_ctx *ctx);
void		sha256_update (sha256_ctx *ctx, const uint8_t *message,
		    unsigned int len);
void		sha256_final (sha256_ctx *ctx, uint8_t *digest);
void 		sha256 (const uint8_t *message, unsigned int len,
		    uint8_t *digest);

#endif
