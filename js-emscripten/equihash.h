#ifndef EQUIHASH_H
#define EQUIHASH_H

#define WN			200
#define WK			9

typedef struct {
	unsigned char	version[4];
	unsigned char	prevhash[32];
	unsigned char	merkleroot[32];
	unsigned char	reserved[32];
	unsigned char	time[4];
	unsigned char	bits[4];
	unsigned char	nonce[32];
	unsigned char	solsize[3];
	unsigned char	solution[1344];
} block_t;

typedef char equihash_dummy_t[1 / (sizeof (block_t) == 1487)];

void		step0 (block_t *block);
void		step (int step);	/* 1..WK */
int		solution (void);	/* implemented by caller */

#endif
