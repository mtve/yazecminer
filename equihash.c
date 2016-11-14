#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>

#include "blake2b.h"
#include "equihash.h"

#define DEBUG			0

typedef unsigned int		word_t;

#define STRING_IDX_BITS		(WN / (WK + 1) + 1)
#define STRINGS			(1 << STRING_IDX_BITS)
#define SOLUTION_NUMS		(1 << WK)
#define STEP_BITS		(WN / (WK + 1))

#define BYTE_BITS		(8)
#define WORD_BYTES		((int)sizeof (word_t))
#define WORD_BITS		(WORD_BYTES * BYTE_BITS)
#define DIV_UP(x,r)		((x + r - 1) / r)

#define STRING_BITS		(WN)
#define STRING_BYTES		(STRING_BITS / BYTE_BITS)
#define STRING_WORDS		DIV_UP (STRING_BYTES, WORD_BYTES)
#define STRING_ALIGN_BITS	(STRING_WORDS * WORD_BITS - STRING_BITS)
#define STRING_ALIGN_BYTES	(STRING_ALIGN_BITS / BYTE_BITS)

#define L2_BITS			(8)
#define L1_BITS			(STEP_BITS - L2_BITS)
#define L3_STRINGS		16
#define L1_BOXES		(1 << L1_BITS)
#define L2_BOXES		(1 << L2_BITS)
#define L2_STRINGS		(STRINGS / L1_BOXES * 5 / 2)
#define L1_MASK			(L1_BOXES - 1)
#define L2_MASK			(L2_BOXES - 1)
#define L12_MASK		((1 << STEP_BITS) - 1)
#define L212_MASK		((1 << (STEP_BITS + L2_BITS)) - 1)

#define MEM_BITS(step)		(STRING_BITS - (step) * STEP_BITS + L2_BITS + WORD_BITS)
#define MEM_WORDS(step)		(DIV_UP (MEM_BITS (step), WORD_BITS))
#define MEM_DECR0		(STRING_WORDS + 1 - MEM_WORDS (1))
#define L2_WORDS		(MEM_WORDS (1) * L2_STRINGS)

#define BIT_IDX(x)		(WORD_BITS - 1 - (x) % WORD_BITS)
#define L2_FIRST_BIT(step)	BIT_IDX (STRING_ALIGN_BITS + (step    ) * STEP_BITS - L2_BITS)
#define L212_LAST_BIT(step)	BIT_IDX (STRING_ALIGN_BITS + (step + 1) * STEP_BITS - 1)

#define TREE_SIZE		(STRINGS * WK)

#define HASH_STRINGS		(BLAKE2B_OUTBYTES / STRING_BYTES)
#define HASH_BYTES		(HASH_STRINGS * STRING_BYTES)
#define HASHES			(STRINGS / HASH_STRINGS)

#if DEBUG
#define IF_DEBUG(x)		(x)
#define ASSERT(x)						\
	do {							\
		if (!(x)) {					\
			printf ("%s:%d assertion %s failed\n",	\
			    __FILE__, __LINE__, #x);		\
			exit (1);				\
		}						\
	} while (0)
#else
#define IF_DEBUG(x)		((void)0)
#define ASSERT(x)		((void)0)
#endif

typedef struct {
	int		l2cnt[L1_BOXES];
	word_t		l2mem[L1_BOXES][L2_WORDS];
} l1_t;

static block_t		*pblock;
static l1_t		l1a, l1b;
static word_t		tree[TREE_SIZE][2];
static int		ntree;

#if DEBUG
static word_t		orig[STRINGS][STRING_BYTES];
#endif

static void
die (char *str) {
	printf ("die: %s\n", str);
	exit (1);
}

static void
store32 (uint8_t *c, int b) {
	c[0] = b;
	c[1] = b >> 8;
	c[2] = b >> 16;
	c[3] = b >> 24;
}

static void
l1_init (l1_t *l1) {
	memset (l1->l2cnt, 0, sizeof (l1->l2cnt));
}

static word_t *
l1_addr (int step, l1_t *l1, word_t i1) {
	int		i2;

	ASSERT (i1 < L1_BOXES);
	i2 = l1->l2cnt[i1]++;
	if (DEBUG && i2 >= L2_STRINGS - 1)
		die ("no mem");
	return &l1->l2mem[i1][i2 * MEM_WORDS (step)];
}

static word_t
l212_val (int step, word_t *ptr) {
	int		f = L2_FIRST_BIT (step);
	int		t = L212_LAST_BIT (step);
	word_t		x;

	/* big endian */
	if (f > t) {
		/* same word, bits w0[f..t] */
		x = ptr[0] >> t;
	} else {
		/* two words, bits w0[f..0].w1[max..t] */
		x = (ptr[0] << (WORD_BITS - t)) | (ptr[1] >> t);
	}
	return x & L212_MASK;
}

static void
step0_add (int s, uint8_t *string) {
	int			i, j, k, x;
	word_t			w[STRING_WORDS], *ptr;

	/* everything is LE but bits are BE... f*ck that, BE all */

	k = -STRING_ALIGN_BYTES;
	for (i = 0; i < STRING_WORDS; i++) {
		x = 0;
		for (j = WORD_BYTES - 1; j >= 0; j--, k++)
			x |= (k < 0 ? 0 : string[k]) << (BYTE_BITS * j);
		w[i] = x;
	}
#if DEBUG
	memcpy (orig[s], w, STRING_WORDS * WORD_BYTES);
#endif
	ASSERT (STRING_ALIGN_BITS >= L2_BITS);

	ptr = l1_addr (1, &l1a, (l212_val (0, w) >> L2_BITS) & L1_MASK);
	memcpy (ptr, w + MEM_DECR0, (MEM_WORDS (1) - 1) * WORD_BYTES);
	ptr[MEM_WORDS (1) - 1] = -s - 1;
}

void
step0 (block_t *p) {
	int			h, i;
	blake2b_state		state0 = { 0 },
				state;
	blake2b_param		param = { 0 };
	uint8_t			c[4], hash[HASH_BYTES];

	ASSERT (STRING_BITS % BYTE_BITS == 0);
	ASSERT (STRING_ALIGN_BITS % BYTE_BITS == 0);
	ASSERT ((STRING_ALIGN_BYTES + STRING_BYTES) % WORD_BYTES == 0);
	ASSERT (L2_BITS + STEP_BITS <= WORD_BITS);

	pblock = p;
	ASSERT (DIV_UP (SOLUTION_NUMS * STRING_IDX_BITS, BYTE_BITS) ==
	    sizeof (pblock->solution));

	memcpy (param.personal, "ZcashPoW", 8);
	ASSERT (WN < 256);
	ASSERT (WK < 256);
	param.personal[8] = WN;
	param.personal[12] = WK;
	param.digest_length = HASH_BYTES;
	param.fanout = 1;
	param.depth = 1;
	blake2b_init_param (&state0, &param);
	blake2b_update (&state0, (uint8_t *)pblock,
	    pblock->solsize - pblock->version);

	ntree = 0;
	l1_init (&l1a);
	ASSERT (STRING_BYTES == HASH_BYTES / HASH_STRINGS);
	for (h = 0; h < HASHES; h++) {
		store32 (c, h);
		state = state0;
		blake2b_update (&state, c, 4);
		blake2b_final (&state, hash, HASH_BYTES);

		for (i = 0; i < HASH_STRINGS; i++)
			step0_add (h * HASH_STRINGS + i,
			    hash + i * STRING_BYTES);
	}
	if (DEBUG) {
		printf ("step0\n");
		fflush (stdout);
	}
}

static int
tree_restore (int step, word_t *sol, int idx) {
	int		i, j,
			k = 1 << (step - 1);

	if (step == 0) {
		ASSERT (idx < 0);
		*sol = -idx - 1;
	} else {
		ASSERT (idx >= 0);
		ASSERT (idx <= ntree);
		if (!tree_restore (step - 1, sol, tree[idx][0]))
			return 0;
		if (!tree_restore (step - 1, sol + k, tree[idx][1]))
			return 0;
		for (i = 0; i < k; i++)
		for (j = 0; j < k; j++)
			if (sol[i] == sol[j + k])
				return 0;
		if (sol[0] > sol[k]) {
			for (i = 0; i < k; i++) {
				j = sol[i];
				sol[i] = sol[i + k];
				sol[i + k] = j;
			}
		}
	}
	return 1;
}

static int
check_sol () {
	word_t		sol[SOLUTION_NUMS];
	int		i;
#if DEBUG
	int		j;
	word_t		xor, nok;
#endif

	if (!tree_restore (WK, sol, ntree))
		return 0;

#if DEBUG
	printf ("solution");
	for (i = 0; i < SOLUTION_NUMS; i++)
		printf (" %x", sol[i]);

	printf (" xor");
	nok = 0;
	for (j = 0; j < STRING_WORDS; j++) {
		xor = 0;
		for (i = 0; i < SOLUTION_NUMS; i++)
			xor ^= orig[ sol[i] ][j];
		printf (" %x", xor);
		nok |= xor;
	}
	printf ("\n");
	if (nok)
		die ("not ok");
#endif

	ASSERT (sizeof (pblock->solution) >= 0xfd);
	ASSERT (sizeof (pblock->solution) <= 0xffff);
	pblock->solsize[0] = 0xfd;
	pblock->solsize[1] = (uint8_t)(sizeof (pblock->solution));
	pblock->solsize[2] = (uint8_t)(sizeof (pblock->solution) >> 8);

	memset (pblock->solution, 0, sizeof (pblock->solution));
	for (i = 0; i < SOLUTION_NUMS * STRING_IDX_BITS; i++)
		if (sol[i / STRING_IDX_BITS] &
		    (1 << (STRING_IDX_BITS - 1 - i % STRING_IDX_BITS)))
			pblock->solution[i / 8] |= 1 << (7 - i % 8);

	return solution ();
}

void
step (int step) {
	const int	WORDS = MEM_WORDS (step);
	const int	WORDS_NEXT = MEM_WORDS (step + 1);
	const int	DECR = WORDS - WORDS_NEXT;
	l1_t		*l1f = step & 1 ? &l1a : &l1b;
	l1_t		*l1t = step & 1 ? &l1b : &l1a;
	int		i1, ia, a2, i3, ib, i;
	word_t		a212, c12;
	word_t		*pa, *pb, *pc;
	uint8_t		l3cnt[L2_BOXES];
	word_t		*l3ptr[L2_BOXES][L3_STRINGS];

	l1_init (l1t);
	for (i1 = 0; i1 < L1_BOXES; i1++) {
		memset (l3cnt, 0, sizeof (l3cnt));
		
		for (ia = l1f->l2cnt[i1] - 1; ia >= 0; ia--) {
			pa = &l1f->l2mem[i1][ia * WORDS];
			a212 = l212_val (step, pa);
			a2 = a212 >> STEP_BITS;
			i3 = l3cnt[a2]++;
			if (DEBUG) {
				if (i3 >= L3_STRINGS)
					die ("no l3");
				if (ntree >= TREE_SIZE - L3_STRINGS)
					die ("no tree");
			}
			l3ptr[a2][i3] = pa;
			for (ib = i3 - 1; ib >= 0; ib--) {
				pb = l3ptr[a2][ib];
				
				if (step < WK &&
				    pa[WORDS - 2] == pb[WORDS - 2]) {
					continue;
				}
				c12 = (a212 ^ l212_val (step, pb)) &
				    L12_MASK;
				if (step == WK && c12)
					continue;
					
				tree[ntree][0] = pa[WORDS - 1];
				tree[ntree][1] = pb[WORDS - 1];
				if (step == WK) {
					if (check_sol ())
						return;
					continue;
				}
				pc = l1_addr (step + 1, l1t, c12 >> L2_BITS);
				for (i = 0; i < WORDS_NEXT - 1; i++)
					pc[i] = pa[i + DECR] ^ pb[i + DECR];
				pc[WORDS_NEXT - 1] = ntree++;
			}
		}
	}
#if DEBUG
	printf ("step %d tree %d/%d\n", step, ntree, TREE_SIZE);
	fflush (stdout);
#endif
}
