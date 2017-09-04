#include "blake2b.h"
#include "equihash.h"

#define BLAKE2_OPT		0

#define DEBUG			0
#define printf(...)		((void)0)
#define fflush(...)		((void)0)

typedef uint32_t		word_t;

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
#define L2_STRINGS		(STRINGS / L1_BOXES * 7 / 4)
#define L1_MASK			(L1_BOXES - 1)
#define L2_MASK			(L2_BOXES - 1)
#define L12_MASK		((1 << STEP_BITS) - 1)
#define L212_MASK		((1 << (STEP_BITS + L2_BITS)) - 1)

#define L2Z_BITS		(L2_BITS + 2)
#define L2Z_MASK		((1 << L2Z_BITS) - 1)
#define TREE_BITS		(L1_BITS + L2Z_BITS * 2)
#define TREE_WORDS		DIV_UP (TREE_BITS, WORD_BITS)
#define TREE(i1,i2a,i2b)	(((i1) << (L2Z_BITS * 2)) | ((i2a) << L2Z_BITS) | (i2b))
#define TREE_L1(tree)		((tree) >> (L2Z_BITS * 2))
#define TREE_L2A(tree)		(((tree) >> L2Z_BITS) & L2Z_MASK)
#define TREE_L2B(tree)		((tree) & L2Z_MASK)

#define MEM_BITS(step)		(STRING_BITS - (step) * STEP_BITS + L2_BITS + TREE_WORDS * WORD_BITS)
#define MEM_WORDS(step)		(DIV_UP (MEM_BITS (step), WORD_BITS))
#define MEM_WORDS1		MEM_WORDS (1)
#define MEM_DECR0		(STRING_WORDS + TREE_WORDS - MEM_WORDS1)
#define TREE_POS(step)		(MEM_WORDS1 - 1 - ((step) >> 1))

#define BIT_IDX(x)		(WORD_BITS - 1 - (x) % WORD_BITS)
#define L2_FIRST_BIT(step)	BIT_IDX (STRING_ALIGN_BITS + (step    ) * STEP_BITS - L2_BITS)
#define L212_LAST_BIT(step)	BIT_IDX (STRING_ALIGN_BITS + (step + 1) * STEP_BITS - 1)

#define HASH_STRINGS		(BLAKE2B_OUTBYTES / STRING_BYTES)
#define HASH_BYTES		(HASH_STRINGS * STRING_BYTES)
#define HASHES			(STRINGS / HASH_STRINGS)

#define L12L2Z(i12,i2)		((i12) << L2Z_BITS | (i2))
#define L12L2Z_L2Z(pack)	((pack) & L2Z_MASK)
#define L12L2Z_L12(pack)	((pack) >> L2Z_BITS)

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
	int		cnt[L1_BOXES];
	word_t		mem[L1_BOXES][L2_STRINGS][MEM_WORDS1];
} l1_t;

static block_t		*pblock;
static l1_t		l1x, l1y;

#define L1(step)		((step) & 1 ? &l1y : &l1x)

#if DEBUG
static word_t		orig[STRINGS][STRING_WORDS];
#endif

static void
die (char *str) {
	(void)str;
	printf ("die: %s\n", str);
	exit (1);
}

static void
l1_init (l1_t *l1) {
	memset (l1->cnt, 0, sizeof (l1->cnt));
}

static word_t *
l1_addr (l1_t *l1, word_t i1) {
	int		i2;

	ASSERT (i1 < L1_BOXES);
	i2 = l1->cnt[i1]++;
	if (DEBUG && i2 >= L2_STRINGS - 1)
		die ("no mem");
	return l1->mem[i1][i2];
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
step0_add (int s, uint8_t *str) {
	int			i, j, k;
	word_t			*ptr, x;

#if DEBUG
	orig[s][STRING_WORDS - 1] = 0;
	memcpy (orig[s], str, STRING_BYTES);
#endif
	/* everything is LE but bits are BE... f*ck that, BE all */

	ASSERT (L1_BITS <= 16);
	ptr = l1_addr (L1 (0), ((str[0] << 8) | str[1]) >> (16 - L1_BITS));

	k = MEM_DECR0 * WORD_BYTES - STRING_ALIGN_BYTES;
	for (i = 0; i < MEM_WORDS1 - 1; i++) {
		x = 0;
		for (j = WORD_BYTES - 1; j >= 0; j--, k++)
			if (k >= 0)
				x |= str[k] << (BYTE_BITS * j);
		ptr[i] = x;
	}
	ASSERT (k == STRING_BYTES);
	ptr[TREE_POS (0)] = s;
}

void
step0 (block_t *p) {
	int			h, i;
	blake2b_state		state;
	blake2b_param		param;
	uint8_t			hash[HASH_BYTES];

	ASSERT (STRING_BITS % BYTE_BITS == 0);
	ASSERT (STRING_ALIGN_BITS % BYTE_BITS == 0);
	ASSERT ((STRING_ALIGN_BYTES + STRING_BYTES) % WORD_BYTES == 0);
	ASSERT (L2_BITS + STEP_BITS <= WORD_BITS);
	ASSERT (TREE_WORDS == 1);
	ASSERT (TREE_POS (0) == MEM_WORDS1 - 1);
	ASSERT (TREE_POS (WK - 1) >= MEM_WORDS (WK - 1) - 1);

	pblock = p;
	ASSERT (DIV_UP (SOLUTION_NUMS * STRING_IDX_BITS, BYTE_BITS) ==
	    sizeof (pblock->solution));

	memset (&param, 0, sizeof (param));
	memcpy (param.personal, "ZcashPoW", 8);
	ASSERT (WN < 256);
	ASSERT (WK < 256);
	param.personal[8] = WN;
	param.personal[12] = WK;
	param.digest_length = HASH_BYTES;
	param.fanout = 1;
	param.depth = 1;
	blake2b_init_param (&state, &param);
	blake2b_update (&state, (uint8_t *)pblock,
	    pblock->solsize - pblock->version);

	l1_init (L1 (0));
	ASSERT (STRING_BYTES == HASH_BYTES / HASH_STRINGS);
	for (h = 0; h < HASHES; h++) {
#if BLAKE2_OPT
		blake2b_zcash (&state, h, hash);
#else
		blake2b_state	state2 = state;

		blake2b_update (&state2, (uint8_t *)&h, 4); /* LE only!!! */
		blake2b_final (&state2, hash, HASH_BYTES);
#endif
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
tree_restore (int step, word_t *sol, word_t tree) {
	int		i, j,
			k = 1 << (step - 1),
			i1 = TREE_L1 (tree),
			i2a = TREE_L2A (tree),
			i2b = TREE_L2B (tree);

	if (step == 0) {
		*sol = tree;
		return 1;
	}

#define T(i2)	L1 (step - 1)->mem[i1][i2][TREE_POS (step - 1)]
	if (!tree_restore (step - 1, sol    , T (i2a)))
		return 0;
	if (!tree_restore (step - 1, sol + k, T (i2b)))
		return 0;
#undef T

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
	return 1;
}

static int
check_sol (word_t tree) {
	word_t		sol[SOLUTION_NUMS];
	int		i;
#if DEBUG
	int		j;
	word_t		xor, nok;
#endif

	if (!tree_restore (WK, sol, tree))
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

#define GENSTEP(step) \
void \
genstep##step (void) { \
	const int	WORDS = MEM_WORDS (step); \
	const int	WORDS_NEXT = MEM_WORDS (step + 1); \
	const int	DECR = WORDS - WORDS_NEXT; \
	l1_t		*l1f = L1 (step - 1); \
	l1_t		*l1t = L1 (step); \
	int		i1, i2a, a2, i3, ib, i2b, i; \
	word_t		a212, b2z, c12; \
	word_t		*pa, *pb, *pc; \
	uint8_t		l3cnt[L2_BOXES]; \
	word_t		l3i2[L2_BOXES][L3_STRINGS]; \
	\
	l1_init (l1t); \
	if (DEBUG) { \
		printf ("step %d\n", step); \
		fflush (stdout); \
	} \
	for (i1 = 0; i1 < L1_BOXES; i1++) { \
		memset (l3cnt, 0, sizeof (l3cnt)); \
		for (i2a = l1f->cnt[i1] - 1; i2a >= 0; i2a--) { \
			ASSERT (i2a <= L2Z_MASK); \
			pa = l1f->mem[i1][i2a]; \
			a212 = l212_val (step, pa); \
			a2 = a212 >> STEP_BITS; \
			i3 = l3cnt[a2]++; \
			if (DEBUG && i3 >= L3_STRINGS) \
				die ("no l3"); \
			l3i2[a2][i3] = L12L2Z (a212, i2a); \
			for (ib = i3 - 1; ib >= 0; ib--) { \
				b2z = l3i2[a2][ib]; \
				i2b = L12L2Z_L2Z (b2z); \
				pb = l1f->mem[i1][i2b]; \
				if (step < WK && \
				    pa[WORDS - 2] == pb[WORDS - 2]) { \
					continue; \
				} \
				c12 = (a212 ^ L12L2Z_L12 (b2z)) \
				    & L12_MASK; \
				if (step == WK) { \
					if (!c12 && \
					    check_sol (TREE (i1, i2a, i2b))) \
						return; \
					continue; \
				} \
				pc = l1_addr (l1t, c12 >> L2_BITS); \
				for (i = 0; i < WORDS_NEXT - 1; i++) \
					pc[i] = pa[i + DECR] ^ pb[i + DECR]; \
				ASSERT (i <= TREE_POS (step)); \
				ASSERT (i1 < L1_BOXES); \
				ASSERT (i2a <= L2Z_MASK); \
				ASSERT (i2b <= L2Z_MASK); \
				pc[TREE_POS (step)] = TREE (i1, i2a, i2b); \
			} \
		} \
	} \
}

GENSTEP(1)
GENSTEP(2)
GENSTEP(3)
GENSTEP(4)
GENSTEP(5)
GENSTEP(6)
GENSTEP(7)
GENSTEP(8)
GENSTEP(9)

void
step (int step) {
	switch (step) {
	case 1: genstep1 (); break;
	case 2: genstep2 (); break;
	case 3: genstep3 (); break;
	case 4: genstep4 (); break;
	case 5: genstep5 (); break;
	case 6: genstep6 (); break;
	case 7: genstep7 (); break;
	case 8: genstep8 (); break;
	case 9: genstep9 (); break;
	default: die ("wtf");
	}
}
