#include <emscripten.h>
#include "equihash.h"
#include "util.h"
#include "sha256.h"

#define puts(s)		((void)(s))

static block_t			block;
static uint8_t			target[SHA256_DIGEST_SIZE] = { 0 };

static int
hex2int (char ch) {
	return	'0' <= ch && ch <= '9' ? ch - '0' :
		'A' <= ch && ch <= 'F' ? ch - 'A' + 10 :
		'a' <= ch && ch <= 'f' ? ch - 'a' + 10 : -1;
}

static char
int2hex (uint8_t i) { return "0123456789abcdef"[i]; }

static void
from_hex (uint8_t *bin, char *hex, int len) {
	int		i;

	for (i = 0; i < len; i++)
		bin[i] = hex2int (hex[i * 2]) * 16 + hex2int (hex[i * 2 + 1]);
	if (hex[i * 2])
		puts ("bad len of hex string");
}

static void
to_hex (char *hex, uint8_t *bin, int len) {
	int		i;

	for (i = 0; i < len; i++) {
		hex[i * 2    ] = int2hex (bin[i] / 16);
		hex[i * 2 + 1] = int2hex (bin[i] % 16);
	}
	hex[i * 2] = 0;
}

EMSCRIPTEN_KEEPALIVE
void
mine (char *block_hex, char *target_hex) {
	int		i;

	from_hex ((void *)&block, block_hex, 140);
	from_hex ((void *)target, target_hex, sizeof (target));

	step0 (&block);
	for (i = 1; i <= WK; i++) {
		puts ("step");
		step (i);
	}
}

static int
above_target (void) {
	int		i;
	uint8_t		diff[SHA256_DIGEST_SIZE];

	sha256 ((uint8_t *)&block, sizeof (block), diff);
	sha256 (diff, SHA256_DIGEST_SIZE, diff);

	for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
		if (diff[SHA256_DIGEST_SIZE - 1 - i] < target[i])
			return 0;
		if (diff[SHA256_DIGEST_SIZE - 1 - i] > target[i])
			return 1;
	}
	return -1;
}

int
solution (void) {
	char		buf[sizeof (block)*2 + 2];

	if (above_target ()) {
		EM_ASM( above (); );
		puts ("above");
		return 0;
	}
	puts ("solution");
	to_hex (buf, (void *)&block, sizeof (block));
	EM_ASM_({ submit (Pointer_stringify ($0)); }, buf);
	return 1;
}

#if 0
int
main (void) {
	int		b, i;

	memset (&block, 0, sizeof (block));
	for (b = 0; b < 10; b++) {
		puts ("job");
		block.nonce[0] = b;
		step0 (&block);
		for (i = 1; i <= WK; i++) {
			puts ("step");
			step (i);
		}
	}
	return 0;
}
#endif
