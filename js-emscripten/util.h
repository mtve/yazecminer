#ifndef UTIL_H
#define UTIL_H

typedef unsigned char		uint8_t;
typedef unsigned short		uint16_t;
typedef unsigned int		uint32_t;
typedef unsigned long long	uint64_t;

typedef char util_dummy_t1[1 / (sizeof (uint8_t ) == 1)];
typedef char util_dummy_t2[1 / (sizeof (uint16_t) == 2)];
typedef char util_dummy_t4[1 / (sizeof (uint32_t) == 4)];
typedef char util_dummy_t8[1 / (sizeof (uint64_t) == 8)];

void		*memset (void *ptr, int val, unsigned int len);
void		*memcpy (void *dst, const void *src, unsigned int len);
int		memcmp (const void *a, const void *b, unsigned int len);

void		exit (int code);
int		puts (const char *str);

#endif
