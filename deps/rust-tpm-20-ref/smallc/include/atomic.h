#ifndef _ATOMIC_H_
#define _ATOMIC_H_

#ifndef a_ctz_32
#define a_ctz_32 a_ctz_32
static inline int a_ctz_32(uint32_t x)
{
#ifdef a_clz_32
	return 31 - a_clz_32(x & -x);
#else
	static const char debruijn32[32] = {
		0, 1, 23, 2, 29, 24, 19, 3, 30, 27, 25, 11, 20, 8, 4, 13,
		31, 22, 28, 18, 26, 10, 7, 12, 21, 17, 9, 6, 16, 5, 15, 14};
	return debruijn32[(x & -x) * 0x076be629 >> 27];
#endif
}
#endif

#ifndef a_ctz_64
#define a_ctz_64 a_ctz_64
static inline int a_ctz_64(uint64_t x)
{
	static const char debruijn64[64] = {
		0, 1, 2, 53, 3, 7, 54, 27, 4, 38, 41, 8, 34, 55, 48, 28,
		62, 5, 39, 46, 44, 42, 22, 9, 24, 35, 59, 56, 49, 18, 29, 11,
		63, 52, 6, 26, 37, 40, 33, 47, 61, 45, 43, 21, 23, 58, 17, 10,
		51, 25, 36, 32, 60, 20, 57, 16, 50, 31, 19, 15, 30, 14, 13, 12};
	if (sizeof(long) < 8)
	{
		uint32_t y = x;
		if (!y)
		{
			y = x >> 32;
			return 32 + a_ctz_32(y);
		}
		return a_ctz_32(y);
	}
	return debruijn64[(x & -x) * 0x022fdd63cc95386dull >> 58];
}
#endif

static inline int a_ctz_l(unsigned long x)
{
	return (sizeof(long) < 8) ? a_ctz_32(x) : a_ctz_64(x);
}

#endif
