
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <atomic.h>

#define ntz(x) a_ctz_l((x))

typedef int (*cmpfun)(const void *, const void *);

static inline int pntz(size_t p[2])
{
	int r = ntz(p[0] - 1);
	if (r != 0 || (r = 8 * sizeof(size_t) + ntz(p[1])) != 8 * sizeof(size_t))
	{
		return r;
	}
	return 0;
}

static void cycle(size_t width, unsigned char *ar[], int n)
{
	unsigned char tmp[256];
	size_t l;
	int i;

	if (n < 2)
	{
		return;
	}

	ar[n] = tmp;
	while (width)
	{
		l = sizeof(tmp) < width ? sizeof(tmp) : width;
		memcpy(ar[n], ar[0], l);
		for (i = 0; i < n; i++)
		{
			memcpy(ar[i], ar[i + 1], l);
			ar[i] += l;
		}
		width -= l;
	}
}

/* shl() and shr() need n > 0 */
static inline void shl(size_t p[2], int n)
{
	if (n >= 8 * sizeof(size_t))
	{
		n -= 8 * sizeof(size_t);
		p[1] = p[0];
		p[0] = 0;
	}
	p[1] <<= n;
	p[1] |= p[0] >> (sizeof(size_t) * 8 - n);
	p[0] <<= n;
}

static inline void shr(size_t p[2], int n)
{
	if (n >= 8 * sizeof(size_t))
	{
		n -= 8 * sizeof(size_t);
		p[0] = p[1];
		p[1] = 0;
	}
	p[0] >>= n;
	p[0] |= p[1] << (sizeof(size_t) * 8 - n);
	p[1] >>= n;
}

static void sift(unsigned char *head, size_t width, cmpfun cmp, int pshift, size_t lp[])
{
	unsigned char *rt, *lf;
	unsigned char *ar[14 * sizeof(size_t) + 1];
	int i = 1;

	ar[0] = head;
	while (pshift > 1)
	{
		rt = head - width;
		lf = head - width - lp[pshift - 2];

		if ((*cmp)(ar[0], lf) >= 0 && (*cmp)(ar[0], rt) >= 0)
		{
			break;
		}
		if ((*cmp)(lf, rt) >= 0)
		{
			ar[i++] = lf;
			head = lf;
			pshift -= 1;
		}
		else
		{
			ar[i++] = rt;
			head = rt;
			pshift -= 2;
		}
	}
	cycle(width, ar, i);
}

static void trinkle(unsigned char *head, size_t width, cmpfun cmp, size_t pp[2], int pshift, int trusty, size_t lp[])
{
	unsigned char *stepson,
		*rt, *lf;
	size_t p[2];
	unsigned char *ar[14 * sizeof(size_t) + 1];
	int i = 1;
	int trail;

	p[0] = pp[0];
	p[1] = pp[1];

	ar[0] = head;
	while (p[0] != 1 || p[1] != 0)
	{
		stepson = head - lp[pshift];
		if ((*cmp)(stepson, ar[0]) <= 0)
		{
			break;
		}
		if (!trusty && pshift > 1)
		{
			rt = head - width;
			lf = head - width - lp[pshift - 2];
			if ((*cmp)(rt, stepson) >= 0 || (*cmp)(lf, stepson) >= 0)
			{
				break;
			}
		}

		ar[i++] = stepson;
		head = stepson;
		trail = pntz(p);
		shr(p, trail);
		pshift += trail;
		trusty = 0;
	}
	if (!trusty)
	{
		cycle(width, ar, i);
		sift(head, width, cmp, pshift, lp);
	}
}

void qsort(void *base, size_t nel, size_t width, cmpfun cmp)
{
	size_t lp[12 * sizeof(size_t)];
	size_t i, size = width * nel;
	unsigned char *head, *high;
	size_t p[2] = {1, 0};
	int pshift = 1;
	int trail;

	if (!size)
		return;

	head = base;
	high = head + size - width;

	/* Precompute Leonardo numbers, scaled by element width */
	for (lp[0] = lp[1] = width, i = 2; (lp[i] = lp[i - 2] + lp[i - 1] + width) < size; i++)
		;

	while (head < high)
	{
		if ((p[0] & 3) == 3)
		{
			sift(head, width, cmp, pshift, lp);
			shr(p, 2);
			pshift += 2;
		}
		else
		{
			if (lp[pshift - 1] >= high - head)
			{
				trinkle(head, width, cmp, p, pshift, 0, lp);
			}
			else
			{
				sift(head, width, cmp, pshift, lp);
			}

			if (pshift == 1)
			{
				shl(p, 1);
				pshift = 0;
			}
			else
			{
				shl(p, pshift - 1);
				pshift = 1;
			}
		}

		p[0] |= 1;
		head += width;
	}

	trinkle(head, width, cmp, p, pshift, 0, lp);

	while (pshift != 1 || p[0] != 1 || p[1] != 0)
	{
		if (pshift <= 1)
		{
			trail = pntz(p);
			shr(p, trail);
			pshift += trail;
		}
		else
		{
			shl(p, 2);
			pshift -= 2;
			p[0] ^= 7;
			shr(p, 1);
			trinkle(head - lp[pshift] - width, width, cmp, p, pshift + 1, 1, lp);
			shl(p, 1);
			p[0] |= 1;
			trinkle(head - width, width, cmp, p, pshift, 1, lp);
		}
		head -= width;
	}
}
