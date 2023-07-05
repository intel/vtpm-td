#include <stdint.h>
#include <stddef.h>
#include <string.h>

size_t
strlen(str)
	const char *str;
{
	register const char *s;

	for (s = str; *s; ++s);
	return(s - str);
}

int strcmp(const char *l, const char *r)
{
	for (; *l==*r && *l; l++, r++);
	return *(unsigned char *)l - *(unsigned char *)r;
}

int strncmp(const char *_l, const char *_r, size_t n)
{
	const unsigned char *l=(void *)_l, *r=(void *)_r;
	if (!n--) return 0;
	for (; *l && *r && n && *l == *r ; l++, r++, n--);
	return *l - *r;
}

char *strcat(char * dest, const char * src)
{
	strcpy(dest + strlen(dest), src);
	return dest;
}

char *strncat(char * d, const char * s, size_t n)
{
	char *a = d;
	d += strlen(d);
	while (n && *s) n--, *d++ = *s++;
	*d++ = 0;
	return a;
}

char *__stpcpy(char * d, const char * s)
{
	for (; (*d=*s); s++, d++);
	return d;
}

char *strcpy(char * dest, const char * src)
{
	__stpcpy(dest, src);
	return dest;
}

char *__stpncpy(char *restrict d, const char *restrict s, size_t n)
{
	for (; n && (*d=*s); n--, s++, d++);
	memset(d, 0, n);
	return d;
}

char *strncpy(char *restrict d, const char *restrict s, size_t n)
{
	__stpncpy(d, s, n);
	return d;
}


char *__strchrnul(const char *s, int c)
{
	c = (unsigned char)c;
	if (!c) return (char *)s + strlen(s);
	for (; *s && *(unsigned char *)s != c; s++);
	return (char *)s;
}

char *strchr(const char *s, int c)
{
	char *r = __strchrnul(s, c);
	return *(unsigned char *)r == (unsigned char)c ? r : 0;
}

void *__memrchr(const void *m, int c, size_t n)
{
	const unsigned char *s = m;
	c = (unsigned char)c;
	while (n--) if (s[n]==c) return (void *)(s+n);
	return 0;
}

char *strrchr(const char *s, int c)
{
	return __memrchr(s, c, strlen(s) + 1);
}

void *memchr(const void *src, int c, size_t n)
{
	const unsigned char *s = src;
	c = (unsigned char)c;
	for (; n && *s != c; s++, n--);
	return n ? (void *)s : 0;
}
