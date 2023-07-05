#ifndef _STRING_H_
#define _STRING_H_

#include <stddef.h>

size_t strlen(const char *);

int strcmp(const char *, const char *);
int strncmp(const char *, const char *, size_t);

char *strcat(char *, const char *);
char *strncat(char *, const char *, size_t);

char *strcpy(char *, const char *);
char *strncpy(char *, const char *, size_t);

char *strchr(const char *, int);
char *strrchr(const char *, int);

char *strstr(const char *, const char *);

size_t strcspn(const char *s, const char *c);
size_t strspn(const char *s, const char *c);

void *memset(void *, int, size_t);
void *memcpy(void *, const void *, size_t);
int memcmp(const void *vl, const void *vr, size_t n);
void *memmove(void *dest, const void *src, size_t n);
void *memchr(const void *, int, size_t);

#include <strings.h>

#endif
