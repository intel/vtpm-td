#ifndef _STDLIB_H_
#define _STDLIB_H_

#include <stddef.h>

int atoi(const char *);

unsigned long strtoul(const char *, char **, int);
long strtol(const char *, char **, int);
void *malloc(size_t n);
void *realloc(void *p, size_t n);
void free(void *p);
#endif
