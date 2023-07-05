#ifndef _STDIO_H_
#define _STDIO_H_

#include <stddef.h>
#include <stdarg.h>

#define SEEK_SET 0
#define SEEK_END 1
#define SEEK_CUR 2

typedef size_t FILE;

int printf(char *fmt, ...);
int snprintf(char *str, size_t size, const char *format, ...);
int vsnprintf(char *str, size_t size, const char *format, va_list arg);

FILE *fopen(const char *, const char *);
size_t fread(void *, size_t, size_t, FILE *);
size_t fwrite(const void *, size_t, size_t, FILE *);
int fclose(FILE *);
int fprintf(FILE *, const char *, ...);
int fseek(FILE *stream, long offset, int whence);
long ftell(FILE *stream);
int fflush(FILE *stream);

#endif