#include <stdint.h>
#include <stdio.h>

int errno = 0;

// TBD: need impl
extern void __fw_debug_msg(char *, int);

int printf(char *fmt, ...)
{
#ifndef _PRINTF_BUF_SIZE_
#define _PRINTF_BUF_SIZE_ 512
#endif
    char buf[_PRINTF_BUF_SIZE_] = {0};
    int len = 0;
    va_list args;
    va_start(args, fmt);
    len = vsnprintf(buf, _PRINTF_BUF_SIZE_, fmt, args);
    va_end(args);
    __fw_debug_msg(buf, len);
    return len;
#undef _PRINTF_BUF_SIZE_
}

void __assert_fail(const char *expr, const char *file, int line, const char *func)
{
    printf("Assertion failed: %s (%s: %s: %d)\n", expr, file, func, line);
}

FILE *fopen(const char * filename, const char * mode){
    return 0;
}

size_t fread(void * destv, size_t size, size_t nmemb, FILE * f)
{
    return 0;
}

int fclose(FILE *f)
{
    return -1;
}

size_t fwrite(const void *restrict src, size_t size, size_t nmemb, FILE * f)
{
    return 0;
}

int sscanf(const char *restrict s, const char *restrict fmt, ...)
{
    return 0;
}

int fseek(FILE *f, long off, int whence) {
    return -1;
}

long ftell(FILE *f) {
    return -1;
}

char           *strerror   (int e)
{
    return (char*)0;
}

char           *getenv     (const char *n)
{
    return (char*)0;
}

char           *secure_getenv (const char *n)
{
    return (char*)0;
}
