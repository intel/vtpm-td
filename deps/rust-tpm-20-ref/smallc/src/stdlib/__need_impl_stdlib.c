#include <assert.h>
#include <stddef.h>
#include <stdint.h>

// TBD:
extern void *__fw_malloc(size_t n);
extern void __fw_free(void *p);
extern void *__fw_realloc(void *p, size_t n);
extern uint32_t __fw_rdrand32(void);

void *malloc(size_t n)
{
    return __fw_malloc(n);
}

void free(void *p)
{
    __fw_free(p);
}

void *realloc(void *p, size_t n)
{
    if(n == 0) {
        return 0;
    }

    if(p == 0) {
        return malloc(n);
    }

    return __fw_realloc(p, n);
}

int rand(void)
{
    return (int)__fw_rdrand32();
}
