#include <stdlib.h>

// TBD:
extern void __fw_abort();

void abort(void) {
    __fw_abort();
}