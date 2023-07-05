
## OpenSSL libc stub (smallc).

This is a small c library for running OpenSSL in bare metal environment.

Blow symbols must be supply for using this library.

  - print debug information

    ```
    extern void __fw_debug_msg(char *, int);
    ```

  - abort

    ```
    extern void __fw_abort();
    ```

  - malloc

    ```
    extern void *__fw_malloc(size_t n);
    ```

  - random

    ```
    extern uint32_t __fw_rdrand32(void);
    ```


## How to build

CC=clang-12 AR=llvm-ar-12 make

## TODOs:

  - Check snprintf implement
  - Investigate how to implement time malloc free realloc abort print
