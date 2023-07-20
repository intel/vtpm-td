AR = llvm-ar
RANLIB = ranlib
ARCH = x86_64
SUBARCH = 
ASMSUBARCH = 
srcdir = ./musl
includedir = ./include
syslibdir = /lib
CC = clang
CFLAGS = -fPIC
CFLAGS_AUTO = -Os -pipe -fomit-frame-pointer -fno-unwind-tables -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -w -Wno-pointer-to-int-cast -Werror=implicit-function-declaration -Werror=implicit-int -Werror=pointer-sign -Werror=pointer-arith -Werror=int-conversion -Werror=incompatible-pointer-types -Qunused-arguments -Waddress -Warray-bounds -Wchar-subscripts -Wduplicate-decl-specifier -Winit-self -Wreturn-type -Wsequence-point -Wstrict-aliasing -Wunused-function -Wunused-label -Wunused-variable
CFLAGS_C99FSE = -std=c99 -nostdinc -ffreestanding -frounding-math -fno-strict-aliasing -Wa,--noexecstack
CFLAGS_MEMOPS = 
CFLAGS_NOSSP = -fno-stack-protector
CPPFLAGS = 
LDFLAGS = 
LDFLAGS_AUTO = -Wl,--sort-section,alignment -Wl,--sort-common -Wl,--gc-sections -Wl,--hash-style=both -Wl,--no-undefined -Wl,--exclude-libs=ALL -Wl,--dynamic-list=./dynamic.list
CROSS_COMPILE = x86_64-
LIBCC = -lgcc -lgcc_eh
OPTIMIZE_GLOBS = internal/*.c malloc/*.c string/*.c
ALL_TOOLS =  obj/musl-clang obj/ld.musl-clang
TOOL_LIBS = 
ADD_CFI = no
MALLOC_DIR = mallocng
WRAPCC_CLANG = $(CC)
AOBJS = $(LOBJS)
