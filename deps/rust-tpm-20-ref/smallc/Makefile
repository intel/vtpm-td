
CSRC = $(wildcard src/*.c) $(wildcard src/string/*.c) $(wildcard src/stdlib/*.c) $(wildcard src/time/*.c)
OBJS = $(CSRC:.c=.o)

DEFINED =
TARGET = -target x86_64-unknown-none
CFLAGS += ${TARGET} ${DEFINED} -g -Wall -Werror -fPIC \
	-I include -std=c99 -nostdlib -nostdlibinc -ffreestanding \
	-mno-red-zone -mcmodel=small -fno-builtin

all: libsmallc.a smallc.lib

clean:
	$(RM) $(OBJS) $(TESTS_OBJS) libsmallc.a

libsmallc.a: $(OBJS)
	$(RM) $@
	$(AR) ru $@ $^

smallc.lib: $(OBJS)
	$(RM) $@
	$(AR) ru $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<
