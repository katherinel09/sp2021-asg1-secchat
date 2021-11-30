.PHONY: all clean

#CFLAGS=-g -Wall -Werror -O0 -UDEBUG
CFLAGS=-Wall  -O0 -UDEBUG -fno-stack-protector -g
LDLIBS=-lsqlite3 -lcrypto -lssl
LDFLAGS=-O0 -fno-stack-protector
CC=../../../icp_kernel/tools/bin/bin/clang
CC=gcc
all: simple_cp_hijack simple_overflow simple_leak simple_mem_leak simple_heap_leak simple_heap_metadata_corruption memory_errors ltrace_strace_fun simple_double_free

clean:
	rm -f server client *.o chat.db simple_cp_hijack simple_overflow simple_leak simple_mem_leak simple_heap_leak simple_heap_metadata_corruption memory_errors ltrace_strace_fun simple_double_free
	rm -rf  valgrind-out.txt


util.o: util.c util.h

#cp_hijack.o: cp_hijack.c util.h

ltrace_strace_fun.o: ltrace_strace_fun.c

memory_errors.o: memory_errors.c

simple_overflow.o: simple_overflow.c

simple_cp_hijack.o: simple_cp_hijack.c

simple_leak.o: simple_leak.c

simple_mem_leak.o: simple_mem_leak.c

simple_heap_leak.o: simple_heap_leak.c

simple_double_free.o: simple_double_free.c

simple_heap_metadata_corruption.o: simple_heap_metadata_corruption.c

simple_overflow: simple_overflow.o util.o

simple_cp_hijack: simple_cp_hijack.o util.o

simple_leak: simple_leak.o util.o

simple_mem_leak: simple_mem_leak.o util.o

simple_heap_leak: simple_heap_leak.o util.o

simple_heap_metadata_corruption: simple_heap_metadata_corruption.o util.o

memory_errors: memory_errors.o util.o

ltrace_strace_fun: ltrace_strace_fun.o

simple_double_free: simple_double_free.o util.o




#cp_hijack: util.o cp_hijack.o



