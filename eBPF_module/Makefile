CLANG=clang
BPFTOOL=bpftool

COMMON_FLAGS=-g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -Wall -Werror -I. -I./

CFLAGS=$(COMMON_FLAGS)

DEBUG_FLAGS=$(COMMON_FLAGS) -DDEBUG

ARCH := x86

all: ioNet.o

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

ioNet.o: ioNet.c vmlinux.h
	$(CLANG) $(CFLAGS) -c ioNet.c -o ioNet.o

debug: ioNet.c vmlinux.h
	$(CLANG) $(DEBUG_FLAGS) -c ioNet.c -o ioNet.o

clean:
	rm -f *.o vmlinux.h