CLANG ?= clang
BPFTOOL ?= bpftool
CFLAGS ?= -g -O2 -Wall
INCLUDES := -I$(shell pwd)
BPF_OBJ = monitor.bpf.o

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): monitor.bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_x86 -c $< -o $@

clean:
	rm -f $(BPF_OBJ) vmlinux.h

.PHONY: clean
