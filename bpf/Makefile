BPF_CLANG ?= clang
BPF_LLVM_STRIP ?= llvm-strip
BPF_SOURCES := micro_sentinel_kern.bpf.c
BPF_TARGET := micro_sentinel_kern.o

VMLINUX ?= ./vmlinux.h

.PHONY: all clean vmlinux

all: $(BPF_TARGET)

$(BPF_TARGET): $(BPF_SOURCES) $(VMLINUX) ms_common.h
	$(BPF_CLANG) \
		-D__TARGET_ARCH_x86 \
		-O2 -g -Wall -Werror \
		-target bpf \
		-I. \
		-c $< -o $@
	$(BPF_LLVM_STRIP) -g $@

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

clean:
	rm -f $(BPF_TARGET)
