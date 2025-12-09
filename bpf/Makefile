BPF_CLANG ?= clang
BPF_LLVM_STRIP ?= llvm-strip
BPF_SOURCES := micro_sentinel_kern.bpf.c
BPF_TARGET := micro_sentinel_kern.bpf.o

LIBBPF_ROOT ?= /home/hjjiang/tools/libbpf
LIBBPF_BUILD ?= $(LIBBPF_ROOT)/src/build
LIBBPF_PREFIX ?= $(LIBBPF_BUILD)/root/usr
LIBBPF_INCLUDE_DIR ?= $(LIBBPF_PREFIX)/include/bpf

VMLINUX ?= ./vmlinux.h

.PHONY: all clean vmlinux

all: $(BPF_TARGET)

$(BPF_TARGET): $(BPF_SOURCES) $(VMLINUX) ms_common.h
	$(BPF_CLANG) \
		-D__TARGET_ARCH_x86 \
		-D__TARGET_ARCH_x86_64 \
		-O2 -g \
		-target bpf \
		-I. \
		-I$(LIBBPF_INCLUDE_DIR) \
		-c $< -o $@
	$(BPF_LLVM_STRIP) -g $@

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

clean:
	rm -f $(BPF_TARGET)
