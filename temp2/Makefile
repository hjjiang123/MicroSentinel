# 确保 libbpf 和 clang/llvm 可用
CLANG ?= clang
LIBBPF_DIR ?= /usr/lib/x86_64-linux-gnu/libbpf.so

# BPF 目标文件 (.o)
BPF_OBJ = net_trace.bpf.o

# 用户空间可执行文件
USER_PROG = net_trace

# 编译 BPF C 代码
$(BPF_OBJ): net_trace.bpf.c
    $(CLANG) -target bpf -g -O2 -c $< -o $@ -I. -I/usr/include/bpf

# 生成 BPF 骨架头文件
net_trace.skel.h: $(BPF_OBJ)
    bpftool gen skeleton $< > $@

# 编译用户空间程序
$(USER_PROG): net_trace.c net_trace.skel.h
    $(CLANG) $^ -o $@ -l:libbpf.a -lz -lelf -I/usr/include/bpf

all: $(USER_PROG)

clean:
    rm -f $(BPF_OBJ) $(USER_PROG) net_trace.skel.h
