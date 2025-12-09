#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "net_kprobe.skel.h" // 编译时自动生成的骨架头文件
#include <stdint.h>
#include <sys/resource.h>
static volatile bool exiting = false;

// 定义传给用户态的数据结构
struct event_t {
    uint32_t pid;
    uint32_t len;
    char comm[16];   // 进程名
    char ifname[16]; // 网卡名
};

// 处理 Ctrl-C 信号
static void sig_handler(int sig) {
    exiting = true;
}

// RingBuffer 的回调函数
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event_t *e = data;
    
    printf("PID: %-6d COMM: %-16s DEV: %-10s LEN: %d\n",
           e->pid, e->comm, e->ifname, e->len);
    return 0;
}

int main(int argc, char **argv) {
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return 1;
    }

    struct net_kprobe_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    // 设置信号处理
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 1. 打开并加载 BPF 脚手架
    skel = net_kprobe_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = net_kprobe_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    // 2. 挂载 (Attach) Kprobe
    err = net_kprobe_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    // 3. 设置 RingBuffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Successfully started! Ctrl+C to stop.\n");
    printf("%-6s %-16s %-10s %s\n", "PID", "COMM", "DEV", "LEN");

    // 4. 循环轮询
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    net_kprobe_bpf__destroy(skel);
    return -err;
}
