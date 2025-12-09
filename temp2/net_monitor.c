#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "net_monitor.h"
#include "net_monitor.skel.h" // 自动生成的 Skeleton 头文件

static int stop = 0;

// Ctrl-C 信号处理
static void sig_handler(int signo)
{
    stop = 1;
}

// 处理 Ring Buffer 收到的事件
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    
    // 简单打印：网卡名和包长度
    printf("Dev: %-10s | Packet Len: %u bytes\n", e->dev, e->len);
    return 0;
}

int main(int argc, char **argv)
{
    struct net_monitor_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    // 设置信号处理
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 1. 打开并加载 BPF Skeleton
    skel = net_monitor_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = net_monitor_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    // 2. 挂载 Tracepoint
    err = net_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    // 3. 设置 Ring Buffer 轮询
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Successfully started! Ctrl-C to stop.\n");

    // 4. 循环轮询
    while (!stop) {
        err = ring_buffer__poll(rb, 100 /* timeout ms */);
        if (err == -EINTR)
            err = 0;
        if (err < 0) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    net_monitor_bpf__destroy(skel);
    return -err;
}
