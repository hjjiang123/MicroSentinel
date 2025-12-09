// net_trace.c

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "net_trace.skel.h" // 自动生成的骨架文件

// 与 BPF C 代码中的 struct event 保持一致
struct event {
    int pid;
    char comm[16];
    char ifname[16];
    __u32 pkt_len;
};

// 信号处理函数，用于优雅地退出
static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

// Perf buffer 回调函数：处理从内核接收的事件
void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    const struct event *e = data;
    printf("PID: %d, COMM: %s, Interface: %s, Length: %u bytes\n",
           e->pid, e->comm, e->ifname, e->pkt_len);
}

int main(int argc, char **argv)
{
    struct net_trace_bpf *skel;
    struct perf_buffer *pb = NULL;
    int err;

    // 1. 设置信号处理
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 2. 打开 BPF 骨架
    skel = net_trace_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // 3. 加载 BPF 程序到内核
    err = net_trace_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program: %d\n", err);
        goto cleanup;
    }
    
    // 4. 挂载 BPF 程序到 tracepoint
    err = net_trace_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %d\n", err);
        goto cleanup;
    }

    // 5. 创建 perf buffer 来读取 events map
    // skel->maps.events 是 BPF 映射的引用
    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 64, handle_event, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer\n");
        err = -1;
        goto cleanup;
    }

    printf("Tracing netif_receive_skb... Press Ctrl-C to stop.\n");

    // 6. 循环等待并处理事件
    while (!exiting) {
        err = perf_buffer__poll(pb, 100); // 100ms 超时
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
        // 如果 perf_buffer__poll 返回 -EINTR (中断)，则继续循环
        // 如果返回 0 或大于 0，则处理了事件，继续循环
    }

cleanup:
    perf_buffer__free(pb);
    net_trace_bpf__destroy(skel);
    return -err;
}
