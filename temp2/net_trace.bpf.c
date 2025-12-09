// net_trace.bpf.c

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 定义事件结构体，用于在用户空间和内核空间间传递数据

#define IFNAMSIZ 16

struct event {
    int pid;
    char comm[TASK_COMM_LEN];
    char ifname[IFNAMSIZ];
    __u32 pkt_len; // 数据包长度
};

// BPF 映射：perf buffer 用于将事件发送给用户空间
// 0 是 perf buffer 类型
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// tracepoint/net/netif_receive_skb 的 BPF 处理函数
// 使用通用的 void* ctx 作为上下文
// 且SEC名称采用 tp/net/netif_receive_skb 格式
SEC("tp/net/netif_receive_skb")
int handle_netif_receive(void *ctx)
{
    // 获取 tracepoint 上下文指针。
    // 在 BPF 程序中，可以通过 bpf_core_read 获取其字段。
    // 需要通过 ctx 获取 skbaddr 和 devaddr。

    // BPF 宏定义了 TRACE_EVENT_FN(netif_receive_skb, proto, bool skb_addr, bool dev_addr)
    // 其参数通常命名为 skbaddr 和 devaddr
    unsigned long skbaddr;
    unsigned long devaddr;

    // 使用 BPF_CORE_READ 访问 tracepoint 上下文中的字段。
    // ctx 是 tracepoint 的上下文，其内部结构体类型是匿名的，但字段是已知的。
    // offset 0 是 common_type, offset 4 是 common_flags 等，
    // skbaddr 和 devaddr 字段的位置取决于内核版本和 tracepoint 定义。

    // 在 modern BPF 中，我们直接访问 tracepoint 结构体的参数字段：
    // 使用 BPF_CORE_READ 获取 skbaddr 和 devaddr
    BPF_CORE_READ_INTO(&skbaddr, ctx, skbaddr);
    BPF_CORE_READ_INTO(&devaddr, ctx, devaddr);

    struct sk_buff *skb = (struct sk_buff *)skbaddr;
    struct net_device *dev = (struct net_device *)devaddr;

    struct event data = {};

    // 获取进程信息
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // 获取接口名称 (dev->name) - 确保 BPF_CORE_READ_KERNEL_STR 被定义
    bpf_core_read_kernel_str(&data.ifname, sizeof(data.ifname), BPF_CORE_READ(dev, name));

    // 获取数据包长度 (skb->len)
    BPF_CORE_READ_INTO(&data.pkt_len, skb, len);

    // 将数据推送到 perf buffer
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
