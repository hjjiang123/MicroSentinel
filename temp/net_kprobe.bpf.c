#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义传给用户态的数据结构
struct event_t {
    u32 pid;
    u32 len;
    char comm[16];   // 进程名
    char ifname[16]; // 网卡名
};

// 定义 RingBuffer 用于向用户态发送数据
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB
} rb SEC(".maps");

// Hook 核心接收函数
// int __netif_receive_skb_core(struct sk_buff **pskb, bool pfmemalloc, struct packet_type **ppt_prev)
// 注意：内核版本不同参数可能略有不同，但第一个参数通常都是 skb 相关
SEC("tracepoint/net/netif_receive_skb")
int BPF_KPROBE(handle_netif_core, int pid, char *comm, void *skb) {
    // struct sk_buff *skb = *pskb; // 获取 skb 指针
    struct event_t *e;
    struct net_device *dev;

    // 在 RingBuffer 中申请空间
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    // 1. 获取基本信息
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 2. 读取 SKB 长度 (使用 CO-RE 读取，兼容性更强)
    e->len = BPF_CORE_READ(skb, len);

    // 3. 读取网卡名称
    // 路径: skb -> dev -> name
    dev = BPF_CORE_READ(skb, dev);
    // 从内核内存中读取字符串到 e->ifname
    bpf_probe_read_kernel_str(&e->ifname, sizeof(e->ifname), BPF_CORE_READ(dev, name));

    // 提交数据
    bpf_ringbuf_submit(e, 0);
    return 0;
}
