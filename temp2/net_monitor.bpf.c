#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "net_monitor.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/*
 * 使用 SEC("tp_btf/...") 挂载到 Raw Tracepoint
 * 函数签名对应你 grep 到的: void (*btf_trace_netif_receive_skb)(void *, struct sk_buff *);
 * BPF_PROG 宏会自动处理第一个 void *ctx 参数，我们只需要关心后面的参数
 */
SEC("tp_btf/netif_receive_skb")
int BPF_PROG(handle_netif_receive_skb, struct sk_buff *skb)
{
    struct event *e;
    
    // 过滤：例如只看长度 > 0 的包
    // 由于启用了 CO-RE，我们可以直接读取 skb->len
    if (skb->len == 0)
        return 0;
    bpf_printk("netif_receive_skb: len=%d\n", skb->len);
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    // 1. 获取包长度 (直接访问，就像写内核模块一样)
    e->len = skb->len;

    // 2. 获取网卡名称
    // skb->dev 是 net_device 结构体指针，name 是其中的 char[]
    // 使用 BPF_CORE_READ 宏进行安全的内存读取
    BPF_CORE_READ_STR_INTO(&e->dev, skb, dev, name);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
