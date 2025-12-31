// SPDX-License-Identifier: Apache-2.0
#ifndef __TARGET_ARCH_x86_64
#define __TARGET_ARCH_x86_64
#endif
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "ms_common.h"

#ifndef NULL
#define NULL 0
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER) __builtin_offsetof(TYPE, MEMBER)
#endif
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif
#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS 0
#endif
#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING 43
#endif
#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT 44
#endif
#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS 60
#endif

char _license[] SEC("license") = "Dual BSD/GPL";

/* -------------------------------------------------------------------------- */
/*                                Map Layout                                  */
/* -------------------------------------------------------------------------- */

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ms_flow_ctx);
} ms_curr_ctx SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MS_HISTORY_LEN);
    __type(key, __u32);
    __type(value, struct ms_hist_slot);
} ms_hist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} ms_hist_head SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 0);
    __type(key, __u32);
    __type(value, __u32);
} ms_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ms_token_bucket);
} ms_tb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ms_tb_cfg);
} ms_tb_cfg_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ms_tb_ctrl);
} ms_tb_ctrl_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MS_MAX_EVENT_SLOTS);
    __type(key, __u64);
    __type(value, struct ms_event_binding);
} ms_event_cookie SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} ms_active_event SEC(".maps");

// Interface filter (optional):
// ms_if_filter_ctrl[0] = 0 => allow all (default)
// ms_if_filter_ctrl[0] = 1 => allow only ifindex present in ms_if_filter_map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} ms_if_filter_ctrl SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);   // ifindex
    __type(value, __u8);  // 1
} ms_if_filter_map SEC(".maps");

struct ms_lbr_tmp {
    struct perf_branch_entry entries[MS_LBR_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ms_lbr_tmp);
} ms_lbr_tmp_map SEC(".maps");

/* -------------------------------------------------------------------------- */
/*                         Helper / Utility Functions                         */
/* -------------------------------------------------------------------------- */

static __always_inline __u64 get_tb_limit(void)
{
    __u32 key = 0;
    const struct ms_tb_cfg *cfg = bpf_map_lookup_elem(&ms_tb_cfg_map, &key);
    if (!cfg || cfg->max_samples_per_sec == 0)
        return MS_MAX_SAMPLES_PER_SEC;
    return cfg->max_samples_per_sec;
}

static __always_inline __u64 get_hard_drop_ns(void)
{
    __u32 key = 0;
    const struct ms_tb_cfg *cfg = bpf_map_lookup_elem(&ms_tb_cfg_map, &key);
    if (!cfg || cfg->hard_drop_threshold == 0)
        return MS_FLOW_SKID_NS * 4ULL;
    return cfg->hard_drop_threshold;
}

static __always_inline bool allow_sample(__u64 now)
{
    // bpf_printk("allow_sample: enter now=%llu\n", now);
    bool allowed = false;
    __u64 remaining = 0;
    __u32 key = 0;
    struct ms_token_bucket *tb = bpf_map_lookup_elem(&ms_tb, &key);
    __u64 limit = get_tb_limit();
    __u64 hard_drop = get_hard_drop_ns();
    const struct ms_tb_ctrl *ctrl = bpf_map_lookup_elem(&ms_tb_ctrl_map, &key);

    if (!tb) {
        bpf_printk("allow_sample: missing token bucket state\n");
        goto out;
    }

    if (ctrl && ctrl->cfg_seq != tb->cfg_seq) {
        tb->cfg_seq = ctrl->cfg_seq;
        tb->tokens = limit;
        tb->last_tsc = now;
        tb->last_emit_tsc = 0;
    }

    if (tb->last_tsc == 0) {
        tb->last_tsc = now;
        tb->tokens = limit;
        tb->cfg_seq = ctrl ? ctrl->cfg_seq : 0;
        tb->last_emit_tsc = 0;
    }

    __u64 elapsed = now - tb->last_tsc;
    if (elapsed) {
        __u64 refill = (elapsed * limit) / 1000000000ULL;
        if (refill) {
            tb->tokens += refill;
            if (tb->tokens > MS_TOKEN_HEADROOM)
                tb->tokens = MS_TOKEN_HEADROOM;
            tb->last_tsc = now;
        }
    }

    if (hard_drop && tb->last_emit_tsc && now - tb->last_emit_tsc < hard_drop) {
        bpf_printk("allow_sample: hard drop window active\n");
        goto out;
    }

    if (tb->tokens == 0) {
        bpf_printk("allow_sample: token bucket empty\n");
        goto out;
    }

    tb->tokens--;
    tb->last_emit_tsc = now;
    allowed = true;

out:
    remaining = tb ? tb->tokens : 0;
    bpf_printk("allow_sample: exit allowed=%u tokens=%llu\n", allowed, remaining);
    return allowed;
}

static __always_inline __u64 load_perf_sample_time(const struct bpf_perf_event_data *ctx)
{
    (void)ctx;
    return bpf_ktime_get_ns();
}

struct ms_ipv6_tuple {
    __u32 src[4];
    __u32 dst[4];
};

struct ms_flow_tuple {
    __u16 sport;
    __u16 dport;
    __u8 proto;
    __u8 dir;
    __u8 is_ipv6;
    __u8 reserved;
    __u32 saddr_v4;
    __u32 daddr_v4;
    struct ms_ipv6_tuple v6;
};

static __always_inline __u64 fallback_flow_id(void);

#define MS_FNV64_OFFSET 1469598103934665603ULL
#define MS_FNV64_PRIME  1099511628211ULL

static __always_inline __u64 fnv64_mix(__u64 hash, __u64 data)
{
    hash ^= data;
    hash *= MS_FNV64_PRIME;
    return hash;
}

static __always_inline __u64 hash_flow_tuple(const struct ms_flow_tuple *tuple)
{
    __u64 h = MS_FNV64_OFFSET;
    h = fnv64_mix(h, tuple->dir);
    h = fnv64_mix(h, tuple->proto);
    h = fnv64_mix(h, ((__u64)tuple->sport << 32) | tuple->dport);
    if (tuple->is_ipv6) {
        h = fnv64_mix(h, ((__u64)tuple->v6.src[0] << 32) | tuple->v6.src[1]);
        h = fnv64_mix(h, ((__u64)tuple->v6.src[2] << 32) | tuple->v6.src[3]);
        h = fnv64_mix(h, ((__u64)tuple->v6.dst[0] << 32) | tuple->v6.dst[1]);
        h = fnv64_mix(h, ((__u64)tuple->v6.dst[2] << 32) | tuple->v6.dst[3]);
    } else {
        h = fnv64_mix(h, ((__u64)tuple->saddr_v4 << 32) | tuple->daddr_v4);
    }
    if (h == 0)
        h = fallback_flow_id();
    bpf_printk("src_addr=%x dst_addr=%x sport=%u dport=%u proto=%u dir=%u hash=%llu\n",
               tuple->saddr_v4, tuple->daddr_v4,
               tuple->sport, tuple->dport,
               tuple->proto, tuple->dir, h);
    return h;
}

static __always_inline __u64 fallback_flow_id(void)
{
    return ((__u64)bpf_get_prandom_u32() << 32) | bpf_get_prandom_u32();
}

static __always_inline bool load_header(const void *base, __u32 offset, void *dst, __u32 len)
{
    if (!base || !offset)
        return true;
    const void *addr = (const void *)((const __u8 *)base + offset);
    return bpf_probe_read_kernel(dst, len, addr);
}

struct ms_ipv6_opt_hdr {
    __u8 nexthdr;
    __u8 hdrlen;
};

struct ms_ipv6_frag_hdr {
    __u8 nexthdr;
    __u8 reserved;
    __be16 frag_off;
    __be32 identification;
};

static __always_inline int compute_ipv6_l4_off(const void *head, __u16 l3_off, struct ipv6hdr *ip6h, __u16 *l4_off, __u8 *l4_proto)
{
    if (!head || !l3_off || !ip6h || !l4_off || !l4_proto)
        return -1;

    __u16 off = l3_off + sizeof(struct ipv6hdr);
    __u8 nexthdr = ip6h->nexthdr;

#pragma unroll
    for (int i = 0; i < 4; i++) {
        if (nexthdr == IPPROTO_HOPOPTS || nexthdr == IPPROTO_ROUTING || nexthdr == IPPROTO_DSTOPTS) {
            struct ms_ipv6_opt_hdr oh = {};
            if (load_header(head, off, &oh, sizeof(oh)))
                return -1;
            nexthdr = oh.nexthdr;
            off += (__u16)(oh.hdrlen + 1) * 8;
            continue;
        }
        if (nexthdr == IPPROTO_FRAGMENT) {
            struct ms_ipv6_frag_hdr fh = {};
            if (load_header(head, off, &fh, sizeof(fh)))
                return -1;
            nexthdr = fh.nexthdr;
            off += 8;
            continue;
        }
        break;
    }

    *l4_off = off;
    *l4_proto = nexthdr;
    return 0;
}

static __always_inline int parse_ipv4_tuple(struct sk_buff *skb, bool inner, struct ms_flow_tuple *tuple)
{
    __u16 l3_off = 0;
    __u16 l4_off = 0;
    void *head = NULL;
    bpf_core_read(&head, sizeof(head), &skb->head);
    if (!head)
        return -1;

    if (inner) {
        bpf_core_read(&l3_off, sizeof(l3_off), &skb->inner_network_header);
        bpf_core_read(&l4_off, sizeof(l4_off), &skb->inner_transport_header);
    } else {
        bpf_core_read(&l3_off, sizeof(l3_off), &skb->network_header);
        bpf_core_read(&l4_off, sizeof(l4_off), &skb->transport_header);
    }
    if (!l3_off)
        return -1;

    struct iphdr iph = {};
    if (load_header(head, l3_off, &iph, sizeof(iph)))
        return -1;

    tuple->proto = iph.protocol;
    tuple->is_ipv6 = 0;
    tuple->saddr_v4 = iph.saddr;
    tuple->daddr_v4 = iph.daddr;

    // At tp_btf/netif_receive_skb, skb->transport_header is often unset.
    // Fall back to computing the L4 offset from the IPv4 IHL.
    if (!l4_off && (tuple->proto == IPPROTO_TCP || tuple->proto == IPPROTO_UDP)) {
        __u32 ihl = iph.ihl;
        if (ihl < 5)
            return -1;
        l4_off = l3_off + (__u16)(ihl * 4);
    }

    if (l4_off && (tuple->proto == IPPROTO_TCP || tuple->proto == IPPROTO_UDP)) {
        __be16 ports[2] = {};
        if (load_header(head, l4_off, &ports, sizeof(ports)))
            return -1;
        tuple->sport = bpf_ntohs(ports[0]);
        tuple->dport = bpf_ntohs(ports[1]);
    }
    return 0;
}

static __always_inline int parse_ipv6_tuple(struct sk_buff *skb, bool inner, struct ms_flow_tuple *tuple)
{
    __u16 l3_off = 0;
    __u16 l4_off = 0;
    void *head = NULL;
    bpf_core_read(&head, sizeof(head), &skb->head);
    if (!head)
        return -1;

    if (inner) {
        bpf_core_read(&l3_off, sizeof(l3_off), &skb->inner_network_header);
        bpf_core_read(&l4_off, sizeof(l4_off), &skb->inner_transport_header);
    } else {
        bpf_core_read(&l3_off, sizeof(l3_off), &skb->network_header);
        bpf_core_read(&l4_off, sizeof(l4_off), &skb->transport_header);
    }
    if (!l3_off)
        return -1;

    struct ipv6hdr ip6h = {};
    if (load_header(head, l3_off, &ip6h, sizeof(ip6h)))
        return -1;

    tuple->proto = ip6h.nexthdr;
    tuple->is_ipv6 = 1;
#pragma unroll
    for (int i = 0; i < 4; i++) {
        tuple->v6.src[i] = ip6h.saddr.in6_u.u6_addr32[i];
        tuple->v6.dst[i] = ip6h.daddr.in6_u.u6_addr32[i];
    }

    // Similar to IPv4: transport_header may be unset at netif_receive_skb.
    // Also attempt to skip a small number of IPv6 extension headers.
    if (!l4_off) {
        __u8 l4_proto = 0;
        __u16 computed = 0;
        if (compute_ipv6_l4_off(head, l3_off, &ip6h, &computed, &l4_proto) == 0) {
            l4_off = computed;
            tuple->proto = l4_proto;
        }
    }

    if (l4_off && (tuple->proto == IPPROTO_TCP || tuple->proto == IPPROTO_UDP)) {
        __be16 ports[2] = {};
        if (load_header(head, l4_off, &ports, sizeof(ports)))
            return -1;
        tuple->sport = bpf_ntohs(ports[0]);
        tuple->dport = bpf_ntohs(ports[1]);
    }
    return 0;
}

/*
 * calc_flow_hash - 计算并返回数据包的流（flow）哈希值
 *
 * 描述：
 *   这是一个在 eBPF 环境下的内联辅助函数，用于基于 skb（struct sk_buff）内容
 *   生成一个 64 位的流标识/哈希值。函数首先安全地读取 skb 的协议字段和内层
 *   网络头偏移（inner_network_header）以判断是否为封装包（encap）。然后填充
 *   一个 ms_flow_tuple 结构并尝试解析 IP 四元组（源/目的地址与端口）来计算哈希。
 *
 * 行为与步骤：
 *   1. 使用 bpf_core_read 读取 skb->protocol 与 skb->inner_network_header。
 *   2. 根据 inner_network_header 是否非零确定是否“封装”包（encap）。
 *   3. 初始化 ms_flow_tuple 并设置方向字段（tuple.dir = direction）。
 *   4. 若检测到封装（encap），再次读取 inner_network_header 并在有内层网络头时：
 *        - 若外层/捕获的协议为 IPv4，调用 parse_ipv4_tuple(skb, true, &tuple) 解析内层四元组；
 *        - 若为 IPv6，调用 parse_ipv6_tuple(skb, true, &tuple) 解析内层四元组；
 *        - 若解析成功（返回 0），跳转到 hash_tuple 生成哈希。
 *   5. 若非封装或内层解析未成功，按照外层协议继续：
 *        - IPv4：调用 parse_ipv4_tuple(skb, false, &tuple) 解析外层；若失败返回 fallback_flow_id()；
 *        - IPv6：调用 parse_ipv6_tuple(skb, false, &tuple) 解析外层；若失败返回 fallback_flow_id()；
 *        - 其他协议：读取 skb->hash 并打印调试信息（bpf_printk 包含 src/dst/proto/encap/hash），
 *          若 skb->hash 非零则返回该值，否则返回 fallback_flow_id()。
 *   6. hash_tuple 标签：当 tuple 被成功填充时，调用 hash_flow_tuple(&tuple) 并返回其结果。
 *
 * 参数：
 *   - struct sk_buff *skb: 指向要计算哈希的数据包缓冲区（SKB）。
 *   - __u8 direction: 表示方向的标志，存储到 tuple.dir 中影响最终哈希/流标识。
 *
 * 返回值：
 *   - 返回 __u64 类型的流哈希/标识；可能来自解析出的五元组（通过 hash_flow_tuple），
 *     或来自 skb->hash（若非 IP 包且该字段非零），或 fallback_flow_id()（解析失败或无 hash 时）。
 *
 * 注意事项/副作用：
 *   - 使用 bpf_core_read 进行内核内存安全读取，适用于 CO-RE（Compile Once — Run Everywhere）。
 *   - 使用 __bpf_constant_htons 比较协议常量（ETH_P_IP/ETH_P_IPV6）。
 *   - 当遇到未知协议分支时会调用 bpf_printk 打印调试信息，可能对性能/日志有影响。
 *   - 该函数依赖 parse_ipv4_tuple、parse_ipv6_tuple、hash_flow_tuple 和 fallback_flow_id 的语义：
 *       * parse_* 返回 0 表示成功并填充 tuple；返回负数表示失败。
 *       * hash_flow_tuple 基于 tuple 生成最终哈希值。
 *       * fallback_flow_id 提供解析失败或无哈希时的后备值。
 *   - 被声明为 __always_inline，返回类型为 __u64，适合在 BPF 程序内联使用以减少栈/调用开销。
 */
static __always_inline __u64 calc_flow_hash(struct sk_buff *skb, __u8 direction)
{
    __u16 protocol = 0;
    bpf_core_read(&protocol, sizeof(protocol), &skb->protocol);
    __u16 inner_nh = 0;
    bpf_core_read(&inner_nh, sizeof(inner_nh), &skb->inner_network_header);
    bool encap = inner_nh != 0;

    struct ms_flow_tuple tuple = {};
    tuple.dir = direction;

    if (encap) {
        __u16 inner_nh = 0;
        bpf_core_read(&inner_nh, sizeof(inner_nh), &skb->inner_network_header);
        if (inner_nh) {
            if (protocol == __bpf_constant_htons(ETH_P_IP)) {
                if (parse_ipv4_tuple(skb, true, &tuple) == 0)
                    goto hash_tuple;
            } else if (protocol == __bpf_constant_htons(ETH_P_IPV6)) {
                if (parse_ipv6_tuple(skb, true, &tuple) == 0)
                    goto hash_tuple;
            }
        }
    }

    if (protocol == __bpf_constant_htons(ETH_P_IP)) {
        if (parse_ipv4_tuple(skb, false, &tuple) < 0)
            return fallback_flow_id();
    } else if (protocol == __bpf_constant_htons(ETH_P_IPV6)) {
        if (parse_ipv6_tuple(skb, false, &tuple) < 0)
            return fallback_flow_id();
    } else {
        __u32 hash = 0;
        bpf_core_read(&hash, sizeof(hash), &skb->hash);
        // bpf_printk("src_ip=%x dst_ip=%x protocol=0x%x encap=%u hash=%u\n",
        //            tuple.saddr_v4, tuple.daddr_v4,
        //            protocol, encap, hash);
        return hash ? hash : fallback_flow_id();
    }

hash_tuple:
    return hash_flow_tuple(&tuple);
}

static __always_inline __u32 calc_gso_segs(struct sk_buff *skb)
{
    __u32 gso_segs = 1;
    unsigned char *head = NULL;
    sk_buff_data_t end_off = 0;

    bpf_core_read(&head, sizeof(head), &skb->head);
    bpf_core_read(&end_off, sizeof(end_off), &skb->end);
    if (!head || end_off == 0)
        return gso_segs;

    unsigned char *shinfo = head + end_off;
    __u16 segs = 0;
    const void *addr = shinfo + offsetof(struct skb_shared_info, gso_segs);
    if (bpf_probe_read_kernel(&segs, sizeof(segs), addr) == 0 && segs)
        gso_segs = segs;
    return gso_segs;
}

static __always_inline void parse_l4_ports(__u8 proto, void *l4, void *data_end, struct ms_flow_tuple *tuple)
{
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        return;
    if (!l4 || data_end <= l4)
        return;
    if ((__u8 *)l4 + sizeof(__be16) * 2 > (__u8 *)data_end)
        return;
    __be16 *ports = l4;
    tuple->sport = bpf_ntohs(ports[0]);
    tuple->dport = bpf_ntohs(ports[1]);
}

static __always_inline int parse_xdp_tuple(struct xdp_md *ctx, struct ms_flow_tuple *tuple)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if (!eth || (void *)(eth + 1) > data_end)
        return -1;
    __u16 h_proto = eth->h_proto;
    void *cursor = eth + 1;

#pragma unroll
    for (int i = 0; i < 2; ++i) {
        if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
            struct vlan_hdr *vh = cursor;
            if (!vh || (void *)(vh + 1) > data_end)
                return -1;
            h_proto = vh->h_vlan_encapsulated_proto;
            cursor = vh + 1;
        }
    }

    if (h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = cursor;
        if (!iph || (void *)(iph + 1) > data_end)
            return -1;
        __u32 ihl = iph->ihl;
        if (ihl < 5)
            return -1;
        void *l4 = (void *)iph + ihl * 4;
        if (l4 > data_end)
            return -1;
        tuple->proto = iph->protocol;
        tuple->is_ipv6 = 0;
        tuple->saddr_v4 = iph->saddr;
        tuple->daddr_v4 = iph->daddr;
        parse_l4_ports(tuple->proto, l4, data_end, tuple);
        return 0;
    }

    if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = cursor;
        if (!ip6h || (void *)(ip6h + 1) > data_end)
            return -1;
        tuple->proto = ip6h->nexthdr;
        tuple->is_ipv6 = 1;
#pragma unroll
        for (int i = 0; i < 4; ++i) {
            tuple->v6.src[i] = ip6h->saddr.in6_u.u6_addr32[i];
            tuple->v6.dst[i] = ip6h->daddr.in6_u.u6_addr32[i];
        }
        void *l4 = ip6h + 1;
        parse_l4_ports(tuple->proto, l4, data_end, tuple);
        return 0;
    }

    return -1;
}

static __always_inline __u64 calc_flow_hash_xdp(struct xdp_md *ctx, struct ms_flow_ctx *flow_ctx)
{
    struct ms_flow_tuple tuple = {};
    tuple.dir = 0;
    if (parse_xdp_tuple(ctx, &tuple) < 0)
        return fallback_flow_id();
    flow_ctx->l4_proto = tuple.proto;
    return hash_flow_tuple(&tuple);
}

static __always_inline __u16 calc_ifindex(struct sk_buff *skb)
{
    struct net_device *dev = NULL;
    bpf_core_read(&dev, sizeof(dev), &skb->dev);
    if (!dev)
        return 0;
    __u32 ifindex = 0;
    bpf_core_read(&ifindex, sizeof(ifindex), &dev->ifindex);
    return ifindex;
}

static __always_inline __u8 extract_l4_proto(struct sk_buff *skb)
{
    __u16 protocol = 0;
    bpf_core_read(&protocol, sizeof(protocol), &skb->protocol);
    if (protocol == __bpf_constant_htons(ETH_P_IP)) {
        void *head = NULL;
        bpf_core_read(&head, sizeof(head), &skb->head);
        __u16 network_header = 0;
        bpf_core_read(&network_header, sizeof(network_header), &skb->network_header);
        if (!network_header || !head)
            return 0;
        struct iphdr iph = {};
        if (load_header(head, network_header, &iph, sizeof(iph)))
            return 0;
        return iph.protocol;
    }
    if (protocol == __bpf_constant_htons(ETH_P_IPV6)) {
        void *head = NULL;
        bpf_core_read(&head, sizeof(head), &skb->head);
        __u16 network_header = 0;
        bpf_core_read(&network_header, sizeof(network_header), &skb->network_header);
        if (!network_header || !head)
            return 0;
        struct ipv6hdr ip6h = {};
        if (load_header(head, network_header, &ip6h, sizeof(ip6h)))
            return 0;
        return ip6h.nexthdr;
    }
    return 0;
}

static __always_inline void ms_hist_push(__u64 tsc, __u64 flow_id)
{
    __u32 key = 0;
    __u32 *head = bpf_map_lookup_elem(&ms_hist_head, &key);
    if (!head)
        return;

    __u32 idx = (*head + 1) % MS_HISTORY_LEN;
    *head = idx;

    struct ms_hist_slot *slot = bpf_map_lookup_elem(&ms_hist, &idx);
    if (!slot)
        return;

    slot->tsc = tsc;
    slot->flow_id = flow_id;
}

static __always_inline __u64 find_flow_in_history(__u64 ts_begin, __u64 ts_end)
{
    __u32 key = 0;
    __u32 *head = bpf_map_lookup_elem(&ms_hist_head, &key);
    if (!head)
        return 0;

    __u64 best_flow = 0;
    __u64 best_delta = (__u64)-1;

#pragma unroll
    for (int i = 0; i < MS_HISTORY_LEN; i++) {
        __u32 idx = (*head + MS_HISTORY_LEN - i) % MS_HISTORY_LEN;
        struct ms_hist_slot *slot = bpf_map_lookup_elem(&ms_hist, &idx);
        if (!slot)
            break;
        __u64 slot_tsc = slot->tsc;
        if (slot_tsc < ts_begin || slot_tsc > ts_end)
            continue;
        __u64 delta = ts_end - slot_tsc;
        if (delta < best_delta) {
            best_delta = delta;
            best_flow = slot->flow_id;
        }
    }

    return best_flow;
}

static __always_inline __u64 ms_get_attach_cookie(const void *ctx)
{
    return bpf_get_attach_cookie((void *)ctx);
}

static __always_inline int ms_get_branch_snapshot(void *entries, __u32 size, __u64 flags)
{
//     bpf_printk("ms_get_branch_snapshot: enter size=%u flags=%llu\n", size, flags);
// #if defined(BPF_FUNC_get_branch_snapshot)
    // bpf_printk("ms_get_branch_snapshot: using bpf_get_branch_snapshot\n");
    return bpf_get_branch_snapshot(entries, size, flags);
// #else
    // return -1;
// #endif
}

static __always_inline __u32 map_hw_event(const struct bpf_perf_event_data *ctx)
{
    __u64 cookie = ms_get_attach_cookie(ctx);
    if (cookie) {
        struct ms_event_binding *binding = bpf_map_lookup_elem(&ms_event_cookie, &cookie);
        if (binding)
            return binding->pmu_event;
    }
    __u32 key = 0;
    __u32 *active = bpf_map_lookup_elem(&ms_active_event, &key);
    if (active)
        return *active;
    return MS_EVT_L3_MISS;
}

/* -------------------------------------------------------------------------- */
/*                        Context Injector (fentry)                           */
/* -------------------------------------------------------------------------- */

static __always_inline void capture_flow_ctx(struct sk_buff *skb, __u8 direction)
{
    // bpf_printk("capture_flow_ctx: enter dir=%u\n", direction);
    
    
    __u64 flow_id = calc_flow_hash(skb, direction);


    __u32 key = 0;
    struct ms_flow_ctx *ctx = bpf_map_lookup_elem(&ms_curr_ctx, &key);
    if (!ctx) {
        // bpf_printk("capture_flow_ctx: ms_curr_ctx lookup failed\n");
        return;
    }

    // Optional per-interface allowlist. If enabled and not allowed, no-op.
    __u32 ctrl_key = 0;
    __u32 *mode = bpf_map_lookup_elem(&ms_if_filter_ctrl, &ctrl_key);
    __u16 ifindex = calc_ifindex(skb);
    if (mode && *mode == 1) {
        __u32 ifk = (__u32)ifindex;
        __u8 *allowed = bpf_map_lookup_elem(&ms_if_filter_map, &ifk);
        if (!allowed)
            return;
    }

    __u64 now = bpf_ktime_get_ns();
    // __u64 flow_id = calc_flow_hash(skb, direction);
    __u32 gso_segs = calc_gso_segs(skb);
    __u8 proto = extract_l4_proto(skb);

    ctx->tsc = now;
    ctx->flow_id = flow_id;
    ctx->gso_segs = gso_segs;
    ctx->ingress_ifindex = ifindex;
    ctx->l4_proto = proto;
    ctx->direction = direction;

    ms_hist_push(now, flow_id);
    // bpf_printk("capture_flow_ctx: exit dir=%u flow=%llu ifindex=%u gso=%u\n",
    //            direction, flow_id, ifindex, gso_segs);
}

static __always_inline void capture_flow_ctx_xdp(struct xdp_md *xdp)
{
    // bpf_printk("capture_flow_ctx_xdp: enter ifindex=%u\n", xdp->ingress_ifindex);
    __u32 key = 0;
    struct ms_flow_ctx *ctx = bpf_map_lookup_elem(&ms_curr_ctx, &key);
    if (!ctx) {
        bpf_printk("capture_flow_ctx_xdp: ms_curr_ctx lookup failed\n");
        return;
    }

    __u64 now = bpf_ktime_get_ns();
    ctx->l4_proto = 0;
    __u64 flow_id = calc_flow_hash_xdp(xdp, ctx);

    ctx->tsc = now;
    ctx->flow_id = flow_id;
    ctx->gso_segs = 1;
    ctx->ingress_ifindex = xdp->ingress_ifindex;
    ctx->direction = 0;

    ms_hist_push(now, flow_id);
    // bpf_printk("capture_flow_ctx_xdp: exit flow=%llu ifindex=%u\n", flow_id, xdp->ingress_ifindex);
}

SEC("tp_btf/netif_receive_skb")
int BPF_PROG(ms_ctx_inject, struct sk_buff *skb)
{
    // // 安全检查：确保 skb 非空且数据可读
    // if (!skb)
    //     return 0;

    // // 读取 skb->head, data, len 等关键字段（使用 CO-RE 安全读取）
    // unsigned char *head = (unsigned char *)BPF_CORE_READ(skb, head);
    // unsigned char *data = (unsigned char *)BPF_CORE_READ(skb, data);
    // unsigned int len = BPF_CORE_READ(skb, len);

    // // 计算数据起始偏移
    // unsigned int mac_offset = data - head;
    // if (mac_offset >= len || len < sizeof(struct ethhdr))
    //     return 0;

    // // 指向以太网帧开始
    // struct ethhdr *eth = (struct ethhdr *)(head + mac_offset);
    // if ((void *)eth + sizeof(*eth) > head + len)
    //     return 0;

    // // 只处理 IPv4
    // if (eth->h_proto != bpf_htons(ETH_P_IP))
    //     return 0;

    // // IP 头位置：紧跟在 ethhdr 之后
    // struct iphdr *ip = (struct iphdr *)(eth + 1);
    // if ((void *)ip + sizeof(*ip) > head + len)
    //     return 0;

    // // 检查 IP 头长度和总长度
    // __u8 ip_hdr_len = ip->ihl * 4;
    // if (ip_hdr_len < sizeof(*ip) || ip_hdr_len > len)
    //     return 0;

    // // 只处理 TCP 和 UDP
    // if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
    //     return 0;

    // // 提取传输层头部（TCP/UDP）
    // struct tcphdr *tcp = (struct tcphdr *)((unsigned char *)ip + ip_hdr_len);
    // struct udphdr *udp = (struct udphdr *)((unsigned char *)ip + ip_hdr_len);

    // // 检查 TCP/UDP 头是否在 skb 范围内
    // if (ip->protocol == IPPROTO_TCP) {
    //     if ((void *)tcp + sizeof(*tcp) > head + len)
    //         return 0;
    // } else {
    //     if ((void *)udp + sizeof(*udp) > head + len)
    //         return 0;
    // }

    // // 提取五元组
    // __u32 src_ip = ip->saddr;
    // __u32 dst_ip = ip->daddr;
    // __u16 src_port = 0, dst_port = 0;

    // if (ip->protocol == IPPROTO_TCP) {
    //     src_port = bpf_ntohs(tcp->source);
    //     dst_port = bpf_ntohs(tcp->dest);
    // } else {
    //     src_port = bpf_ntohs(udp->source);
    //     dst_port = bpf_ntohs(udp->dest);
    // }

    // // 格式化输出字符串
    // bpf_printk("ms_ctx_inject: src_ip=%x dst_ip=%x src_port=%u dst_port=%u proto=%u\n",
    //            src_ip, dst_ip, src_port, dst_port, ip->protocol);
    // bpf_printk("ms_ctx_inject: enter skb=%p\n", skb);
    capture_flow_ctx(skb, 0);
    // bpf_printk("ms_ctx_inject: exit\n");
    return 0;
}

/* SEC("fentry/dev_queue_xmit")
int ms_ctx_inject_tx(struct sk_buff *skb)
{
    capture_flow_ctx(skb, 1);
    return 0;
} */

SEC("xdp")
int ms_ctx_inject_xdp(struct xdp_md *ctx)
{
    // bpf_printk("ms_ctx_inject_xdp: enter ingress_ifindex=%u\n", ctx->ingress_ifindex);
    capture_flow_ctx_xdp(ctx);
    // bpf_printk("ms_ctx_inject_xdp: exit\n");
    return XDP_PASS;
}

/* -------------------------------------------------------------------------- */
/*                         PMU Event Perf Handler                             */
/* -------------------------------------------------------------------------- */

SEC("perf_event")
int ms_pmu_handler(struct bpf_perf_event_data *ctx)
{
    // bpf_printk("ms_pmu_handler: enter\n");
    bool sample_emitted = false;
    int rc = 0;
    __u64 flow_id = 0;
    __u32 gso = 1;
    __u16 ifindex = 0;
    __u8 proto = 0;
    __u64 ctx_tsc = 0;

    struct pt_regs *regs = NULL;
    __u64 ip = 0;
    __u64 data_addr = 0;
    __u64 pid_tgid = 0;
    __u32 pid = 0;
    __u32 tid = 0;
    const struct ms_flow_ctx *fctx = NULL;
    __u32 key = 0;

    __u64 sample_ts = load_perf_sample_time(ctx);
    if (!allow_sample(sample_ts))
        goto out;

    regs = &ctx->regs;
    ip = PT_REGS_IP(regs);
    data_addr = ctx->addr;
    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;
    tid = pid_tgid;

    fctx = bpf_map_lookup_elem(&ms_curr_ctx, &key);

    if (fctx) {
        flow_id = fctx->flow_id;
        gso = fctx->gso_segs ? fctx->gso_segs : 1;
        ifindex = fctx->ingress_ifindex;
        proto = fctx->l4_proto;
        ctx_tsc = fctx->tsc;
    }

    if (!flow_id || (sample_ts > ctx_tsc && sample_ts - ctx_tsc > MS_FLOW_SKID_NS)) {
        __u64 best = find_flow_in_history(sample_ts - MS_FLOW_SKID_NS, sample_ts + MS_FLOW_SKID_NS);
        if (best)
            flow_id = best;
    }

    struct ms_sample sample = {};
    sample.tsc = sample_ts;
    sample.cpu = bpf_get_smp_processor_id();
    sample.pid = pid;
    sample.tid = tid;
    sample.pmu_event = map_hw_event(ctx);
    sample.ip = ip;
    sample.data_addr = data_addr;
    sample.flow_id = flow_id;
    sample.gso_segs = gso;                  
    sample.ingress_ifindex = ifindex;
    sample.numa_node = bpf_get_numa_node_id();
    sample.l4_proto = proto;
    sample.direction = fctx ? fctx->direction : 0;
    sample.lbr_nr = 0;

    struct ms_lbr_tmp *lbr_tmp = bpf_map_lookup_elem(&ms_lbr_tmp_map, &key);
    if (lbr_tmp) {
        int lbr_nr = ms_get_branch_snapshot(lbr_tmp->entries, sizeof(lbr_tmp->entries), 0);
        if (lbr_nr > 0) {
            if (lbr_nr > MS_LBR_MAX)
                lbr_nr = MS_LBR_MAX;
            sample.lbr_nr = lbr_nr;

#define MS_COPY_LBR(_i)                                                                 \
    do {                                                                                \
        if (lbr_nr > (_i)) {                                                            \
            sample.lbr[_i].from = lbr_tmp->entries[_i].from;                            \
            sample.lbr[_i].to = lbr_tmp->entries[_i].to;                                \
        }                                                                               \
    } while (0)

            MS_COPY_LBR(0);
            MS_COPY_LBR(1);
            MS_COPY_LBR(2);
            MS_COPY_LBR(3);
            MS_COPY_LBR(4);
            MS_COPY_LBR(5);
            MS_COPY_LBR(6);
            MS_COPY_LBR(7);
            MS_COPY_LBR(8);
            MS_COPY_LBR(9);
            MS_COPY_LBR(10);
            MS_COPY_LBR(11);
            MS_COPY_LBR(12);
            MS_COPY_LBR(13);
            MS_COPY_LBR(14);
            MS_COPY_LBR(15);

#undef MS_COPY_LBR
        }
    }
    // bpf_printk("sizeof ms_sample=%u lbr_nr=%u\n", sizeof(sample), sample.lbr_nr);
    if (bpf_perf_event_output(ctx, &ms_events, BPF_F_CURRENT_CPU, &sample, sizeof(sample)) < 0) {
        bpf_printk("ms_pmu_handler: bpf_perf_event_output failed\n");
        goto out;
    }

    sample_emitted = true;
    // bpf_printk("ms_pmu_handler: sample output success flow_id=%llu pid=%u tid=%u ip=0x%llx\n", flow_id, pid, tid, ip);

out:
    // bpf_printk("ms_pmu_handler: exit emitted=%u flow_id=%llu\n", sample_emitted, flow_id);
    return rc;
}

/* -------------------------------------------------------------------------- */
/*                       Safety Controller (Command)                          */
/* -------------------------------------------------------------------------- */

SEC("kprobe/__bpf_ms_update_tb")
int BPF_KPROBE(ms_update_tb)
{
    __u32 key = 0;
    struct ms_token_bucket *tb = bpf_map_lookup_elem(&ms_tb, &key);
    if (!tb)
        return 0;
    tb->tokens = get_tb_limit();
    tb->last_tsc = bpf_ktime_get_ns();
    tb->last_emit_tsc = 0;
    return 0;
}
