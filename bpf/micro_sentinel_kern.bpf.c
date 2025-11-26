// SPDX-License-Identifier: Apache-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include "ms_common.h"

char LICENSE[] SEC("license") = "Apache-2.0";

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
    __u32 key = 0;
    struct ms_token_bucket *tb = bpf_map_lookup_elem(&ms_tb, &key);
    __u64 limit = get_tb_limit();
    __u64 hard_drop = get_hard_drop_ns();
    const struct ms_tb_ctrl *ctrl = bpf_map_lookup_elem(&ms_tb_ctrl_map, &key);

    if (!tb)
        return false;

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

    if (hard_drop && tb->last_emit_tsc && now - tb->last_emit_tsc < hard_drop)
        return false;

    if (tb->tokens == 0)
        return false;

    tb->tokens--;
    tb->last_emit_tsc = now;
    return true;
}

static __always_inline __u64 load_perf_sample_time(const struct bpf_perf_event_data *ctx)
{
    struct perf_sample_data *data = BPF_CORE_READ(ctx, data);
    if (data) {
        __u64 ts = BPF_CORE_READ(data, time);
        if (ts)
            return ts;
    }
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

    if (!l4_off)
        return 0;

    if (tuple->proto == IPPROTO_TCP || tuple->proto == IPPROTO_UDP) {
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
    bpf_probe_read_kernel(tuple->v6.src, sizeof(tuple->v6.src), &ip6h.saddr.s6_addr32);
    bpf_probe_read_kernel(tuple->v6.dst, sizeof(tuple->v6.dst), &ip6h.daddr.s6_addr32);

    if (!l4_off)
        return 0;
    if (tuple->proto == IPPROTO_TCP || tuple->proto == IPPROTO_UDP) {
        __be16 ports[2] = {};
        if (load_header(head, l4_off, &ports, sizeof(ports)))
            return -1;
        tuple->sport = bpf_ntohs(ports[0]);
        tuple->dport = bpf_ntohs(ports[1]);
    }
    return 0;
}

static __always_inline __u64 calc_flow_hash(struct sk_buff *skb, __u8 direction)
{
    __u16 protocol = 0;
    bpf_core_read(&protocol, sizeof(protocol), &skb->protocol);
    bool encap = false;
    bpf_core_read(&encap, sizeof(encap), &skb->encapsulation);

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
        return hash ? hash : fallback_flow_id();
    }

hash_tuple:
    return hash_flow_tuple(&tuple);
}

static __always_inline __u32 calc_gso_segs(struct sk_buff *skb)
{
    __u32 gso_segs = 1;
    bpf_core_read(&gso_segs, sizeof(gso_segs), &skb->gso_segs);
    if (gso_segs == 0)
        gso_segs = 1;
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
            tuple->v6.src[i] = ip6h->saddr.s6_addr32[i];
            tuple->v6.dst[i] = ip6h->daddr.s6_addr32[i];
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

static __always_inline __u32 map_hw_event(const struct bpf_perf_event_data *ctx)
{
    __u64 cookie = bpf_get_attach_cookie(ctx);
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
    __u32 key = 0;
    struct ms_flow_ctx *ctx = bpf_map_lookup_elem(&ms_curr_ctx, &key);
    if (!ctx)
        return;

    __u64 now = bpf_ktime_get_ns();
    __u64 flow_id = calc_flow_hash(skb, direction);
    __u32 gso_segs = calc_gso_segs(skb);
    __u16 ifindex = calc_ifindex(skb);
    __u8 proto = extract_l4_proto(skb);

    ctx->tsc = now;
    ctx->flow_id = flow_id;
    ctx->gso_segs = gso_segs;
    ctx->ingress_ifindex = ifindex;
    ctx->l4_proto = proto;
    ctx->direction = direction;

    ms_hist_push(now, flow_id);
}

static __always_inline void capture_flow_ctx_xdp(struct xdp_md *xdp)
{
    __u32 key = 0;
    struct ms_flow_ctx *ctx = bpf_map_lookup_elem(&ms_curr_ctx, &key);
    if (!ctx)
        return;

    __u64 now = bpf_ktime_get_ns();
    ctx->l4_proto = 0;
    __u64 flow_id = calc_flow_hash_xdp(xdp, ctx);

    ctx->tsc = now;
    ctx->flow_id = flow_id;
    ctx->gso_segs = 1;
    ctx->ingress_ifindex = xdp->ingress_ifindex;
    ctx->direction = 0;

    ms_hist_push(now, flow_id);
}

SEC("fentry/netif_receive_skb")
int BPF_PROG(ms_ctx_inject, struct sk_buff *skb)
{
    capture_flow_ctx(skb, 0);
    return 0;
}

SEC("fentry/dev_queue_xmit")
int BPF_PROG(ms_ctx_inject_tx, struct sk_buff *skb)
{
    capture_flow_ctx(skb, 1);
    return 0;
}

SEC("xdp")
int ms_ctx_inject_xdp(struct xdp_md *ctx)
{
    capture_flow_ctx_xdp(ctx);
    return XDP_PASS;
}

/* -------------------------------------------------------------------------- */
/*                         PMU Event Perf Handler                             */
/* -------------------------------------------------------------------------- */

SEC("perf_event")
int BPF_PROG(ms_pmu_handler, struct bpf_perf_event_data *ctx)
{
    __u64 sample_ts = load_perf_sample_time(ctx);
    if (!allow_sample(sample_ts))
        return 0;

    struct pt_regs *regs = ctx->regs;
    __u64 ip = regs ? PT_REGS_IP(regs) : 0;
    __u64 data_addr = ctx->addr;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid;

    __u32 key = 0;
    const struct ms_flow_ctx *fctx = bpf_map_lookup_elem(&ms_curr_ctx, &key);

    __u64 flow_id = 0;
    __u32 gso = 1;
    __u16 ifindex = 0;
    __u8 proto = 0;
    __u64 ctx_tsc = 0;

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

    struct perf_branch_entry stack[MS_LBR_MAX] = {};
    int lbr_nr = (int)bpf_get_branch_snapshot(&stack, sizeof(stack), 0);
    if (lbr_nr > 0) {
        if (lbr_nr > MS_LBR_MAX)
            lbr_nr = MS_LBR_MAX;
        sample.lbr_nr = lbr_nr;
#pragma unroll
        for (int i = 0; i < MS_LBR_MAX; i++) {
            if (i >= lbr_nr)
                break;
            sample.lbr[i].from = stack[i].from;
            sample.lbr[i].to = stack[i].to;
        }
    }

    bpf_perf_event_output(ctx, &ms_events, BPF_F_CURRENT_CPU, &sample, sizeof(sample));
    return 0;
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
