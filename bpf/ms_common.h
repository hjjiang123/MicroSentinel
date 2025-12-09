#ifndef MS_COMMON_H
#define MS_COMMON_H

#ifdef __cplusplus
#include <linux/types.h>
#else
#include "vmlinux.h"
#endif

#define MS_HISTORY_LEN 16
#define MS_LBR_MAX     16
#define MS_MAX_EVENT_SLOTS 256

/* Default token bucket parameters (per CPU) */
#define MS_MAX_SAMPLES_PER_SEC 5000ULL
#define MS_TOKEN_HEADROOM      (MS_MAX_SAMPLES_PER_SEC * 2ULL)
#define MS_FLOW_SKID_NS        2000ULL

#ifdef __cplusplus
extern "C" {
#endif

enum ms_pmu_event_type {
    MS_EVT_L3_MISS = 1,
    MS_EVT_BRANCH_MISPRED = 2,
    MS_EVT_ICACHE_STALL = 3,
    MS_EVT_AVX_DOWNCLOCK = 4,
    MS_EVT_STALL_BACKEND = 5,
    MS_EVT_XSNP_HITM = 6,
    MS_EVT_REMOTE_DRAM = 7,
};

struct ms_flow_ctx {
    __u64 tsc;
    __u64 flow_id;
    __u32 gso_segs;
    __u16 ingress_ifindex;
    __u8  l4_proto;
    __u8  direction;
};

struct ms_hist_slot {
    __u64 tsc;
    __u64 flow_id;
};

struct ms_lbr_entry {
    __u64 from;
    __u64 to;
};

struct ms_sample {
    __u64 tsc;
    __u32 cpu;
    __u32 pid;
    __u32 tid;
    __u32 pmu_event;
    __u64 ip;
    __u64 data_addr;
    __u64 flow_id;
    __u32 gso_segs;
    __u16 ingress_ifindex;
    __u16 numa_node;
    __u8  l4_proto;
    __u8  direction;
    __u8  lbr_nr;
    __u8  pad0;
    struct ms_lbr_entry lbr[MS_LBR_MAX];
};

struct ms_token_bucket {
    __u64 last_tsc;
    __u64 tokens;
    __u64 cfg_seq;
    __u64 last_emit_tsc;
};

struct ms_tb_cfg {
    __u64 max_samples_per_sec;
    __u64 hard_drop_threshold;
};

struct ms_tb_ctrl {
    __u64 cfg_seq;
};

struct ms_event_binding {
    __u32 pmu_event;
};

#ifdef __cplusplus
}
#endif

#endif /* MS_COMMON_H */
