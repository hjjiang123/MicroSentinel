#pragma once

#include <memory>
#include <mutex>
#include <vector>

#ifdef MS_WITH_LIBBPF
extern "C" {
#include <bpf/libbpf.h>
}
#endif

#include "micro_sentinel/config.h"
#include "micro_sentinel/mode_controller.h"

namespace micro_sentinel {

class BpfOrchestrator {
public:
    explicit BpfOrchestrator(PerfConsumerConfig cfg);
    ~BpfOrchestrator();

    bool Init();
    bool Ready() const;
    int EventsMapFd() const;
    bool SwitchMode(AgentMode mode);
    bool RotateToGroup(size_t index);
    bool UpdateSampleBudget(AgentMode mode,
                            uint64_t sentinel_budget,
                            uint64_t diagnostic_budget,
                            uint64_t hard_drop_ns);
    void UpdateGroupConfig(const std::vector<PmuGroupConfig> *sentinel,
                           const std::vector<PmuGroupConfig> *diagnostic);
    void SetMaxEventsPerGroup(size_t limit);
    void SyncBudgetConfig(uint64_t sentinel_budget,
                          uint64_t diagnostic_budget,
                          uint64_t hard_drop_ns);

    // Restrict flow-context capture to a set of interfaces.
    // Note: the underlying tracepoint program is still globally attached; this
    // config makes it a no-op for non-allowed interfaces.
    bool ConfigureInterfaceFilter(const std::vector<std::string> &ifaces);
    const std::vector<int> &ActiveCpus() const;
    size_t ActiveGroupCount() const;
    size_t CurrentGroupIndex() const;

private:
    PerfConsumerConfig cfg_;
    std::vector<int> cpus_;

#ifdef MS_WITH_LIBBPF
    struct bpf_object *obj_{nullptr};
    struct bpf_program *ctx_prog_{nullptr};
    /* struct bpf_program *ctx_tx_prog_{nullptr}; */
    struct bpf_program *xdp_prog_{nullptr};
    struct bpf_program *pmu_prog_{nullptr};
    struct bpf_link *ctx_link_{nullptr};
    /* struct bpf_link *ctx_tx_link_{nullptr}; */
    std::vector<struct bpf_link *> xdp_links_;
    struct bpf_map *events_map_{nullptr};
    struct bpf_map *cookie_map_{nullptr};
    struct bpf_map *tb_cfg_map_{nullptr};
    struct bpf_map *tb_ctrl_map_{nullptr};
    struct bpf_map *active_evt_map_{nullptr};
    struct bpf_map *if_filter_ctrl_map_{nullptr};
    struct bpf_map *if_filter_map_{nullptr};
    int events_map_fd_{-1};
    int cookie_map_fd_{-1};
    int tb_cfg_map_fd_{-1};
    int tb_ctrl_map_fd_{-1};
    int active_evt_fd_{-1};
    int if_filter_ctrl_fd_{-1};
    int if_filter_fd_{-1};

    struct PerfAttach {
        int fd{-1};
        struct bpf_link *link{nullptr};
        __u64 cookie{0};
    };

    std::vector<PerfAttach> perf_links_;
    __u64 next_cookie_{1};
    __u64 tb_cfg_seq_{0};
    bool ready_{false};
    bool cookie_supported_{false};
    std::vector<PmuGroupConfig> active_groups_;
    size_t active_group_index_{0};
    size_t max_events_per_group_{static_cast<size_t>(-1)};
    mutable std::mutex mu_;

    bool LoadBpfObject();
    bool AttachNetPrograms();
    bool AttachXdpPrograms();
    bool AttachPerfGroupsLocked(const std::vector<PmuGroupConfig> &groups);
    bool AttachPerfGroupsLegacy(const std::vector<PmuGroupConfig> &groups);
    void DetachPerfGroupsLocked();
    bool ConfigureTokenBucket(uint64_t samples_per_sec, uint64_t hard_drop_ns);
    bool ConfigureInterfaceFilterLocked(const std::vector<std::string> &ifaces);
    bool WriteCookie(__u64 cookie, ms_pmu_event_type evt);
    bool WriteActiveEvent(ms_pmu_event_type evt);
#endif
};

inline bool BpfOrchestrator::Ready() const {
#ifdef MS_WITH_LIBBPF
    return ready_;
#else
    return false;
#endif
}

inline int BpfOrchestrator::EventsMapFd() const {
#ifdef MS_WITH_LIBBPF
    return events_map_fd_;
#else
    return -1;
#endif
}

inline const std::vector<int> &BpfOrchestrator::ActiveCpus() const {
    return cpus_;
}

inline size_t BpfOrchestrator::ActiveGroupCount() const {
#ifdef MS_WITH_LIBBPF
    std::lock_guard<std::mutex> lk(mu_);
    return active_groups_.size();
#else
    return 0;
#endif
}

inline size_t BpfOrchestrator::CurrentGroupIndex() const {
#ifdef MS_WITH_LIBBPF
    std::lock_guard<std::mutex> lk(mu_);
    return active_group_index_;
#else
    return 0;
#endif
}

} // namespace micro_sentinel
