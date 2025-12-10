#include "micro_sentinel/bpf_orchestrator.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <net/if.h>

#include "micro_sentinel/scope_logger.h"
#include "ms_common.h"

#ifdef MS_WITH_LIBBPF
extern "C" {
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>
}
#endif

#if defined(LIBBPF_STRICT_ALL)
#define MS_LIBBPF_HAS_STRICT_MODE 1
#else
#define MS_LIBBPF_HAS_STRICT_MODE 0
#endif

#if defined(LIBBPF_OPTS)
#define MS_LIBBPF_HAS_PERF_OPTS 1
#else
#define MS_LIBBPF_HAS_PERF_OPTS 0
#endif

namespace {

std::vector<int> ParseCpuList(const std::vector<int> &explicit_list) {
    if (!explicit_list.empty())
        return explicit_list;

    std::ifstream in("/sys/devices/system/cpu/online");
    std::string line;
    if (!std::getline(in, line) || line.empty())
        return {0};

    std::vector<int> cpus;
    size_t pos = 0;
    while (pos < line.size()) {
        size_t comma = line.find(',', pos);
        std::string token = line.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
        size_t dash = token.find('-');
        if (dash == std::string::npos) {
            cpus.push_back(std::stoi(token));
        } else {
            int start = std::stoi(token.substr(0, dash));
            int end = std::stoi(token.substr(dash + 1));
            for (int cpu = start; cpu <= end; ++cpu)
                cpus.push_back(cpu);
        }
        if (comma == std::string::npos)
            break;
        pos = comma + 1;
    }
    std::sort(cpus.begin(), cpus.end());
    cpus.erase(std::unique(cpus.begin(), cpus.end()), cpus.end());
    if (cpus.empty())
        cpus.push_back(0);
    return cpus;
}

} // namespace

namespace micro_sentinel {

BpfOrchestrator::BpfOrchestrator(PerfConsumerConfig cfg) : cfg_(std::move(cfg)) {
    cpus_ = ParseCpuList(cfg_.cpus);
#ifdef MS_WITH_LIBBPF
    cookie_supported_ = MS_LIBBPF_HAS_PERF_OPTS;
#endif
}

BpfOrchestrator::~BpfOrchestrator() {
#ifdef MS_WITH_LIBBPF
    std::lock_guard<std::mutex> lk(mu_);
    DetachPerfGroupsLocked();
    for (auto *link : xdp_links_) {
        if (link)
            bpf_link__destroy(link);
    }
    xdp_links_.clear();
    if (ctx_link_)
        bpf_link__destroy(ctx_link_);
    /* if (ctx_tx_link_)
        bpf_link__destroy(ctx_tx_link_); */
    if (obj_)
        bpf_object__close(obj_);
#endif
}

bool BpfOrchestrator::Init() {
#ifdef MS_WITH_LIBBPF
    if (cfg_.mock_mode) {
        std::cerr << "[BpfOrchestrator] Perf consumer configured for mock mode; skipping BPF init" << std::endl;
        return false;
    }

    if (!LoadBpfObject()) {
        std::cerr << "[BpfOrchestrator] LoadBpfObject failed" << std::endl;
        return false;
    }
    if (!AttachNetPrograms()) {
        std::cerr << "[BpfOrchestrator] AttachNetPrograms failed" << std::endl;
        return false;
    }
    if (!ConfigureTokenBucket(cfg_.sentinel_sample_budget, cfg_.hard_drop_ns)) {
        std::cerr << "[BpfOrchestrator] ConfigureTokenBucket failed" << std::endl;
        return false;
    }
    if (!cookie_supported_)
        std::cerr << "MicroSentinel running in legacy PMU mode; upgrade libbpf for per-event attribution" << std::endl;
    ready_ = true;
    return true;
#else
    (void)cfg_;
    return false;
#endif
}

#ifdef MS_WITH_LIBBPF

static int PerfEventOpen(perf_event_attr *attr, int pid, int cpu, int group_fd, unsigned long flags) {
    // std::cout << "[PerfCmd] perf_event_open pid=" << pid
            //   << " cpu=" << cpu
            //   << " type=" << attr->type
            //   << " config=0x" << std::hex << attr->config << std::dec
            //   << " period=" << attr->sample_period
            //   << " precise=" << static_cast<int>(attr->precise_ip)
            //   << " flags=0x" << std::hex << flags << std::dec
            //   << std::endl;
    return static_cast<int>(syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags));
}

bool BpfOrchestrator::LoadBpfObject() {
#if MS_LIBBPF_HAS_STRICT_MODE
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
#endif
    obj_ = bpf_object__open_file(cfg_.bpf_object_path.c_str(), nullptr);
    std::cout << "Loading BPF object from: " << cfg_.bpf_object_path << std::endl;
    if (!obj_) {
        std::cerr << "Failed to open BPF object: " << cfg_.bpf_object_path << std::endl;
        return false;
    }
    std::cout << "Loading BPF object from: " << cfg_.bpf_object_path << std::endl;

    if (int err = bpf_object__load(obj_); err) {
        std::cerr << "Failed to load BPF object: " << strerror(-err) << std::endl;
        return false;
    }

    ctx_prog_ = bpf_object__find_program_by_name(obj_, "ms_ctx_inject");
    /* ctx_tx_prog_ = bpf_object__find_program_by_name(obj_, "ms_ctx_inject_tx"); */
    xdp_prog_ = bpf_object__find_program_by_name(obj_, "ms_ctx_inject_xdp");
    pmu_prog_ = bpf_object__find_program_by_name(obj_, "ms_pmu_handler");
    events_map_ = bpf_object__find_map_by_name(obj_, "ms_events");
    cookie_map_ = bpf_object__find_map_by_name(obj_, "ms_event_cookie");
    tb_cfg_map_ = bpf_object__find_map_by_name(obj_, "ms_tb_cfg_map");
    tb_ctrl_map_ = bpf_object__find_map_by_name(obj_, "ms_tb_ctrl_map");
    active_evt_map_ = bpf_object__find_map_by_name(obj_, "ms_active_event");

    if (!ctx_prog_ || /*!ctx_tx_prog_ ||*/ !pmu_prog_ || !events_map_ || !tb_cfg_map_ || !tb_ctrl_map_ || !active_evt_map_) {
        std::cerr << "Missing symbols in BPF object" << std::endl;
        std::cerr << "ctx_prog_: " << (ctx_prog_ ? "found" : "missing") << std::endl;
        /* std::cerr << "ctx_tx_prog_: " << (ctx_tx_prog_ ? "found" : "missing") << std::endl; */
        std::cerr << "pmu_prog_: " << (pmu_prog_ ? "found" : "missing") << std::endl;
        std::cerr << "events_map_: " << (events_map_ ? "found" : "missing") << std::endl;
        std::cerr << "tb_cfg_map_: " << (tb_cfg_map_ ? "found" : "missing") << std::endl;
        std::cerr << "tb_ctrl_map_: " << (tb_ctrl_map_ ? "found" : "missing") << std::endl;
        std::cerr << "active_evt_map_: " << (active_evt_map_ ? "found" : "missing") << std::endl;
        return false;
    }

    events_map_fd_ = bpf_map__fd(events_map_);
    cookie_map_fd_ = cookie_map_ ? bpf_map__fd(cookie_map_) : -1;
    tb_cfg_map_fd_ = bpf_map__fd(tb_cfg_map_);
    tb_ctrl_map_fd_ = bpf_map__fd(tb_ctrl_map_);
    active_evt_fd_ = bpf_map__fd(active_evt_map_);
    if (cookie_map_fd_ < 0){
        cookie_supported_ = false;
        std::cout<< "MicroSentinel running in legacy PMU mode; upgrade libbpf for per-event attribution" <<std::endl;
    }
    return events_map_fd_ >= 0 && tb_cfg_map_fd_ >= 0 && tb_ctrl_map_fd_ >= 0 && active_evt_fd_ >= 0;
}

bool BpfOrchestrator::AttachNetPrograms() {
    if (!ctx_prog_ /*|| !ctx_tx_prog_*/) {
        std::cerr << "[BpfOrchestrator] Context injector program missing" << std::endl;
        return false;
    }
    ctx_link_ = bpf_program__attach_trace(ctx_prog_);
    if (!ctx_link_) {
        std::cerr << "Failed to attach ms_ctx_inject" << std::endl;
        return false;
    }
    if (!cfg_.xdp_ifaces.empty()) {
        if (!xdp_prog_) {
            std::cerr << "XDP context injector missing from BPF object" << std::endl;
            return false;
        }
        if (!AttachXdpPrograms()) {
            for (auto *link : xdp_links_) {
                if (link)
                    bpf_link__destroy(link);
            }
            xdp_links_.clear();
            return false;
        }
    }
    return true;
}

bool BpfOrchestrator::ConfigureTokenBucket(uint64_t samples_per_sec, uint64_t hard_drop_ns) {
    if (tb_cfg_map_fd_ < 0 || tb_ctrl_map_fd_ < 0) {
        std::cerr << "[BpfOrchestrator] Token bucket maps unavailable" << std::endl;
        return false;
    }
    struct ms_tb_cfg cfg{};
    cfg.max_samples_per_sec = samples_per_sec;
    cfg.hard_drop_threshold = hard_drop_ns ? hard_drop_ns : MS_FLOW_SKID_NS * 4ULL;
    __u32 key = 0;
    if (bpf_map_update_elem(tb_cfg_map_fd_, &key, &cfg, BPF_ANY) < 0) {
        std::perror("bpf_map_update_elem(tb_cfg_map)");
        return false;
    }
    struct ms_tb_ctrl ctrl{};
    ctrl.cfg_seq = ++tb_cfg_seq_;
    if (bpf_map_update_elem(tb_ctrl_map_fd_, &key, &ctrl, BPF_ANY) < 0) {
        std::perror("bpf_map_update_elem(tb_ctrl_map)");
        return false;
    }
    return true;
}

bool BpfOrchestrator::WriteCookie(__u64 cookie, ms_pmu_event_type evt) {
    if (!cookie_supported_ || cookie_map_fd_ < 0) {
        std::cerr << "[BpfOrchestrator] Cookie map unavailable while binding event " << evt << std::endl;
        return false;
    }
    struct ms_event_binding binding{static_cast<__u32>(evt)};
    if (bpf_map_update_elem(cookie_map_fd_, &cookie, &binding, BPF_ANY) < 0) {
        std::perror("bpf_map_update_elem(cookie)");
        std::cerr << "[BpfOrchestrator] Failed to write cookie mapping for event " << evt << std::endl;
        return false;
    }
    return true;
}

bool BpfOrchestrator::WriteActiveEvent(ms_pmu_event_type evt) {
    if (active_evt_fd_ < 0) {
        std::cerr << "[BpfOrchestrator] Active event map unavailable" << std::endl;
        return false;
    }
    __u32 key = 0;
    __u32 value = static_cast<__u32>(evt);
    if (bpf_map_update_elem(active_evt_fd_, &key, &value, BPF_ANY) < 0) {
        std::perror("bpf_map_update_elem(active_evt)");
        std::cerr << "[BpfOrchestrator] Failed to publish active event " << evt << std::endl;
        return false;
    }
    return true;
}

void BpfOrchestrator::DetachPerfGroupsLocked() {
    for (auto &attach : perf_links_) {
        if (attach.link)
            bpf_link__destroy(attach.link);
        if (attach.fd >= 0)
            close(attach.fd);
        if (cookie_map_fd_ >= 0 && attach.cookie != 0)
            bpf_map_delete_elem(cookie_map_fd_, &attach.cookie);
    }
    perf_links_.clear();
}

bool BpfOrchestrator::AttachXdpPrograms() {
    if (!xdp_prog_)
        return cfg_.xdp_ifaces.empty();
    for (const auto &iface : cfg_.xdp_ifaces) {
        if (iface.empty())
            continue;
        unsigned int ifindex = if_nametoindex(iface.c_str());
        if (ifindex == 0) {
            std::cerr << "Unknown XDP interface: " << iface << std::endl;
            continue;
        }
        auto *link = bpf_program__attach_xdp(xdp_prog_, ifindex);
        if (libbpf_get_error(link)) {
            std::cerr << "Failed to attach XDP program on " << iface << std::endl;
            continue;
        }
        xdp_links_.push_back(link);
    }
    if (!cfg_.xdp_ifaces.empty() && xdp_links_.empty()) {
        std::cerr << "Unable to attach XDP program to any requested interface" << std::endl;
        return false;
    }
    return true;
}

bool BpfOrchestrator::AttachPerfGroupsLocked(const std::vector<PmuGroupConfig> &groups) {
    // MS_SCOPE_LOG("Bpf_Orchestrator::AttachPerfGroupsLocked");
    DetachPerfGroupsLocked();
    if (!pmu_prog_) {
        std::cerr << "[BpfOrchestrator] PMU handler program missing" << std::endl;
        return false;
    }

#if !MS_LIBBPF_HAS_PERF_OPTS
    // MS_SCOPE_LOG("Bpf_Orchestrator::AttachPerfGroupsLocked::AttachPerfGroupsLegacy");
    return AttachPerfGroupsLegacy(groups);
#else
    // MS_SCOPE_LOG("Bpf_Orchestrator::AttachPerfGroupsLocked::AttachPerfGroupsLocked");
    if (!cookie_supported_)
        return AttachPerfGroupsLegacy(groups);
    // MS_SCOPE_LOG("Bpf_Orchestrator::AttachPerfGroupsLocked::AttachPerfGroupsLocked::MainLoop");
    __u64 cookie = next_cookie_;
    size_t limit = max_events_per_group_;
    bool limit_events = (limit != static_cast<size_t>(-1));
    // std::cout << "[BpfOrchestrator] Attaching PMU groups with "
            //   << (cookie_supported_ ? "cookie support" : "legacy mode") << std::endl;
    // std::cout << "[BpfOrchestrator] max_events_per_group = "
            //   << (limit_events ? std::to_string(limit) : "unlimited") << std::endl;
    for (const auto &group : groups) {
        size_t events_attached = 0;
        for (const auto &evt : group.events) {
            if (limit_events && events_attached >= limit)
                break;
            for (int cpu : cpus_) {
                perf_event_attr attr{};
                attr.type = evt.type;
                attr.size = sizeof(attr);
                attr.config = evt.config;
                attr.sample_period = evt.sample_period;
                attr.disabled = 0;
                attr.exclude_hv = 1;
                attr.exclude_idle = 1;
                attr.precise_ip = evt.precise ? 2 : 0;
                attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ADDR;
                attr.sample_type |= PERF_SAMPLE_BRANCH_STACK;
                attr.branch_sample_type = PERF_SAMPLE_BRANCH_USER | PERF_SAMPLE_BRANCH_CALL_STACK;

                int fd = PerfEventOpen(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
                if (fd < 0) {
                    std::perror("perf_event_open");
                    continue;
                }

                bpf_perf_event_opts opts{};
                opts.sz = sizeof(opts);
                opts.bpf_cookie = cookie;
                // MS_SCOPE_LOG("Bpf_Orchestrator::AttachPerfGroupsLocked::AttachPerfGroupsLocked::MainLoop::AttachPerfEventOpts");
                auto *link = bpf_program__attach_perf_event_opts(pmu_prog_, fd, &opts);
                long err = libbpf_get_error(link);
                if (err) {
                    if (err == -EOPNOTSUPP) {
                        std::cerr << "Perf-event cookies unsupported by kernel; falling back to legacy attribution" << std::endl;
                        cookie_supported_ = false;
                        close(fd);
                        DetachPerfGroupsLocked();
                        return AttachPerfGroupsLegacy(groups);
                    }

                    std::cerr << "Failed to attach perf event for CPU " << cpu << std::endl;
                    close(fd);
                    continue;
                }

                if (!WriteCookie(cookie, evt.logical)) {
                    bpf_link__destroy(link);
                    close(fd);
                    continue;
                }
                // std::cout<<"event type "
                //           <<static_cast<int>(evt.logical)
                //           <<" cookie "
                //           <<cookie
                //           <<" cpu "
                //           <<cpu
                //           <<std::endl;
                perf_links_.push_back(PerfAttach{fd, link, cookie});
                ++cookie;
            }
            events_attached++;
        }
    }

    next_cookie_ = cookie;
    return !perf_links_.empty();
#endif
}

bool BpfOrchestrator::AttachPerfGroupsLegacy(const std::vector<PmuGroupConfig> &groups)
{
    if (groups.empty() || groups.front().events.empty()) {
        std::cerr << "No PMU events configured for legacy perf mode" << std::endl;
        return false;
    }

    const auto &evt = groups.front().events.front();
    if (!WriteActiveEvent(evt.logical))
        return false;

    for (int cpu : cpus_) {
        perf_event_attr attr{};
        attr.type = evt.type;
        attr.size = sizeof(attr);
        attr.config = evt.config;
        attr.sample_period = evt.sample_period;
        attr.disabled = 0;
        attr.exclude_hv = 1;
        attr.exclude_idle = 1;
        attr.precise_ip = evt.precise ? 2 : 0;
        attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ADDR;
        attr.sample_type |= PERF_SAMPLE_BRANCH_STACK;
        attr.branch_sample_type = PERF_SAMPLE_BRANCH_USER | PERF_SAMPLE_BRANCH_CALL_STACK;

        int fd = PerfEventOpen(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
        if (fd < 0) {
            std::perror("perf_event_open");
            continue;
        }

        auto *link = bpf_program__attach_perf_event(pmu_prog_, fd);
        if (libbpf_get_error(link)) {
            std::cerr << "Failed to attach perf event for CPU " << cpu << std::endl;
            close(fd);
            continue;
        }

        perf_links_.push_back(PerfAttach{fd, link, 0});
    }

    if (perf_links_.empty()) {
        std::cerr << "[BpfOrchestrator] Legacy perf attachment failed on all CPUs; consider upgrading libbpf" << std::endl;
        return false;
    }

    return true;
}

bool BpfOrchestrator::SwitchMode(AgentMode mode) {
    const auto &groups = (mode == AgentMode::Sentinel) ? cfg_.sentinel_groups : cfg_.diagnostic_groups;
    if (groups.empty()) {
        std::cerr << "[BpfOrchestrator] No PMU groups configured for mode " << (mode == AgentMode::Sentinel ? "Sentinel" : "Diagnostic") << std::endl;
        return false;
    }
    uint64_t budget = (mode == AgentMode::Sentinel) ? cfg_.sentinel_sample_budget : cfg_.diagnostic_sample_budget;
    if (!ConfigureTokenBucket(budget, cfg_.hard_drop_ns)) {
        std::cerr << "[BpfOrchestrator] Failed to configure token bucket for mode switch" << std::endl;
        return false;
    }
    std::lock_guard<std::mutex> lk(mu_);
    active_groups_ = groups;
    active_group_index_ = 0;
    std::vector<PmuGroupConfig> to_attach;
    to_attach.push_back(active_groups_.front());
    bool ok = AttachPerfGroupsLocked(to_attach);
    if (!ok)
        std::cerr << "[BpfOrchestrator] AttachPerfGroupsLocked failed during mode switch" << std::endl;
        active_groups_.clear();
    return ok;
}

bool BpfOrchestrator::RotateToGroup(size_t index) {
#ifdef MS_WITH_LIBBPF
    std::lock_guard<std::mutex> lk(mu_);
    if (!ready_ || active_groups_.empty() || index >= active_groups_.size()) {
        std::cerr << "[BpfOrchestrator] RotateToGroup invalid state (ready=" << ready_ << ", groups=" << active_groups_.size()
                  << ", requested=" << index << ")" << std::endl;
        return false;
    }
    std::vector<PmuGroupConfig> to_attach;
    to_attach.push_back(active_groups_[index]);
    if (!AttachPerfGroupsLocked(to_attach)) {
        std::cerr << "[BpfOrchestrator] Failed to attach PMU group index " << index << std::endl;
        return false;
    }
    active_group_index_ = index;
    return true;
#else
    (void)index;
    return false;
#endif
}

bool BpfOrchestrator::UpdateSampleBudget(AgentMode mode,
                                         uint64_t sentinel_budget,
                                         uint64_t diagnostic_budget,
                                         uint64_t hard_drop_ns) {
#ifdef MS_WITH_LIBBPF
    uint64_t active_budget = (mode == AgentMode::Sentinel) ? sentinel_budget : diagnostic_budget;
    if (!ready_ || active_budget == 0) {
        std::cerr << "[BpfOrchestrator] UpdateSampleBudget rejected (ready=" << ready_ << ", active_budget=" << active_budget << ")" << std::endl;
        return false;
    }
    cfg_.sentinel_sample_budget = sentinel_budget;
    cfg_.diagnostic_sample_budget = diagnostic_budget;
    cfg_.hard_drop_ns = hard_drop_ns;
    return ConfigureTokenBucket(active_budget, hard_drop_ns);
#else
    (void)mode;
    (void)sentinel_budget;
    (void)diagnostic_budget;
    (void)hard_drop_ns;
    return false;
#endif
}

void BpfOrchestrator::UpdateGroupConfig(const std::vector<PmuGroupConfig> *sentinel,
                                        const std::vector<PmuGroupConfig> *diagnostic) {
#ifdef MS_WITH_LIBBPF
    std::lock_guard<std::mutex> lk(mu_);
    if (sentinel && !sentinel->empty())
        cfg_.sentinel_groups = *sentinel;
    if (diagnostic && !diagnostic->empty())
        cfg_.diagnostic_groups = *diagnostic;
#else
    (void)sentinel;
    (void)diagnostic;
#endif
}

void BpfOrchestrator::SetMaxEventsPerGroup(size_t limit) {
    // std::cout<<"limit:"<<limit<<std::endl;
#ifdef MS_WITH_LIBBPF
    std::lock_guard<std::mutex> lk(mu_);
    if (limit == 0)
        max_events_per_group_ = static_cast<size_t>(-1);
    else
        max_events_per_group_ = limit;
    if (!ready_ || active_groups_.empty())
        return;
    std::vector<PmuGroupConfig> to_attach;
    to_attach.push_back(active_groups_[std::min(active_group_index_, active_groups_.size() - 1)]);
    AttachPerfGroupsLocked(to_attach);
#else
    (void)limit;
#endif
}

void BpfOrchestrator::SyncBudgetConfig(uint64_t sentinel_budget,
                                       uint64_t diagnostic_budget,
                                       uint64_t hard_drop_ns) {
    cfg_.sentinel_sample_budget = sentinel_budget;
    cfg_.diagnostic_sample_budget = diagnostic_budget;
    cfg_.hard_drop_ns = hard_drop_ns;
}

#else

bool BpfOrchestrator::SwitchMode(AgentMode) {
    return false;
}

bool BpfOrchestrator::RotateToGroup(size_t) {
    return false;
}

#endif

} // namespace micro_sentinel
