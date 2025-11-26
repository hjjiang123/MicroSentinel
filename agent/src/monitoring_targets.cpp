#include "micro_sentinel/monitoring_targets.h"

#include <algorithm>
#include <cctype>
#include <fstream>

namespace micro_sentinel {

MonitoringTargetManager::MonitoringTargetManager() = default;

void MonitoringTargetManager::Update(const std::vector<TargetSpec> &specs) {
    std::unordered_set<uint32_t> next_pids;
    std::vector<FlowTarget> next_flows;
    bool allow_all = specs.empty();
    bool has_pid = false;
    bool has_flow = false;

    for (const auto &spec : specs) {
        switch (spec.type) {
        case TargetType::All:
            allow_all = true;
            next_pids.clear();
            next_flows.clear();
            has_pid = false;
            has_flow = false;
            break;
        case TargetType::Process:
            has_pid = true;
            if (spec.pid != 0)
                next_pids.insert(spec.pid);
            break;
        case TargetType::Cgroup:
            has_pid = true;
            if (!spec.path.empty())
                LoadCgroupPids(spec.path, next_pids);
            break;
        case TargetType::Flow:
            has_flow = true;
            next_flows.push_back(spec.flow);
            break;
        }
        if (allow_all)
            break;
    }

    std::lock_guard<std::mutex> lk(mu_);
    allow_all_ = allow_all;
    has_pid_filter_ = has_pid;
    has_flow_filter_ = has_flow;
    allowed_pids_.swap(next_pids);
    flow_targets_.swap(next_flows);
}

bool MonitoringTargetManager::Allow(const Sample &sample) const {
    std::lock_guard<std::mutex> lk(mu_);
    if (allow_all_)
        return true;

    bool pid_ok = !has_pid_filter_;
    if (has_pid_filter_)
        pid_ok = allowed_pids_.count(sample.pid) > 0;

    if (!pid_ok)
        return false;

    if (!has_flow_filter_)
        return true;

    for (const auto &flow : flow_targets_) {
        bool if_ok = (flow.ingress_ifindex == 0) || (flow.ingress_ifindex == sample.ingress_ifindex);
        bool proto_ok = (flow.l4_proto == 0) || (flow.l4_proto == sample.l4_proto);
        if (if_ok && proto_ok)
            return true;
    }
    return false;
}

void MonitoringTargetManager::LoadCgroupPids(const std::string &path, std::unordered_set<uint32_t> &dest) const {
    std::string procs_path = path;
    if (!procs_path.empty() && procs_path.back() != '/')
        procs_path += '/';
    procs_path += "cgroup.procs";

    std::ifstream in(procs_path);
    if (!in.good())
        return;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty())
            continue;
        uint32_t pid = 0;
        try {
            pid = static_cast<uint32_t>(std::stoul(line));
        } catch (...) {
            continue;
        }
        if (pid != 0)
            dest.insert(pid);
    }
}

} // namespace micro_sentinel
