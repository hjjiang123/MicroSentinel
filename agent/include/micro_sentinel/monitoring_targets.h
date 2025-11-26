#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

#include "micro_sentinel/control_messages.h"
#include "micro_sentinel/sample.h"

namespace micro_sentinel {

class MonitoringTargetManager {
public:
    MonitoringTargetManager();

    void Update(const std::vector<TargetSpec> &specs);
    bool Allow(const Sample &sample) const;

private:
    void LoadCgroupPids(const std::string &path, std::unordered_set<uint32_t> &dest) const;

    mutable std::mutex mu_;
    std::unordered_set<uint32_t> allowed_pids_;
    std::vector<FlowTarget> flow_targets_;
    bool allow_all_{true};
    bool has_pid_filter_{false};
    bool has_flow_filter_{false};
};

} // namespace micro_sentinel
