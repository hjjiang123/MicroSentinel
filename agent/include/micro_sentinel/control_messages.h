#pragma once

#include <vector>
#include <string>

#include "micro_sentinel/config.h"

namespace micro_sentinel {

struct PmuConfigUpdate {
    bool has_sentinel{false};
    std::vector<PmuGroupConfig> sentinel_groups;
    bool has_diagnostic{false};
    std::vector<PmuGroupConfig> diagnostic_groups;
};

struct JitRegionRequest {
    uint32_t pid{0};
    uint64_t start{0};
    uint64_t end{0};
    std::string path;
    std::string build_id;
};

struct DataObjectRequest {
    uint32_t pid{0};
    uint64_t address{0};
    std::string name;
    std::string type;
    uint64_t size{0};
};

enum class TargetType {
    All,
    Cgroup,
    Process,
    Flow
};

struct FlowTarget {
    uint16_t ingress_ifindex{0};
    uint8_t l4_proto{0};
};

struct TargetSpec {
    TargetType type{TargetType::All};
    std::string path;
    uint32_t pid{0};
    FlowTarget flow;
};

struct TargetUpdateRequest {
    std::vector<TargetSpec> targets;
};

} // namespace micro_sentinel
