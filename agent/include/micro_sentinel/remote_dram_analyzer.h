#pragma once

#include <cstdint>
#include <functional>
#include <mutex>
#include <unordered_map>

#include "micro_sentinel/sample.h"

namespace micro_sentinel {

struct RemoteDramFinding {
    uint64_t flow_id{0};
    uint16_t numa_node{0};
    uint16_t ifindex{0};
    uint64_t samples{0};
};

class RemoteDramAnalyzer {
public:
    explicit RemoteDramAnalyzer(uint64_t window_ns = 50'000'000ULL);

    void Observe(const Sample &sample);
    void Flush(uint64_t now_tsc, const std::function<void(const RemoteDramFinding &)> &cb);

private:
    struct Key {
        uint64_t flow_id;
        uint16_t numa_node;
        uint16_t ifindex;

        bool operator==(const Key &other) const {
            return flow_id == other.flow_id && numa_node == other.numa_node && ifindex == other.ifindex;
        }
    };

    struct KeyHash {
        std::size_t operator()(const Key &k) const noexcept {
            return std::hash<uint64_t>{}(k.flow_id) ^ (static_cast<std::size_t>(k.numa_node) << 1) ^ (static_cast<std::size_t>(k.ifindex) << 9);
        }
    };

    struct Entry {
        uint64_t count{0};
        uint64_t last_tsc{0};
    };

    uint64_t window_ns_;
    std::unordered_map<Key, Entry, KeyHash> table_;
    std::mutex mu_;
};

} // namespace micro_sentinel
