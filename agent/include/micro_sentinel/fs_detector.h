#pragma once

#include <cstdint>
#include <functional>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "micro_sentinel/sample.h"
#include "micro_sentinel/symbolizer.h"

namespace micro_sentinel {

struct FalseSharingFinding {
    uint64_t line_addr{0};
    uint64_t total_hits{0};
    std::vector<uint64_t> cpu_hits;
    uint32_t dominant_pid{0};
    DataObject object;
};

class FalseSharingDetector {
public:
    explicit FalseSharingDetector(Symbolizer *symbolizer,
                                  uint64_t window_ns = 50'000'000ULL,
                                  uint64_t threshold = 100);

    void Observe(const Sample &sample);
    void Flush(uint64_t now_tsc,
               const std::function<void(const FalseSharingFinding &)> &cb);

private:
    struct Stats {
        uint64_t total_hits{0};
        uint64_t last_tsc{0};
        std::vector<uint64_t> cpu_hits;
        std::unordered_map<uint32_t, uint64_t> pid_hits;
    };

    uint64_t window_ns_;
    uint64_t threshold_;
    std::unordered_map<uint64_t, Stats> table_;
    std::mutex mu_;
    Symbolizer *symbolizer_{nullptr};
};

} // namespace micro_sentinel
