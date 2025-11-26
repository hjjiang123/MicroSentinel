#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <vector>

#include "micro_sentinel/sample.h"

namespace micro_sentinel {

class SkewAdjuster {
public:
    using EmitCallback = std::function<void(Sample &&, LbrStack &&)>;

    SkewAdjuster(uint64_t tolerance_ns = MS_FLOW_SKID_NS, size_t max_window = 4);

    void Process(Sample sample, LbrStack stack, const EmitCallback &emit);
    void Flush(const EmitCallback &emit);

private:
    struct Bundle {
        Sample sample;
        LbrStack stack;
    };

    struct CpuWindow {
        std::deque<Bundle> entries;
    };

    void EnsureCpu(uint32_t cpu);
    void AdjustWindow(CpuWindow &window);
    void DrainReady(CpuWindow &window, std::vector<Bundle> &out_ready);
    void DrainAll(CpuWindow &window, std::vector<Bundle> &out_ready);

    uint64_t tolerance_ns_;
    size_t max_window_;
    std::vector<CpuWindow> per_cpu_;
    std::mutex mu_;
};

} // namespace micro_sentinel
