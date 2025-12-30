#pragma once

#include <cstdint>
#include <functional>
#include <mutex>
#include <vector>

#include "micro_sentinel/config.h"

namespace micro_sentinel {

class TscCalibrator {
public:
    explicit TscCalibrator(TscCalibrationConfig cfg);

    uint64_t Normalize(uint32_t cpu, uint64_t raw_tsc);
    void Snapshot(const std::function<void(uint32_t cpu, double slope, double offset_ns)> &cb) const;

private:
    struct CpuModel {
        double slope{1.0};
        double offset{0.0};
        uint64_t last_raw{0};
        uint64_t last_ref{0};
        bool initialized{false};
        bool passthrough_steady_ns{false};
    };

    static uint64_t NowNs();
    CpuModel &EnsureModel(uint32_t cpu);

    const TscCalibrationConfig cfg_;
    mutable std::mutex mu_;
    std::vector<CpuModel> models_;
};

} // namespace micro_sentinel
