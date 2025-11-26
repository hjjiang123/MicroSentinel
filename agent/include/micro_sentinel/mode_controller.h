#pragma once

#include <atomic>
#include <cstdint>
#include <cstddef>

#include "micro_sentinel/anomaly.h"

#include "micro_sentinel/config.h"

namespace micro_sentinel {

enum class AgentMode { Sentinel, Diagnostic };

class ModeController {
public:
    explicit ModeController(ModeThresholds thresholds);

    AgentMode Mode() const { return mode_.load(std::memory_order_relaxed); }
    AgentMode Update(double throughput_ratio);
    AgentMode NotifyAnomaly(const AnomalySignal &signal);
    void Force(AgentMode mode) { mode_.store(mode, std::memory_order_relaxed); }

private:
    bool AnomalyHoldActive() const;
    static uint64_t NowNs();

    ModeThresholds thresholds_;
    std::atomic<AgentMode> mode_{AgentMode::Sentinel};
    std::atomic<uint64_t> last_anomaly_ns_{0};
    std::atomic<double> last_throughput_ratio_{1.0};
    std::atomic<double> last_latency_ratio_{1.0};
};

} // namespace micro_sentinel
