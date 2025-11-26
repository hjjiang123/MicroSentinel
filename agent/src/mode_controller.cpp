#include "micro_sentinel/mode_controller.h"

#include <algorithm>
#include <chrono>

namespace micro_sentinel {

ModeController::ModeController(ModeThresholds thresholds)
    : thresholds_(thresholds) {}

uint64_t ModeController::NowNs() {
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
}

bool ModeController::AnomalyHoldActive() const {
    uint64_t hold_ns = static_cast<uint64_t>(thresholds_.anomaly_quiet_period.count()) * 1'000'000ULL;
    if (hold_ns == 0)
        return false;
    uint64_t last = last_anomaly_ns_.load(std::memory_order_relaxed);
    if (last == 0)
        return false;
    uint64_t now = NowNs();
    return now >= last && now - last < hold_ns;
}

AgentMode ModeController::Update(double load_ratio) {
    AgentMode cur = mode_.load(std::memory_order_relaxed);
    if (cur == AgentMode::Sentinel && load_ratio > thresholds_.sentinel_to_diag) {
        mode_.store(AgentMode::Diagnostic, std::memory_order_relaxed);
    } else if (cur == AgentMode::Diagnostic) {
        if (!AnomalyHoldActive() && load_ratio < thresholds_.diag_to_sentinel)
            mode_.store(AgentMode::Sentinel, std::memory_order_relaxed);
    }
    return mode_.load(std::memory_order_relaxed);
}

AgentMode ModeController::NotifyAnomaly(const AnomalySignal &signal) {
    uint64_t ts = signal.timestamp_ns ? signal.timestamp_ns : NowNs();
    last_anomaly_ns_.store(ts, std::memory_order_relaxed);
    switch (signal.type) {
    case AnomalyType::ThroughputDrop: {
        last_throughput_ratio_.store(signal.ratio, std::memory_order_relaxed);
        double trigger = thresholds_.throughput_ratio_trigger;
        if (signal.ratio > 0.0 && signal.ratio < trigger)
            mode_.store(AgentMode::Diagnostic, std::memory_order_relaxed);
        break;
    }
    case AnomalyType::LatencySpike: {
        last_latency_ratio_.store(signal.ratio, std::memory_order_relaxed);
        if (signal.ratio > thresholds_.latency_ratio_trigger)
            mode_.store(AgentMode::Diagnostic, std::memory_order_relaxed);
        break;
    }
    }
    return mode_.load(std::memory_order_relaxed);
}

} // namespace micro_sentinel
