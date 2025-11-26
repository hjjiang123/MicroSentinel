#pragma once

#include <cstdint>

namespace micro_sentinel {

enum class AnomalyType : uint8_t {
    ThroughputDrop = 0,
    LatencySpike = 1,
};

struct AnomalySignal {
    AnomalyType type{AnomalyType::ThroughputDrop};
    double ratio{1.0};          // Relative change versus baseline (throughput < 1.0, latency > 1.0)
    double value{0.0};          // Absolute measurement in native units (bytes/sec or usec)
    uint64_t timestamp_ns{0};   // Steady-clock nanoseconds when the sample was recorded
};

} // namespace micro_sentinel
