#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include "micro_sentinel/anomaly.h"
#include "micro_sentinel/config.h"

namespace micro_sentinel {

class AnomalyMonitor {
public:
    explicit AnomalyMonitor(AnomalyDetectorConfig cfg);
    ~AnomalyMonitor();

    void Start(const std::function<void(const AnomalySignal &)> &cb);
    void Stop();

private:
    void Run();
    bool ReadInterfaceBytes(uint64_t &total_bytes) const;
    bool ReadLatencyMicros(double &latency_us) const;
    static uint64_t SteadyNowNs();

    void MaybeEmitThroughput(double bps, uint64_t now_ns);
    void MaybeEmitLatency(double latency_us, uint64_t now_ns);

    const AnomalyDetectorConfig cfg_;
    std::function<void(const AnomalySignal &)> callback_;
    std::thread worker_;
    std::atomic<bool> running_{false};

    double throughput_baseline_{0.0};
    bool throughput_ready_{false};
    uint64_t last_throughput_emit_{0};

    double latency_baseline_{0.0};
    bool latency_ready_{false};
    uint64_t last_latency_emit_{0};
};

} // namespace micro_sentinel
