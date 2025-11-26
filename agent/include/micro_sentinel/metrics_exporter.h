#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

#include "micro_sentinel/config.h"

namespace micro_sentinel {

class MetricsExporter {
public:
    explicit MetricsExporter(MetricsConfig cfg);
    ~MetricsExporter();

    void Start();
    void Stop();

    void SetGauge(const std::string &name, double value);

private:
    void ServerLoop();
    std::string RenderMetrics();

    MetricsConfig cfg_;
    std::atomic<bool> running_{false};
    std::thread worker_;
    std::mutex mu_;
    std::unordered_map<std::string, double> gauges_;
};

} // namespace micro_sentinel
