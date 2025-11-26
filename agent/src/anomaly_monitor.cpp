#include "micro_sentinel/anomaly_monitor.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <fstream>
#include <sstream>

namespace micro_sentinel {

namespace {

std::string Trim(const std::string &value) {
    auto begin = std::find_if_not(value.begin(), value.end(), [](unsigned char c) { return std::isspace(c); });
    auto end = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char c) { return std::isspace(c); }).base();
    if (begin >= end)
        return {};
    return std::string(begin, end);
}

} // namespace

AnomalyMonitor::AnomalyMonitor(AnomalyDetectorConfig cfg)
    : cfg_(std::move(cfg)) {}

AnomalyMonitor::~AnomalyMonitor() {
    Stop();
}

void AnomalyMonitor::Start(const std::function<void(const AnomalySignal &)> &cb) {
    if (!cfg_.enabled)
        return;
    callback_ = cb;
    if (running_.exchange(true))
        return;
    worker_ = std::thread(&AnomalyMonitor::Run, this);
}

void AnomalyMonitor::Stop() {
    if (!running_.exchange(false))
        return;
    if (worker_.joinable())
        worker_.join();
}

void AnomalyMonitor::Run() {
    uint64_t prev_bytes = 0;
    bool has_prev = false;
    auto prev_time = std::chrono::steady_clock::now();

    while (running_.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(cfg_.sample_interval);
        uint64_t cur_bytes = 0;
        if (!ReadInterfaceBytes(cur_bytes))
            continue;
        auto now = std::chrono::steady_clock::now();
        uint64_t now_ns = SteadyNowNs();

        if (has_prev) {
            uint64_t delta_bytes = (cur_bytes >= prev_bytes) ? (cur_bytes - prev_bytes) : 0;
            auto delta_time = std::chrono::duration_cast<std::chrono::duration<double>>(now - prev_time);
            if (delta_time.count() > 0.0 && delta_bytes > 0) {
                double bps = static_cast<double>(delta_bytes) / delta_time.count();
                MaybeEmitThroughput(bps, now_ns);
            }
        } else {
            has_prev = true;
        }
        prev_bytes = cur_bytes;
        prev_time = now;

        double latency_us = 0.0;
        if (ReadLatencyMicros(latency_us))
            MaybeEmitLatency(latency_us, now_ns);
    }
}

bool AnomalyMonitor::ReadInterfaceBytes(uint64_t &total_bytes) const {
    std::ifstream dev("/proc/net/dev");
    if (!dev.good())
        return false;
    std::string line;
    // Skip headers
    std::getline(dev, line);
    std::getline(dev, line);
    total_bytes = 0;
    bool found = false;
    while (std::getline(dev, line)) {
        auto colon = line.find(':');
        if (colon == std::string::npos)
            continue;
        std::string iface = Trim(line.substr(0, colon));
        if (!cfg_.interfaces.empty() &&
            std::find(cfg_.interfaces.begin(), cfg_.interfaces.end(), iface) == cfg_.interfaces.end())
            continue;
        std::istringstream stats(line.substr(colon + 1));
        uint64_t rx_bytes = 0;
        stats >> rx_bytes;
        total_bytes += rx_bytes;
        found = true;
    }
    return found;
}

bool AnomalyMonitor::ReadLatencyMicros(double &latency_us) const {
    if (cfg_.latency_probe_path.empty())
        return false;
    std::ifstream in(cfg_.latency_probe_path);
    if (!in.good())
        return false;
    double value = 0.0;
    in >> value;
    if (!std::isfinite(value) || value <= 0.0)
        return false;
    latency_us = value;
    return true;
}

uint64_t AnomalyMonitor::SteadyNowNs() {
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
}

void AnomalyMonitor::MaybeEmitThroughput(double bps, uint64_t now_ns) {
    if (!callback_)
        return;
    if (!throughput_ready_) {
        throughput_baseline_ = bps;
        throughput_ready_ = true;
        return;
    }
    double alpha = std::clamp(cfg_.throughput_ewma_alpha, 0.01, 0.9);
    throughput_baseline_ = alpha * bps + (1.0 - alpha) * throughput_baseline_;
    double baseline = std::max(throughput_baseline_, 1.0);
    double ratio = bps / baseline;
    if (ratio < cfg_.throughput_ratio_trigger) {
        if (now_ns - last_throughput_emit_ < static_cast<uint64_t>(cfg_.refractory_period.count()) * 1'000'000ULL)
            return;
        last_throughput_emit_ = now_ns;
        callback_(AnomalySignal{AnomalyType::ThroughputDrop, ratio, bps, now_ns});
    }
}

void AnomalyMonitor::MaybeEmitLatency(double latency_us, uint64_t now_ns) {
    if (!callback_)
        return;
    if (!latency_ready_) {
        latency_baseline_ = latency_us;
        latency_ready_ = true;
        return;
    }
    double alpha = std::clamp(cfg_.latency_ewma_alpha, 0.01, 0.9);
    latency_baseline_ = alpha * latency_us + (1.0 - alpha) * latency_baseline_;
    double baseline = std::max(latency_baseline_, 1.0);
    double ratio = latency_us / baseline;
    if (ratio > cfg_.latency_ratio_trigger) {
        if (now_ns - last_latency_emit_ < static_cast<uint64_t>(cfg_.refractory_period.count()) * 1'000'000ULL)
            return;
        last_latency_emit_ = now_ns;
        callback_(AnomalySignal{AnomalyType::LatencySpike, ratio, latency_us, now_ns});
    }
}

} // namespace micro_sentinel
