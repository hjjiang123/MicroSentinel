#include "micro_sentinel/tsc_calibrator.h"

#include <algorithm>
#include <chrono>

namespace micro_sentinel {

namespace {
constexpr double kMinAlpha = 0.001;
constexpr double kMaxAlpha = 0.5;
}

TscCalibrator::TscCalibrator(TscCalibrationConfig cfg)
    : cfg_(cfg) {}

uint64_t TscCalibrator::NowNs() {
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
}

TscCalibrator::CpuModel &TscCalibrator::EnsureModel(uint32_t cpu) {
    if (cpu >= models_.size())
        models_.resize(static_cast<size_t>(cpu) + 1);
    return models_[cpu];
}

uint64_t TscCalibrator::Normalize(uint32_t cpu, uint64_t raw_tsc) {
    if (!cfg_.enabled)
        return raw_tsc;

    const double slope_alpha = std::clamp(cfg_.slope_alpha, kMinAlpha, kMaxAlpha);
    const double offset_alpha = std::clamp(cfg_.offset_alpha, kMinAlpha, kMaxAlpha);

    uint64_t ref_ns = NowNs();
    std::lock_guard<std::mutex> lk(mu_);
    auto &model = EnsureModel(cpu);

    if (!model.initialized) {
        model.initialized = true;

        // Heuristic: if the incoming timestamp is already in the same steady-clock
        // nanoseconds domain as ref_ns (e.g., produced by bpf_ktime_get_ns()),
        // bypass calibration entirely.
        if (ref_ns > 0 && raw_tsc > 0) {
            const double ratio = static_cast<double>(raw_tsc) / static_cast<double>(ref_ns);
            if (ratio > 0.75 && ratio < 1.5) {
                model.passthrough_steady_ns = true;
                model.last_raw = raw_tsc;
                model.last_ref = ref_ns;
                return raw_tsc;
            }
        }

        model.slope = 1.0;
        model.offset = static_cast<double>(ref_ns) - static_cast<double>(raw_tsc);
        model.last_raw = raw_tsc;
        model.last_ref = ref_ns;
        return ref_ns;
    }

    if (model.passthrough_steady_ns)
        return raw_tsc;

    uint64_t raw_delta = raw_tsc >= model.last_raw ? (raw_tsc - model.last_raw) : 0;
    uint64_t ref_delta = ref_ns - model.last_ref;
    if (raw_delta > 0 && ref_delta > 0) {
        double slope_est = static_cast<double>(ref_delta) / static_cast<double>(raw_delta);
        // Guard against backlog/outliers that can make slope_est explode.
        if (slope_est > 0.0 && slope_est < 10.0)
            model.slope = slope_alpha * slope_est + (1.0 - slope_alpha) * model.slope;
    }

    double offset_est = static_cast<double>(ref_ns) - model.slope * static_cast<double>(raw_tsc);
    model.offset = offset_alpha * offset_est + (1.0 - offset_alpha) * model.offset;

    model.last_raw = raw_tsc;
    model.last_ref = ref_ns;

    double normalized = model.slope * static_cast<double>(raw_tsc) + model.offset;
    if (normalized < 0.0)
        normalized = 0.0;
    return static_cast<uint64_t>(normalized);
}

void TscCalibrator::Snapshot(const std::function<void(uint32_t cpu, double slope, double offset_ns)> &cb) const {
    if (!cb)
        return;
    std::lock_guard<std::mutex> lk(mu_);
    for (uint32_t cpu = 0; cpu < models_.size(); ++cpu) {
        if (!models_[cpu].initialized)
            continue;
        cb(cpu, models_[cpu].slope, models_[cpu].offset);
    }
}

} // namespace micro_sentinel
