#include "micro_sentinel/skew_adjuster.h"

#include <algorithm>
#include <limits>

namespace micro_sentinel {

namespace {
inline uint64_t AbsDiff(uint64_t a, uint64_t b) {
    return (a > b) ? (a - b) : (b - a);
}
}

SkewAdjuster::SkewAdjuster(uint64_t tolerance_ns, size_t max_window)
    : tolerance_ns_(tolerance_ns ? tolerance_ns : MS_FLOW_SKID_NS)
    , max_window_(max_window >= 2 ? max_window : 2) {}

void SkewAdjuster::Process(Sample sample, LbrStack stack, const EmitCallback &emit) {
    if (!emit)
        return;

    std::vector<Bundle> ready;
    {
        std::lock_guard<std::mutex> lk(mu_);
        EnsureCpu(sample.cpu);
        auto &window = per_cpu_[sample.cpu];
        window.entries.push_back(Bundle{std::move(sample), std::move(stack)});
        AdjustWindow(window);
        DrainReady(window, ready);
    }

    for (auto &bundle : ready)
        emit(std::move(bundle.sample), std::move(bundle.stack));
}

void SkewAdjuster::Flush(const EmitCallback &emit) {
    if (!emit)
        return;
    std::vector<Bundle> ready;
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto &window : per_cpu_)
            DrainAll(window, ready);
    }
    for (auto &bundle : ready)
        emit(std::move(bundle.sample), std::move(bundle.stack));
}

void SkewAdjuster::EnsureCpu(uint32_t cpu) {
    if (cpu >= per_cpu_.size())
        per_cpu_.resize(static_cast<size_t>(cpu) + 1);
}

void SkewAdjuster::AdjustWindow(CpuWindow &window) {
    if (window.entries.size() < 2)
        return;

    const size_t n = window.entries.size();
    for (size_t i = 0; i < n; ++i) {
        auto &bundle = window.entries[i];
        if (bundle.sample.flow_id != 0)
            continue;
        uint64_t best_flow = 0;
        uint64_t best_delta = std::numeric_limits<uint64_t>::max();

        for (size_t j = i; j-- > 0;) {
            const auto &candidate = window.entries[j];
            if (candidate.sample.flow_id == 0)
                continue;
            uint64_t delta = AbsDiff(candidate.sample.tsc, bundle.sample.tsc);
            if (delta > tolerance_ns_)
                break;
            if (delta < best_delta) {
                best_delta = delta;
                best_flow = candidate.sample.flow_id;
            }
        }

        for (size_t j = i + 1; j < n; ++j) {
            const auto &candidate = window.entries[j];
            if (candidate.sample.flow_id == 0)
                continue;
            uint64_t delta = AbsDiff(candidate.sample.tsc, bundle.sample.tsc);
            if (delta > tolerance_ns_)
                break;
            if (delta < best_delta) {
                best_delta = delta;
                best_flow = candidate.sample.flow_id;
            }
        }

        if (best_flow != 0)
            bundle.sample.flow_id = best_flow;
    }
}

void SkewAdjuster::DrainReady(CpuWindow &window, std::vector<Bundle> &out_ready) {
    while (window.entries.size() > 1) {
        out_ready.push_back(std::move(window.entries.front()));
        window.entries.pop_front();
    }

    if (window.entries.size() > max_window_) {
        out_ready.push_back(std::move(window.entries.front()));
        window.entries.pop_front();
    }
}

void SkewAdjuster::DrainAll(CpuWindow &window, std::vector<Bundle> &out_ready) {
    while (!window.entries.empty()) {
        out_ready.push_back(std::move(window.entries.front()));
        window.entries.pop_front();
    }
}

} // namespace micro_sentinel
