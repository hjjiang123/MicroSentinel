#include "micro_sentinel/fs_detector.h"

#include <algorithm>

namespace micro_sentinel {

FalseSharingDetector::FalseSharingDetector(Symbolizer *symbolizer, uint64_t window_ns, uint64_t threshold)
    : window_ns_(window_ns), threshold_(threshold), symbolizer_(symbolizer) {}

void FalseSharingDetector::Observe(const Sample &sample) {
    if (sample.pmu_event != MS_EVT_XSNP_HITM)
        return;

    uint64_t line = sample.data_addr & ~(64ULL - 1ULL);
    std::lock_guard<std::mutex> lk(mu_);
    auto &stats = table_[line];
    stats.total_hits++;
    stats.last_tsc = sample.tsc;
    if (stats.cpu_hits.size() <= sample.cpu)
        stats.cpu_hits.resize(sample.cpu + 1, 0);
    stats.cpu_hits[sample.cpu]++;
    stats.pid_hits[sample.pid]++;
}

void FalseSharingDetector::Flush(uint64_t now_tsc,
                                 const std::function<void(const FalseSharingFinding &)> &cb) {
    std::unordered_map<uint64_t, Stats> expired;
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto it = table_.begin(); it != table_.end();) {
            if (now_tsc - it->second.last_tsc > window_ns_) {
                expired.emplace(it->first, std::move(it->second));
                it = table_.erase(it);
            } else {
                ++it;
            }
        }
    }

    for (auto &kv : expired) {
        const auto &stats = kv.second;
        if (stats.total_hits < threshold_)
            continue;
        uint64_t active = 0;
        uint64_t max_hits = 0;
        for (uint64_t hits : stats.cpu_hits) {
            if (hits == 0)
                continue;
            active++;
            max_hits = std::max(max_hits, hits);
        }
        if (active < 2)
            continue;
        double dominance = static_cast<double>(max_hits) / static_cast<double>(stats.total_hits);
        if (dominance >= 0.9)
            continue;
        FalseSharingFinding finding;
        finding.line_addr = kv.first;
        finding.total_hits = stats.total_hits;
        finding.cpu_hits = stats.cpu_hits;
        uint32_t dominant_pid = 0;
        uint64_t dominant_hits = 0;
        for (const auto &ph : stats.pid_hits) {
            if (ph.second > dominant_hits) {
                dominant_hits = ph.second;
                dominant_pid = ph.first;
            }
        }
        finding.dominant_pid = dominant_pid;
        if (symbolizer_ && dominant_pid != 0)
            finding.object = symbolizer_->ResolveData(dominant_pid, kv.first);
        cb(finding);
    }
}

} // namespace micro_sentinel
