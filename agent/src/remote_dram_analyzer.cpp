#include "micro_sentinel/remote_dram_analyzer.h"

#include <vector>

namespace micro_sentinel {

RemoteDramAnalyzer::RemoteDramAnalyzer(uint64_t window_ns)
    : window_ns_(window_ns ? window_ns : 50'000'000ULL) {}

void RemoteDramAnalyzer::Observe(const Sample &sample) {
    if (sample.pmu_event != MS_EVT_REMOTE_DRAM)
        return;
    Key key{sample.flow_id, sample.numa_node, sample.ingress_ifindex};
    std::lock_guard<std::mutex> lk(mu_);
    auto &entry = table_[key];
    entry.count++;
    entry.last_tsc = sample.tsc;
}

void RemoteDramAnalyzer::Flush(uint64_t now_tsc, const std::function<void(const RemoteDramFinding &)> &cb) {
    if (!cb)
        return;
    std::vector<std::pair<Key, Entry>> expired;
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto it = table_.begin(); it != table_.end();) {
            if (now_tsc - it->second.last_tsc > window_ns_) {
                expired.emplace_back(it->first, it->second);
                it = table_.erase(it);
            } else {
                ++it;
            }
        }
    }

    for (const auto &pair : expired) {
        if (pair.second.count == 0)
            continue;
        RemoteDramFinding finding;
        finding.flow_id = pair.first.flow_id;
        finding.numa_node = pair.first.numa_node;
        finding.ifindex = pair.first.ifindex;
        finding.samples = pair.second.count;
        cb(finding);
    }
}

} // namespace micro_sentinel
