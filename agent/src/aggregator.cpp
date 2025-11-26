#include "micro_sentinel/aggregator.h"

#include <algorithm>
#include <cmath>

#include "micro_sentinel/symbolizer.h"
#include "micro_sentinel/interference.h"

namespace micro_sentinel {

std::size_t AggregationKeyHash::operator()(const AggregationKey &key) const noexcept {
    std::size_t h = std::hash<uint64_t>{}(key.flow_id);
    h ^= std::hash<uint64_t>{}(key.function_hash + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2));
    h ^= std::hash<uint64_t>{}(key.callstack_id + 0xbf58476d1ce4e5b9ULL + (h << 5) + (h >> 3));
    h ^= std::hash<uint64_t>{}(key.data_object_id + 0x94d049bb133111ebULL + (h << 4) + (h >> 1));
    h ^= std::hash<uint32_t>{}(key.pmu_event + static_cast<uint32_t>(h));
    h ^= std::hash<uint16_t>{}(key.numa_node + static_cast<uint16_t>(h));
    h ^= std::hash<uint8_t>{}(key.interference_class + static_cast<uint8_t>(h));
    h ^= std::hash<uint8_t>{}(key.direction + static_cast<uint8_t>(h));
    h ^= std::hash<uint64_t>{}(key.bucket + 0x517cc1b727220a95ULL);
    return h;
}

Aggregator::Aggregator(AggregatorConfig cfg) : cfg_(cfg) {}

void Aggregator::AttachSymbolizer(Symbolizer *symbolizer) {
    symbolizer_ = symbolizer;
}

void Aggregator::SetSampleScale(double scale) {
    if (scale <= 0.0)
        scale = 1.0;
    sample_scale_.store(scale, std::memory_order_relaxed);
}

double Aggregator::SampleScale() const {
    return sample_scale_.load(std::memory_order_relaxed);
}

uint64_t Aggregator::Bucketize(uint64_t tsc) const {
    if (cfg_.time_window_ns == 0)
        return tsc;
    return tsc / cfg_.time_window_ns;
}

uint64_t Aggregator::InternFunction(uint32_t pid, uint64_t ip, const LbrStack &lbr) {
    if (!symbolizer_)
        return ip;
    return symbolizer_->InternFunction(pid, ip);
}

uint64_t Aggregator::InternCallstack(uint32_t pid, uint64_t ip, const LbrStack &lbr) {
    if (!symbolizer_)
        return ip;
    return symbolizer_->InternStack(pid, ip, lbr);
}

uint64_t Aggregator::InternDataObject(uint32_t pid, uint64_t addr) {
    if (!symbolizer_ || addr == 0)
        return 0;
    return symbolizer_->InternDataObject(pid, addr, nullptr);
}

uint8_t Aggregator::EventClass(uint32_t pmu_event) const {
    return static_cast<uint8_t>(ClassifyEvent(static_cast<ms_pmu_event_type>(pmu_event)));
}

void Aggregator::AddSample(const Sample &sample, const LbrStack &lbr) {
    AggregationKey key{};
    key.flow_id = sample.flow_id;
    key.function_hash = InternFunction(sample.pid, sample.ip, lbr);
    key.callstack_id = InternCallstack(sample.pid, sample.ip, lbr);
    key.data_object_id = InternDataObject(sample.pid, sample.data_addr);
    key.pmu_event = sample.pmu_event;
    key.numa_node = sample.numa_node;
    key.interference_class = EventClass(sample.pmu_event);
    key.direction = sample.direction;
    key.bucket = Bucketize(sample.tsc);

    double weight = sample_scale_.load(std::memory_order_relaxed);
    if (sample.gso_segs > 1)
        weight /= static_cast<double>(sample.gso_segs);

    std::lock_guard<std::mutex> lk(mu_);
    auto &slot = table_[key];
    slot.samples += 1;
    slot.norm_cost += weight;

    if (table_.size() > cfg_.max_entries)
        table_.clear();
}

size_t Aggregator::Flush(const std::function<void(const AggregationKey &, const AggregatedValue &)> &cb) {
    std::unordered_map<AggregationKey, AggregatedValue, AggregationKeyHash> snapshot;
    {
        std::lock_guard<std::mutex> lk(mu_);
        snapshot.swap(table_);
    }
    size_t emitted = 0;
    for (const auto &kv : snapshot) {
        cb(kv.first, kv.second);
        emitted += kv.second.samples;
    }
    return emitted;
}

} // namespace micro_sentinel
