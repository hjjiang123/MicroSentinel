#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <unordered_map>

#include "micro_sentinel/sample.h"
#include "micro_sentinel/config.h"
#include "micro_sentinel/interference.h"

namespace micro_sentinel {

struct AggregatedValue {
    uint64_t samples{0};
    double norm_cost{0.0};
};

struct AggregationKey {
    uint64_t flow_id{0};
    uint64_t function_hash{0};
    uint64_t callstack_id{0};
    uint64_t data_object_id{0};
    uint32_t pmu_event{0};
    uint16_t numa_node{0};
    uint8_t interference_class{static_cast<uint8_t>(InterferenceClass::Unknown)};
    uint8_t direction{0};
    uint64_t bucket{0};

    bool operator==(const AggregationKey &other) const = default;
};

struct AggregationKeyHash {
    std::size_t operator()(const AggregationKey &key) const noexcept;
};

class Symbolizer;

class Aggregator {
public:
    explicit Aggregator(AggregatorConfig cfg);

    void AttachSymbolizer(Symbolizer *symbolizer);
    void SetSampleScale(double scale);
    double SampleScale() const;
    void AddSample(const Sample &sample, const LbrStack &lbr);
    size_t Flush(const std::function<void(const AggregationKey &, const AggregatedValue &)> &cb);

private:
    uint64_t Bucketize(uint64_t tsc) const;
    uint64_t InternFunction(uint32_t pid, uint64_t ip, const LbrStack &lbr);
    uint64_t InternCallstack(uint32_t pid, uint64_t ip, const LbrStack &lbr);
    uint64_t InternDataObject(uint32_t pid, uint64_t addr);
    uint8_t EventClass(uint32_t pmu_event) const;

    AggregatorConfig cfg_;
    Symbolizer *symbolizer_{nullptr};
    std::unordered_map<AggregationKey, AggregatedValue, AggregationKeyHash> table_;
    std::mutex mu_;
    std::atomic<double> sample_scale_{1.0};
};

} // namespace micro_sentinel
