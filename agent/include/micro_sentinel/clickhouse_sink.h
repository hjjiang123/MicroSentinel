#pragma once

#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "micro_sentinel/aggregator.h"
#include "micro_sentinel/config.h"
#include "micro_sentinel/symbolizer.h"

namespace micro_sentinel {

class ClickHouseSink {
public:
    explicit ClickHouseSink(ClickHouseConfig cfg);
    ~ClickHouseSink();

    void Start();
    void Stop();

    void Enqueue(const AggregationKey &key, const AggregatedValue &value);
    void EnqueueStack(const StackTrace &trace);
    void EnqueueRawSample(const Sample &sample, const LbrStack &stack, double norm_cost);
    void EnqueueDataObject(const DataSymbol &symbol);
    void SetBucketWidth(uint64_t ns);

private:
    void RunLoop();
    void FlushBatch();
    bool ParseEndpoint();
    bool SendPayload(const std::string &body);

    ClickHouseConfig cfg_;
    std::atomic<bool> running_{false};
    std::thread worker_;
    std::mutex mu_;
    struct RawRow {
        Sample sample;
        LbrStack stack;
        double norm_cost{1.0};
    };

    std::vector<std::pair<AggregationKey, AggregatedValue>> batch_;
    std::vector<StackTrace> stack_batch_;
    std::vector<RawRow> raw_batch_;
    std::vector<DataSymbol> data_batch_;
    std::string agent_hostname_;
    uint64_t bucket_width_ns_{5'000'000ULL};

    struct HttpEndpoint {
        std::string host;
        uint16_t port{8123};
        std::string path{"/"};
        bool valid{false};
    } endpoint_;
};

} // namespace micro_sentinel
