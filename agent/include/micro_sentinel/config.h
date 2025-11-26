#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "ms_common.h"
#include <linux/perf_event.h>

namespace micro_sentinel {

struct PmuEventDesc {
    std::string name;
    uint32_t type{PERF_TYPE_HARDWARE};
    uint64_t config{PERF_COUNT_HW_CACHE_MISSES};
    uint64_t sample_period{100000ULL};
    ms_pmu_event_type logical{MS_EVT_L3_MISS};
    bool precise{true};
};

struct PmuGroupConfig {
    std::string name;
    std::vector<PmuEventDesc> events;
};

struct PerfConsumerConfig {
    bool mock_mode{false};
    std::string bpf_object_path{"bpf/micro_sentinel_kern.bpf.o"};
    std::vector<int> cpus{};
    std::vector<std::string> xdp_ifaces{};
    bool numa_workers{true};
    std::chrono::milliseconds mock_period{std::chrono::milliseconds{10}};
    std::vector<PmuGroupConfig> sentinel_groups{
        {"sentinel-default",
         {{"l3_miss", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES, 200000ULL, MS_EVT_L3_MISS, true}}}
    };
    std::vector<PmuGroupConfig> diagnostic_groups{
        {"diagnostic-default",
         {
             {"l3_miss", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES, 150000ULL, MS_EVT_L3_MISS, true},
             {"branch_misp", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES, 120000ULL, MS_EVT_BRANCH_MISPRED, false},
             {"xsnp_hitm", PERF_TYPE_RAW, 0x1B7, 80000ULL, MS_EVT_XSNP_HITM, true}
         }}
    };
    uint64_t sentinel_sample_budget{5'000ULL};
    uint64_t diagnostic_sample_budget{20'000ULL};
    uint64_t hard_drop_ns{MS_FLOW_SKID_NS * 4ULL};
    int events_map_fd{-1};
    size_t ring_pages{8};
    std::chrono::milliseconds rotation_window{std::chrono::milliseconds{5000}};
    double safety_high_watermark{0.95};
    double safety_low_watermark{0.75};
    size_t shed_event_limit{1};
};

struct AggregatorConfig {
    uint64_t time_window_ns{5'000'000ULL};
    std::size_t max_entries{200'000};
    std::chrono::milliseconds flush_interval{std::chrono::milliseconds{200}};
};

struct ModeThresholds {
    double sentinel_to_diag{1.10};
    double diag_to_sentinel{1.02};
    double throughput_ratio_trigger{0.85};
    double latency_ratio_trigger{1.25};
    std::chrono::milliseconds anomaly_quiet_period{std::chrono::milliseconds{5000}};
};

struct MetricsConfig {
    std::string listen_address{"0.0.0.0"};
    uint16_t listen_port{9105};
    std::chrono::seconds flush_interval{std::chrono::seconds{5}};
};

struct AnomalyDetectorConfig {
    bool enabled{true};
    std::vector<std::string> interfaces{}; // empty => sum all interfaces
    std::chrono::milliseconds sample_interval{std::chrono::milliseconds{500}};
    double throughput_ewma_alpha{0.1};
    double latency_ewma_alpha{0.2};
    double throughput_ratio_trigger{0.85};
    double latency_ratio_trigger{1.3};
    std::chrono::milliseconds refractory_period{std::chrono::milliseconds{5000}};
    std::string latency_probe_path{}; // optional file containing latest latency in usec
};

struct ClickHouseConfig {
    std::string endpoint{"http://localhost:8123"};
    std::string table{"ms_flow_rollup"};
    std::string stack_table{"ms_stack_traces"};
    std::string raw_table{"ms_raw_samples"};
    std::string data_table{"ms_data_objects"};
    std::chrono::milliseconds flush_interval{std::chrono::milliseconds{500}};
    std::size_t batch_size{4096};
};

struct ControlPlaneConfig {
    std::string listen_address{"127.0.0.1"};
    uint16_t listen_port{9200};
};

struct TscCalibrationConfig {
    bool enabled{true};
    double slope_alpha{0.05};
    double offset_alpha{0.05};
};

struct AgentConfig {
    PerfConsumerConfig perf;
    AggregatorConfig aggregator;
    ModeThresholds thresholds;
    AnomalyDetectorConfig anomaly;
    TscCalibrationConfig tsc_calibration;
    MetricsConfig metrics;
    ClickHouseConfig ch;
    ControlPlaneConfig control;
    bool diagnostic_mode{false};
};

} // namespace micro_sentinel
