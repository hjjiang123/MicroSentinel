#include <cassert>
#include <chrono>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>

#include "micro_sentinel/aggregator.h"
#include "micro_sentinel/anomaly.h"
#include "micro_sentinel/bucket_update.h"
#include "micro_sentinel/config_loader.h"
#include "micro_sentinel/mode_controller.h"
#include "micro_sentinel/tsc_calibrator.h"
#include "micro_sentinel/sample.h"

using namespace micro_sentinel;

void RunJsonTests();
void RunSkewAdjusterTests();
void RunTargetManagerTests();
void RunRemoteDramAnalyzerTests();

int main() {
    AggregatorConfig agg_cfg;
    agg_cfg.time_window_ns = 100;
    Aggregator aggregator(agg_cfg);

    Sample sample{};
    sample.tsc = 1000;
    sample.flow_id = 7;
    sample.pmu_event = MS_EVT_L3_MISS;
    sample.pid = 100;
    sample.ip = 0x1234;
    sample.gso_segs = 4;

    aggregator.AddSample(sample, {});

    bool flushed = false;
    aggregator.Flush([&](const AggregationKey &key, const AggregatedValue &value) {
        flushed = true;
        assert(key.flow_id == 7);
        assert(value.samples == 1);
        assert(value.norm_cost > 0.24 && value.norm_cost < 0.26);
    });
    assert(flushed);

    ModeThresholds thresholds{1.1, 1.01};
    thresholds.throughput_ratio_trigger = 0.8;
    thresholds.latency_ratio_trigger = 1.2;
    thresholds.anomaly_quiet_period = std::chrono::milliseconds(10);
    ModeController controller(thresholds);
    controller.Update(1.2);
    assert(controller.Mode() == AgentMode::Diagnostic);
    controller.Update(1.0);
    assert(controller.Mode() == AgentMode::Sentinel);

    AnomalySignal drop{AnomalyType::ThroughputDrop, 0.6, 100.0, 0};
    controller.NotifyAnomaly(drop);
    assert(controller.Mode() == AgentMode::Diagnostic);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    controller.Update(0.5);
    assert(controller.Mode() == AgentMode::Sentinel);

    AnomalySignal latency{AnomalyType::LatencySpike, 1.5, 120.0, 0};
    controller.NotifyAnomaly(latency);
    assert(controller.Mode() == AgentMode::Diagnostic);

    TscCalibrationConfig tsc_cfg;
    tsc_cfg.slope_alpha = 0.2;
    tsc_cfg.offset_alpha = 0.5;
    TscCalibrator calibrator(tsc_cfg);
    uint64_t base = 1'000'000ULL;
    uint64_t norm1 = calibrator.Normalize(0, base);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    uint64_t norm2 = calibrator.Normalize(0, base + 10'000ULL);
    assert(norm2 > norm1);
    calibrator.Snapshot([](uint32_t cpu, double slope, double offset) {
        assert(cpu == 0);
        assert(slope > 0.0);
        (void)offset;
    });

    AgentConfig cfg;
    std::string error;
    assert(ApplyConfigOverride("sentinel_budget", "12345", cfg, error));
    assert(cfg.perf.sentinel_sample_budget == 12345);
    assert(ApplyCliFlag("--metrics-port=9200", cfg, error));
    assert(cfg.metrics.listen_port == 9200);

    const std::string config_path = "test_agent.conf";
    {
        std::ofstream out(config_path);
        out << "diagnostic_mode=true\n";
        out << "cpus=0,2-3\n";
        out << "mock_period_ms=50\n";
    }
    AgentConfig file_cfg;
    assert(LoadAgentConfigFile(config_path, file_cfg, error));
    assert(file_cfg.diagnostic_mode);
    assert(file_cfg.perf.cpus.size() == 3);
    assert(file_cfg.perf.mock_period.count() == 50);
    std::filesystem::remove(config_path);

    BucketState state{1000, 4000, 8000};
    BucketUpdateRequest sentinel_req;
    sentinel_req.has_sentinel = true;
    sentinel_req.sentinel_budget = 1500;
    auto outcome = ApplyBucketUpdate(sentinel_req, AgentMode::Sentinel, state);
    assert(outcome.reprogram_required);
    assert(outcome.active_budget == 1500);
    assert(state.diagnostic_budget == 4000);

    BucketUpdateRequest diag_req;
    diag_req.has_diagnostic = true;
    diag_req.diagnostic_budget = 6000;
    outcome = ApplyBucketUpdate(diag_req, AgentMode::Sentinel, state);
    assert(!outcome.reprogram_required);
    assert(outcome.active_budget == 1500);
    outcome = ApplyBucketUpdate(diag_req, AgentMode::Diagnostic, state);
    assert(outcome.reprogram_required);
    assert(outcome.active_budget == 6000);

    BucketUpdateRequest drop_req;
    drop_req.has_hard_drop = true;
    drop_req.hard_drop_ns = 2000;
    outcome = ApplyBucketUpdate(drop_req, AgentMode::Sentinel, state);
    assert(outcome.reprogram_required);
    assert(state.hard_drop_ns == 2000);

    RunSkewAdjusterTests();
    RunTargetManagerTests();
    RunRemoteDramAnalyzerTests();
    RunJsonTests();

    std::cout << "All tests passed" << std::endl;
    return 0;
}
