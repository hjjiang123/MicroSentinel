#pragma once

#include <chrono>
#include <memory>
#include <mutex>

#include "micro_sentinel/aggregator.h"
#include "micro_sentinel/anomaly_monitor.h"
#include "micro_sentinel/bpf_orchestrator.h"
#include "micro_sentinel/bucket_update.h"
#include "micro_sentinel/clickhouse_sink.h"
#include "micro_sentinel/control_plane.h"
#include "micro_sentinel/config.h"
#include "micro_sentinel/fs_detector.h"
#include "micro_sentinel/monitoring_targets.h"
#include "micro_sentinel/metrics_exporter.h"
#include "micro_sentinel/mode_controller.h"
#include "micro_sentinel/remote_dram_analyzer.h"
#include "micro_sentinel/skew_adjuster.h"
#include "micro_sentinel/tsc_calibrator.h"
#include "micro_sentinel/pmu_rotator.h"
#include "micro_sentinel/perf_consumer.h"
#include "micro_sentinel/symbolizer.h"

namespace micro_sentinel {

class AgentRuntime {
public:
    explicit AgentRuntime(AgentConfig cfg);
    ~AgentRuntime();

    void Start();
    void Stop();

private:
    enum class SafetyLevel { Normal = 0, ShedHeavy = 1 };

    void HandleSample(const Sample &sample, const LbrStack &lbr);
    void HandleAnomaly(const AnomalySignal &signal);
    void FlushLoop();
    void ApplyMode(AgentMode mode);
    void EmitReadySample(Sample sample, LbrStack stack);
    void HandleBucketUpdate(const BucketUpdateRequest &req);
    void HandlePmuConfig(const PmuConfigUpdate &update);
    void HandleJitRegion(const JitRegionRequest &req);
    void HandleDataObject(const DataObjectRequest &req);
    void HandleTargetUpdate(const TargetUpdateRequest &req);
    void MaybeAdjustSafety(double sample_ratio);
    void RunSingleFlushCycle(std::chrono::milliseconds interval);

    AgentConfig cfg_;
    std::shared_ptr<BpfOrchestrator> bpf_;
    std::unique_ptr<PerfConsumer> consumer_;
    std::unique_ptr<Symbolizer> symbolizer_;
    std::unique_ptr<Aggregator> aggregator_;
    std::unique_ptr<FalseSharingDetector> fs_detector_;
    std::unique_ptr<ModeController> mode_controller_;
    std::unique_ptr<AnomalyMonitor> anomaly_monitor_;
    std::unique_ptr<TscCalibrator> tsc_calibrator_;
    std::unique_ptr<PmuRotator> pmu_rotator_;
    std::unique_ptr<SkewAdjuster> skew_adjuster_;
    std::unique_ptr<MonitoringTargetManager> target_manager_;
    std::unique_ptr<RemoteDramAnalyzer> remote_dram_analyzer_;
    bool pmu_rotator_started_{false};
    std::unique_ptr<MetricsExporter> metrics_;
    std::unique_ptr<ClickHouseSink> ch_sink_;
    std::unique_ptr<ControlPlane> control_;
    std::thread flush_thread_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> samples_total_{0};
    AgentMode current_mode_{AgentMode::Sentinel};
    BucketState bucket_state_{};
    std::mutex config_mu_;
    std::atomic<SafetyLevel> safety_level_{SafetyLevel::Normal};
};

} // namespace micro_sentinel
