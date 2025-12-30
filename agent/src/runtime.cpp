#include "micro_sentinel/runtime.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <vector>

#include "micro_sentinel/scope_logger.h"
#include "micro_sentinel/bucket_update.h"
#include "micro_sentinel/interference.h"

namespace {

std::string EscapePromLabel(const std::string &value) {
    std::string out;
    out.reserve(value.size());
    for (unsigned char c : value) {
        if (c == '"' || c == '\\')
            out.push_back('\\');
        if (std::iscntrl(c))
            continue;
        out.push_back(static_cast<char>(c));
    }
    if (out.empty())
        return "unknown";
    return out;
}

} // namespace

namespace micro_sentinel {

namespace {

std::string FlowMetricName(uint32_t event) {
    switch (event) {
    case MS_EVT_L3_MISS:
        return "ms_flow_micromiss_rate";
    case MS_EVT_REMOTE_DRAM:
        return "ms_remote_dram_rate";
    case MS_EVT_BRANCH_MISPRED:
        return "ms_branch_mispred_rate";
    case MS_EVT_ICACHE_STALL:
        return "ms_icache_stall_rate";
    case MS_EVT_AVX_DOWNCLOCK:
        return "ms_avx_downclock_rate";
    case MS_EVT_STALL_BACKEND:
        return "ms_backend_stall_rate";
    case MS_EVT_XSNP_HITM:
        return "ms_false_sharing_rate";
    default:
        return "ms_flow_event_norm";
    }
}

std::string DirectionLabel(uint8_t dir) {
    switch (dir) {
    case 0:
        return "rx";
    case 1:
        return "tx";
    default:
        return "unknown";
    }
}

} // namespace

AgentRuntime::AgentRuntime(AgentConfig cfg)
    : cfg_(std::move(cfg))
    , symbolizer_(std::make_unique<Symbolizer>())
    , aggregator_(std::make_unique<Aggregator>(cfg_.aggregator))
    , fs_detector_(std::make_unique<FalseSharingDetector>(symbolizer_.get()))
    , metrics_(std::make_unique<MetricsExporter>(cfg_.metrics))
    , ch_sink_(std::make_unique<ClickHouseSink>(cfg_.ch))
    , control_(std::make_unique<ControlPlane>(cfg_.control))
{
    skew_adjuster_ = std::make_unique<SkewAdjuster>(MS_FLOW_SKID_NS, 4);
    target_manager_ = std::make_unique<MonitoringTargetManager>();
    remote_dram_analyzer_ = std::make_unique<RemoteDramAnalyzer>();
    aggregator_->AttachSymbolizer(symbolizer_.get());
    aggregator_->SetSampleScale(1.0);
    ch_sink_->SetBucketWidth(cfg_.aggregator.time_window_ns);

    if (cfg_.anomaly.throughput_ratio_trigger > 0.0)
        cfg_.thresholds.throughput_ratio_trigger = cfg_.anomaly.throughput_ratio_trigger;
    if (cfg_.anomaly.latency_ratio_trigger > 0.0)
        cfg_.thresholds.latency_ratio_trigger = cfg_.anomaly.latency_ratio_trigger;
    if (cfg_.anomaly.refractory_period.count() > 0)
        cfg_.thresholds.anomaly_quiet_period = cfg_.anomaly.refractory_period;

    mode_controller_ = std::make_unique<ModeController>(cfg_.thresholds);
    if (cfg_.tsc_calibration.enabled)
        tsc_calibrator_ = std::make_unique<TscCalibrator>(cfg_.tsc_calibration);

    bucket_state_.sentinel_budget = cfg_.perf.sentinel_sample_budget;
    bucket_state_.diagnostic_budget = cfg_.perf.diagnostic_sample_budget;
    if (bucket_state_.diagnostic_budget < bucket_state_.sentinel_budget)
        bucket_state_.diagnostic_budget = bucket_state_.sentinel_budget;
    bucket_state_.hard_drop_ns = cfg_.perf.hard_drop_ns;
    cfg_.perf.diagnostic_sample_budget = bucket_state_.diagnostic_budget;

    bpf_ = std::make_shared<BpfOrchestrator>(cfg_.perf);
    if (bpf_->Init()) {
#ifdef MS_WITH_LIBBPF
        std::cout << "[Runtime] BPF orchestrator initialized; real perf sampling enabled" << std::endl;
        cfg_.perf.mock_mode = false;
        cfg_.perf.events_map_fd = bpf_->EventsMapFd();
        pmu_rotator_ = std::make_unique<PmuRotator>(bpf_, cfg_.perf.rotation_window, [this](double scale) {
            if (aggregator_)
                aggregator_->SetSampleScale(scale);
            if (metrics_)
                metrics_->SetGauge("ms_pmu_scale", scale);
        });
#endif

        // Restrict ctx capture to configured interfaces (anomaly_interfaces).
        // When anomaly is disabled, always allow all interfaces.
        if (!bpf_->ConfigureInterfaceFilter(cfg_.anomaly.enabled ? cfg_.anomaly.interfaces
                                                                 : std::vector<std::string>{})) {
            std::cerr << "[Runtime] Failed to configure interface filter" << std::endl;
        }

        bpf_->SyncBudgetConfig(bucket_state_.sentinel_budget,
                               bucket_state_.diagnostic_budget,
                               bucket_state_.hard_drop_ns);
    } else {
        std::cerr << "[Runtime] BPF orchestrator unavailable; enabling mock perf sampling" << std::endl;
        cfg_.perf.mock_mode = true;
    }

    consumer_ = std::make_unique<PerfConsumer>(cfg_.perf);
    current_mode_ = cfg_.diagnostic_mode ? AgentMode::Diagnostic : AgentMode::Sentinel;
    mode_controller_->Force(current_mode_);

    control_->SetModeCallback([this](AgentMode mode) { ApplyMode(mode); });
    control_->SetBudgetCallback([this](const BucketUpdateRequest &req) { HandleBucketUpdate(req); });
    control_->SetPmuConfigCallback([this](const PmuConfigUpdate &update) { HandlePmuConfig(update); });
    control_->SetJitRegionCallback([this](const JitRegionRequest &req) { HandleJitRegion(req); });
    control_->SetDataObjectCallback([this](const DataObjectRequest &req) { HandleDataObject(req); });
    control_->SetTargetCallback([this](const TargetUpdateRequest &req) { HandleTargetUpdate(req); });

    if (cfg_.anomaly.enabled)
        anomaly_monitor_ = std::make_unique<AnomalyMonitor>(cfg_.anomaly);
}

AgentRuntime::~AgentRuntime() {
    Stop();
}

void AgentRuntime::Start() {
    running_.store(true, std::memory_order_relaxed);
    std::cout << "[Runtime] Starting agent runtime (mode="
              << (current_mode_ == AgentMode::Diagnostic ? "Diagnostic" : "Sentinel")
              << ", anomaly=" << (anomaly_monitor_ ? "enabled" : "disabled")
              << ", mock_perf=" << (cfg_.perf.mock_mode ? "true" : "false") << ")" << std::endl;
    metrics_->Start();
    ch_sink_->Start();
    if (control_)
        control_->Start();
    if (anomaly_monitor_)
        anomaly_monitor_->Start([this](const AnomalySignal &signal) { HandleAnomaly(signal); });
    if (bpf_ && bpf_->Ready()) {
        ApplyMode(current_mode_);
        if (pmu_rotator_ && !pmu_rotator_started_) {
            pmu_rotator_->Start(current_mode_);
            pmu_rotator_started_ = true;
        }
    }
    MS_SCOPE_LOG("AgentRuntime::Start::AfterBpfSetup");
    consumer_->Start([this](const Sample &sample, const LbrStack &lbr) { HandleSample(sample, lbr); });
    flush_thread_ = std::thread(&AgentRuntime::FlushLoop, this);
}

void AgentRuntime::Stop() {
    if (consumer_)
        consumer_->Stop();
    if (skew_adjuster_) {
        skew_adjuster_->Flush([this](Sample &&ready, LbrStack &&stack) {
            EmitReadySample(std::move(ready), std::move(stack));
        });
    }

    running_.store(false, std::memory_order_relaxed);
    if (flush_thread_.joinable())
        flush_thread_.join();
    RunSingleFlushCycle(cfg_.aggregator.flush_interval);

    if (pmu_rotator_ && pmu_rotator_started_) {
        pmu_rotator_->Stop();
        pmu_rotator_started_ = false;
    }
    if (anomaly_monitor_)
        anomaly_monitor_->Stop();
    if (ch_sink_)
        ch_sink_->Stop();
    if (control_)
        control_->Stop();
    if (metrics_)
        metrics_->Stop();
}

void AgentRuntime::HandleSample(const Sample &sample, const LbrStack &lbr) {
    // MS_SCOPE_LOG("AgentRuntime::HandleSample");
    Sample normalized = sample;
    if (tsc_calibrator_)
        normalized.tsc = tsc_calibrator_->Normalize(sample.cpu, sample.tsc);

    LbrStack stack_copy = lbr;
    auto emit = [this](Sample &&ready, LbrStack &&stack) {
        EmitReadySample(std::move(ready), std::move(stack));
    };

    if (skew_adjuster_)
        skew_adjuster_->Process(std::move(normalized), std::move(stack_copy), emit);
    else
        emit(std::move(normalized), std::move(stack_copy));
}

void AgentRuntime::EmitReadySample(Sample sample, LbrStack stack) {
    // MS_SCOPE_LOG("AgentRuntime::EmitReadySample");
    if (target_manager_ && !target_manager_->Allow(sample))
        return;
    // MS_SCOPE_LOG("AgentRuntime::EmitReadySample::AfterTargetCheck");
    if (remote_dram_analyzer_)
        remote_dram_analyzer_->Observe(sample);
    double norm = aggregator_->SampleScale();
    if (sample.gso_segs > 1)
        norm /= static_cast<double>(sample.gso_segs);
    if (ch_sink_)
        ch_sink_->EnqueueRawSample(sample, stack, norm);
    aggregator_->AddSample(sample, stack);
    fs_detector_->Observe(sample);
    samples_total_.fetch_add(1, std::memory_order_relaxed);
}

void AgentRuntime::HandleBucketUpdate(const BucketUpdateRequest &req) {
    auto outcome = ApplyBucketUpdate(req, current_mode_, bucket_state_);
    {
        std::lock_guard<std::mutex> lk(config_mu_);
        cfg_.perf.sentinel_sample_budget = bucket_state_.sentinel_budget;
        cfg_.perf.diagnostic_sample_budget = bucket_state_.diagnostic_budget;
        cfg_.perf.hard_drop_ns = bucket_state_.hard_drop_ns;
    }

    if (bpf_ && bpf_->Ready()) {
        bpf_->SyncBudgetConfig(bucket_state_.sentinel_budget,
                               bucket_state_.diagnostic_budget,
                               bucket_state_.hard_drop_ns);
        if (outcome.reprogram_required) {
            bpf_->UpdateSampleBudget(current_mode_,
                                     bucket_state_.sentinel_budget,
                                     bucket_state_.diagnostic_budget,
                                     bucket_state_.hard_drop_ns);
        }
    }
}

void AgentRuntime::HandlePmuConfig(const PmuConfigUpdate &update) {
    bool updated = false;
    {
        std::lock_guard<std::mutex> lk(config_mu_);
        if (update.has_sentinel && !update.sentinel_groups.empty()) {
            cfg_.perf.sentinel_groups = update.sentinel_groups;
            updated = true;
        }
        if (update.has_diagnostic && !update.diagnostic_groups.empty()) {
            cfg_.perf.diagnostic_groups = update.diagnostic_groups;
            updated = true;
        }
    }
    if (!updated || !bpf_ || !bpf_->Ready())
        return;

    bpf_->UpdateGroupConfig(update.has_sentinel ? &cfg_.perf.sentinel_groups : nullptr,
                            update.has_diagnostic ? &cfg_.perf.diagnostic_groups : nullptr);
    if (bpf_->SwitchMode(current_mode_) && pmu_rotator_ && pmu_rotator_started_)
        pmu_rotator_->UpdateMode(current_mode_);
}

void AgentRuntime::HandleJitRegion(const JitRegionRequest &req) {
    if (!symbolizer_)
        return;
    symbolizer_->RegisterJitRegion(req.pid, req.start, req.end, req.path, req.build_id);
}

void AgentRuntime::HandleDataObject(const DataObjectRequest &req) {
    if (!symbolizer_)
        return;
    symbolizer_->RegisterDataObject(req.pid, req.address, req.name, req.type, req.size);
}

void AgentRuntime::HandleTargetUpdate(const TargetUpdateRequest &req) {
    if (!target_manager_)
        return;
    target_manager_->Update(req.targets);
}

void AgentRuntime::MaybeAdjustSafety(double ratio) {
    double high = cfg_.perf.safety_high_watermark;
    double low = cfg_.perf.safety_low_watermark;
    SafetyLevel current = safety_level_.load(std::memory_order_relaxed);
    SafetyLevel desired = current;

    if (high > 0.0 && ratio > high)
        desired = SafetyLevel::ShedHeavy;
    else if (low > 0.0 && ratio < low)
        desired = SafetyLevel::Normal;

    if (desired == current)
        return;

    safety_level_.store(desired, std::memory_order_relaxed);
    size_t limit = (desired == SafetyLevel::ShedHeavy) ? std::max<size_t>(1, cfg_.perf.shed_event_limit) : 0;
    if (bpf_ && bpf_->Ready())
        bpf_->SetMaxEventsPerGroup(limit);
    if (pmu_rotator_ && pmu_rotator_started_)
        pmu_rotator_->UpdateMode(current_mode_);
    if (metrics_)
        metrics_->SetGauge("ms_sampling_throttled", desired == SafetyLevel::ShedHeavy ? 1.0 : 0.0);
}

void AgentRuntime::FlushLoop() {
    const auto interval = cfg_.aggregator.flush_interval;
    while (running_.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(interval);
        RunSingleFlushCycle(interval);
    }
}

void AgentRuntime::RunSingleFlushCycle(std::chrono::milliseconds interval) {
    auto now = std::chrono::steady_clock::now();
    uint64_t now_ns = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count());

    size_t flushed_samples = aggregator_->Flush([&](const AggregationKey &key, const AggregatedValue &value) {
        ch_sink_->Enqueue(key, value);
        std::ostringstream metric_name;
        metric_name << FlowMetricName(key.pmu_event) << "{flow=\"" << key.flow_id
                    << "\",function=\"0x" << std::hex << key.function_hash << std::dec
                    << "\",stack=\"0x" << std::hex << key.callstack_id << std::dec
                    << "\",event=\"" << key.pmu_event
                    << "\",numa=\"" << key.numa_node
                    << "\",direction=\"" << DirectionLabel(key.direction)
                    << "\",class=\"" << InterferenceClassName(static_cast<InterferenceClass>(key.interference_class))
                    << "\",data_object=\"0x" << std::hex << key.data_object_id << std::dec << "\"}";
        metrics_->SetGauge(metric_name.str(), value.norm_cost);
    });

    auto new_stacks = symbolizer_->ConsumeStacks();
    for (const auto &stack : new_stacks)
        ch_sink_->EnqueueStack(stack);

    auto new_objects = symbolizer_->ConsumeDataObjects();
    for (const auto &obj : new_objects)
        ch_sink_->EnqueueDataObject(obj);
    // std::cout<< "Flushed " << flushed_samples << " samples" << std::endl;
    if (flushed_samples > 0) {
        double seconds = static_cast<double>(interval.count()) / 1000.0;
        double samples_per_sec = flushed_samples / seconds;
        metrics_->SetGauge("ms_samples_per_sec", samples_per_sec);
        double budget = (current_mode_ == AgentMode::Sentinel) ? static_cast<double>(cfg_.perf.sentinel_sample_budget)
                                                              : static_cast<double>(cfg_.perf.diagnostic_sample_budget);
        double ratio = budget > 0.0 ? samples_per_sec / budget : 1.0;
        std::cout << "[Runtime] Flush cycle: flushed " << flushed_samples
                  << " samples (" << static_cast<uint64_t>(samples_per_sec)
                  << " samples/sec), budget ratio=" << std::fixed << std::setprecision(3)
                  << ratio << std::endl;
        MaybeAdjustSafety(ratio);
        AgentMode updated = mode_controller_->Update(ratio);
        if (updated != current_mode_)
            ApplyMode(updated);
    }

    fs_detector_->Flush(now_ns, [&](const FalseSharingFinding &finding) {
        std::ostringstream metric_name;
        metric_name << "ms_false_sharing_score{line=\"0x" << std::hex << finding.line_addr
                    << std::dec << "\",mapping=\"" << EscapePromLabel(finding.object.mapping)
                    << "\",pid=\"" << finding.dominant_pid << "\",offset=\"0x" << std::hex
                    << finding.object.offset << std::dec << "\"}";
        metrics_->SetGauge(metric_name.str(), static_cast<double>(finding.total_hits));
    });

    if (remote_dram_analyzer_) {
        remote_dram_analyzer_->Flush(now_ns, [&](const RemoteDramFinding &finding) {
            std::ostringstream metric_name;
            metric_name << "ms_remote_dram_hotspot{flow=\"" << finding.flow_id
                        << "\",numa=\"" << finding.numa_node
                        << "\",ifindex=\"" << finding.ifindex << "\"}";
            metrics_->SetGauge(metric_name.str(), static_cast<double>(finding.samples));
        });
    }

    if (tsc_calibrator_ && metrics_) {
        tsc_calibrator_->Snapshot([&](uint32_t cpu, double slope, double offset) {
            std::ostringstream slope_name;
            slope_name << "ms_tsc_slope{cpu=\"" << cpu << "\"}";
            metrics_->SetGauge(slope_name.str(), slope);
            std::ostringstream offset_name;
            offset_name << "ms_tsc_offset_ns{cpu=\"" << cpu << "\"}";
            metrics_->SetGauge(offset_name.str(), offset);
        });
    }
}

void AgentRuntime::HandleAnomaly(const AnomalySignal &signal) {
    if (!mode_controller_)
        return;
    if (metrics_) {
        switch (signal.type) {
        case AnomalyType::ThroughputDrop:
            metrics_->SetGauge("ms_throughput_ratio", signal.ratio);
            metrics_->SetGauge("ms_throughput_bps", signal.value);
            break;
        case AnomalyType::LatencySpike:
            metrics_->SetGauge("ms_latency_ratio", signal.ratio);
            metrics_->SetGauge("ms_latency_us", signal.value);
            break;
        }
    }
    AgentMode updated = mode_controller_->NotifyAnomaly(signal);
    if (updated != current_mode_)
        ApplyMode(updated);
}

void AgentRuntime::ApplyMode(AgentMode mode) {
    auto ModeName = [](AgentMode m) {
        return (m == AgentMode::Diagnostic) ? "Diagnostic" : "Sentinel";
    };
    AgentMode previous = current_mode_;
    current_mode_ = mode;
    if (previous != mode)
        std::cout << "[Runtime] Transitioning agent mode from " << ModeName(previous)
                  << " to " << ModeName(mode) << std::endl;
    else
        std::cout << "[Runtime] Reapplying agent mode: " << ModeName(mode) << std::endl;
    mode_controller_->Force(mode);
    if (bpf_ && bpf_->Ready()) {
        if (bpf_->SwitchMode(mode) && pmu_rotator_ && pmu_rotator_started_)
            pmu_rotator_->UpdateMode(mode);
    }
    metrics_->SetGauge("ms_agent_mode", mode == AgentMode::Diagnostic ? 1.0 : 0.0);
}

} // namespace micro_sentinel
