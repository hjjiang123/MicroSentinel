#include <cassert>
#include <filesystem>
#include <fstream>

#include "micro_sentinel/monitoring_targets.h"
#include "micro_sentinel/remote_dram_analyzer.h"

using namespace micro_sentinel;

static Sample MakeSample(uint32_t pid, uint16_t ifindex, uint8_t proto, ms_pmu_event_type evt) {
    Sample s{};
    s.pid = pid;
    s.ingress_ifindex = ifindex;
    s.l4_proto = proto;
    s.pmu_event = evt;
    s.tsc = 1000;
    s.numa_node = 1;
    return s;
}

void RunTargetManagerTests() {
    MonitoringTargetManager manager;
    Sample sample = MakeSample(123, 2, 6, MS_EVT_L3_MISS);
    assert(manager.Allow(sample));

    TargetSpec pid_spec;
    pid_spec.type = TargetType::Process;
    pid_spec.pid = 123;
    manager.Update({pid_spec});
    assert(manager.Allow(sample));
    Sample other = MakeSample(999, 2, 6, MS_EVT_L3_MISS);
    assert(!manager.Allow(other));

    TargetSpec flow_spec;
    flow_spec.type = TargetType::Flow;
    flow_spec.flow.ingress_ifindex = 2;
    manager.Update({pid_spec, flow_spec});
    assert(manager.Allow(sample));
    Sample wrong_if = MakeSample(123, 8, 6, MS_EVT_L3_MISS);
    assert(!manager.Allow(wrong_if));

    auto temp_dir = std::filesystem::temp_directory_path() / "ms_target_test";
    std::filesystem::create_directories(temp_dir);
    std::ofstream(temp_dir / "cgroup.procs") << "555\n";
    TargetSpec cg_spec;
    cg_spec.type = TargetType::Cgroup;
    cg_spec.path = temp_dir.string();
    manager.Update({cg_spec});
    Sample cg_sample = MakeSample(555, 1, 17, MS_EVT_L3_MISS);
    assert(manager.Allow(cg_sample));
    std::filesystem::remove(temp_dir / "cgroup.procs");
    std::filesystem::remove(temp_dir);
}

void RunRemoteDramAnalyzerTests() {
    RemoteDramAnalyzer analyzer(1000);
    Sample s = MakeSample(42, 3, 17, MS_EVT_REMOTE_DRAM);
    analyzer.Observe(s);
    bool emitted = false;
    analyzer.Flush(s.tsc + 2000, [&](const RemoteDramFinding &finding) {
        emitted = true;
        assert(finding.flow_id == 0 || finding.flow_id == s.flow_id);
        assert(finding.ifindex == 3);
        assert(finding.samples == 1);
    });
    assert(emitted);
}
