#include "micro_sentinel/interference.h"

namespace micro_sentinel {

InterferenceClass ClassifyEvent(ms_pmu_event_type evt) {
    switch (evt) {
    case MS_EVT_L3_MISS:
        return InterferenceClass::DataPath;
    case MS_EVT_BRANCH_MISPRED:
    case MS_EVT_ICACHE_STALL:
        return InterferenceClass::ControlPath;
    case MS_EVT_AVX_DOWNCLOCK:
    case MS_EVT_STALL_BACKEND:
        return InterferenceClass::ExecutionResource;
    case MS_EVT_XSNP_HITM:
    case MS_EVT_REMOTE_DRAM:
        return InterferenceClass::TopologyInterconnect;
    default:
        return InterferenceClass::Unknown;
    }
}

const char *InterferenceClassName(InterferenceClass cls) {
    switch (cls) {
    case InterferenceClass::DataPath:
        return "data_path";
    case InterferenceClass::ControlPath:
        return "control_path";
    case InterferenceClass::ExecutionResource:
        return "execution_resource";
    case InterferenceClass::TopologyInterconnect:
        return "topology";
    case InterferenceClass::Unknown:
    default:
        return "unknown";
    }
}

} // namespace micro_sentinel
