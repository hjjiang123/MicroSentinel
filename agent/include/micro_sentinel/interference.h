#pragma once

#include <cstdint>

#include "ms_common.h"

namespace micro_sentinel {

enum class InterferenceClass : uint8_t {
    DataPath = 0,
    ControlPath = 1,
    ExecutionResource = 2,
    TopologyInterconnect = 3,
    Unknown = 255
};

InterferenceClass ClassifyEvent(ms_pmu_event_type evt);
const char *InterferenceClassName(InterferenceClass cls);

} // namespace micro_sentinel
