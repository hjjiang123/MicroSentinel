#pragma once

#include <cstdint>
#include <vector>
#include "ms_common.h"

namespace micro_sentinel {

using Sample = ms_sample;
using LbrEntry = ms_lbr_entry;
using LbrStack = std::vector<LbrEntry>;

struct FlowAttribution {
    uint64_t flow_id{0};
    uint64_t weight_numer{0};
    uint64_t weight_denom{1};
};

} // namespace micro_sentinel
