#pragma once

#include <cstdint>

#include "micro_sentinel/mode_controller.h"

namespace micro_sentinel {

struct BucketUpdateRequest {
    bool has_sentinel{false};
    uint64_t sentinel_budget{0};
    bool has_diagnostic{false};
    uint64_t diagnostic_budget{0};
    bool has_hard_drop{false};
    uint64_t hard_drop_ns{0};
};

struct BucketState {
    uint64_t sentinel_budget{0};
    uint64_t diagnostic_budget{0};
    uint64_t hard_drop_ns{0};
};

struct BucketUpdateOutcome {
    bool reprogram_required{false};
    uint64_t active_budget{0};
};

BucketUpdateOutcome ApplyBucketUpdate(const BucketUpdateRequest &req,
                                      AgentMode mode,
                                      BucketState &state);

}
