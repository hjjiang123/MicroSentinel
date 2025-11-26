#include "micro_sentinel/bucket_update.h"

#include <algorithm>

namespace micro_sentinel {

BucketUpdateOutcome ApplyBucketUpdate(const BucketUpdateRequest &req,
                                      AgentMode mode,
                                      BucketState &state)
{
    BucketUpdateOutcome outcome{};
    bool sentinel_changed = false;
    bool diagnostic_changed = false;
    bool drop_changed = false;

    if (req.has_sentinel && req.sentinel_budget > 0) {
        state.sentinel_budget = req.sentinel_budget;
        sentinel_changed = true;
    }

    bool diag_auto_adjusted = false;
    if (req.has_diagnostic && req.diagnostic_budget > 0) {
        state.diagnostic_budget = req.diagnostic_budget;
        diagnostic_changed = true;
    } else if (sentinel_changed && state.diagnostic_budget < state.sentinel_budget) {
        state.diagnostic_budget = state.sentinel_budget;
        diag_auto_adjusted = true;
    }

    if (req.has_hard_drop && req.hard_drop_ns > 0) {
        state.hard_drop_ns = req.hard_drop_ns;
        drop_changed = true;
    }

    uint64_t active_budget = (mode == AgentMode::Sentinel) ? state.sentinel_budget : state.diagnostic_budget;
    outcome.active_budget = active_budget;

    bool active_budget_changed =
        (mode == AgentMode::Sentinel && sentinel_changed) ||
        (mode == AgentMode::Diagnostic && (diagnostic_changed || diag_auto_adjusted));

    outcome.reprogram_required = drop_changed || active_budget_changed;
    return outcome;
}

}
