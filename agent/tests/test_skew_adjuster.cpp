#include <cassert>
#include <vector>

#include "micro_sentinel/skew_adjuster.h"

using namespace micro_sentinel;

void RunSkewAdjusterTests() {
    {
        SkewAdjuster adjuster(MS_FLOW_SKID_NS, 4);
        std::vector<Sample> emitted;
        auto emit = [&](Sample &&sample, LbrStack &&) {
            emitted.push_back(sample);
        };

        Sample first{};
        first.cpu = 0;
        first.tsc = 100;
        first.flow_id = 0;
        adjuster.Process(first, {}, emit);
        assert(emitted.empty());

        Sample second{};
        second.cpu = 0;
        second.tsc = 120;
        second.flow_id = 42;
        adjuster.Process(second, {}, emit);
        assert(emitted.size() == 1);
        assert(emitted[0].flow_id == 42);

        adjuster.Flush(emit);
        assert(emitted.size() == 2);
        assert(emitted[1].flow_id == 42);
    }

    {
        SkewAdjuster adjuster(MS_FLOW_SKID_NS, 4);
        std::vector<Sample> emitted;
        auto emit = [&](Sample &&sample, LbrStack &&) {
            emitted.push_back(sample);
        };

        Sample cpu0_a{};
        cpu0_a.cpu = 0;
        cpu0_a.tsc = 1'000;
        cpu0_a.flow_id = 0;
        adjuster.Process(cpu0_a, {}, emit);
        assert(emitted.empty());

        Sample cpu1{};
        cpu1.cpu = 1;
        cpu1.tsc = 1'010;
        cpu1.flow_id = 77;
        adjuster.Process(cpu1, {}, emit);
        assert(emitted.empty());

        Sample cpu0_b{};
        cpu0_b.cpu = 0;
        cpu0_b.tsc = 1'040;
        cpu0_b.flow_id = 99;
        adjuster.Process(cpu0_b, {}, emit);
        assert(emitted.size() == 1);
        assert(emitted[0].cpu == 0);
        assert(emitted[0].flow_id == 99);

        adjuster.Flush(emit);
        assert(emitted.size() == 3);
        assert(emitted[2].cpu == 1);
        assert(emitted[2].flow_id == 77);
    }
}
