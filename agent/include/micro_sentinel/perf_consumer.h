#pragma once

#include <atomic>
#include <functional>
#include <thread>
#include <vector>

#ifdef MS_WITH_LIBBPF
extern "C" {
#include <bpf/libbpf.h>
}
#endif

#include "micro_sentinel/config.h"
#include "micro_sentinel/sample.h"

namespace micro_sentinel {

class PerfConsumer {
public:
    explicit PerfConsumer(PerfConsumerConfig cfg);
    ~PerfConsumer();

    void Start(const std::function<void(const Sample &, const LbrStack &)> &cb);
    void Stop();

private:
    struct CpuContext {
        int cpu{-1};
        int node{-1};
        int fd{-1};
        void *mmap_base{nullptr};
        size_t mmap_len{0};
        size_t data_size{0};
        size_t data_mask{0};
    };

    struct Worker {
        int node{-1};
#ifdef MS_WITH_LIBBPF
        int epoll_fd{-1};
#endif
        std::thread thread;
    };

    void RunPerfLoop(size_t worker_idx);
    void RunMockLoop();
    bool InitPerfEvents();
    bool SetupCpuContext(int cpu, size_t worker_idx);
    void TearDownCpuContext(CpuContext &ctx);
    void ClosePerfEvents();
    void DrainCpu(int index);
    void DispatchSample(const void *data, size_t size);
    std::vector<int> ResolveCpus() const;
    size_t NormalizeRingPages(size_t pages) const;
    int CpuToNode(int cpu) const;
    size_t EnsureWorkerForNode(int node);
    void StopWorkers();

    PerfConsumerConfig cfg_;
    std::function<void(const Sample &, const LbrStack &)> callback_;
    std::atomic<bool> running_{false};
    std::vector<Worker> workers_;
    std::thread mock_thread_;

#ifdef MS_WITH_LIBBPF
    std::vector<CpuContext> cpu_ctxs_;
#endif
};

} // namespace micro_sentinel
