#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

#include "micro_sentinel/bpf_orchestrator.h"
#include "micro_sentinel/mode_controller.h"

namespace micro_sentinel {

class PmuRotator {
public:
    PmuRotator(std::shared_ptr<BpfOrchestrator> orchestrator,
               std::chrono::milliseconds window,
               std::function<void(double)> on_scale);
    ~PmuRotator();

    void Start(AgentMode initial_mode);
    void Stop();
    void UpdateMode(AgentMode mode);

private:
    void Run();
    void RefreshState();

    std::shared_ptr<BpfOrchestrator> orchestrator_;
    std::chrono::milliseconds window_;
    std::function<void(double)> on_scale_;

    std::atomic<bool> running_{false};
    std::thread worker_;
    std::mutex mu_;
    std::condition_variable cv_;
    AgentMode mode_{AgentMode::Sentinel};
    size_t group_count_{0};
    size_t current_index_{0};
    bool mode_dirty_{false};
};

} // namespace micro_sentinel
