#include "micro_sentinel/pmu_rotator.h"

#include <algorithm>

namespace micro_sentinel {

PmuRotator::PmuRotator(std::shared_ptr<BpfOrchestrator> orchestrator,
                       std::chrono::milliseconds window,
                       std::function<void(double)> on_scale)
    : orchestrator_(std::move(orchestrator))
    , window_(window.count() > 0 ? window : std::chrono::milliseconds{5000})
    , on_scale_(std::move(on_scale)) {}

PmuRotator::~PmuRotator() {
    Stop();
}

void PmuRotator::Start(AgentMode initial_mode) {
    if (running_.exchange(true))
        return;
    mode_ = initial_mode;
    RefreshState();
    worker_ = std::thread(&PmuRotator::Run, this);
}

void PmuRotator::Stop() {
    if (!running_.exchange(false))
        return;
    cv_.notify_all();
    if (worker_.joinable())
        worker_.join();
}

void PmuRotator::UpdateMode(AgentMode mode) {
    {
        std::lock_guard<std::mutex> lk(mu_);
        mode_ = mode;
        mode_dirty_ = true;
    }
    RefreshState();
    cv_.notify_all();
}

void PmuRotator::Run() {
    std::unique_lock<std::mutex> lk(mu_);
    while (running_.load(std::memory_order_relaxed)) {
        if (cv_.wait_for(lk, window_, [this] { return !running_.load(std::memory_order_relaxed) || mode_dirty_; })) {
            if (!running_.load(std::memory_order_relaxed))
                break;
            mode_dirty_ = false;
            continue;
        }
        if (group_count_ <= 1)
            continue;
        size_t next = (current_index_ + 1) % group_count_;
        lk.unlock();
        bool ok = orchestrator_ ? orchestrator_->RotateToGroup(next) : false;
        lk.lock();
        if (ok)
            current_index_ = next;
        else if (!ok && orchestrator_)
            RefreshState();
    }
}

void PmuRotator::RefreshState() {
    size_t count = orchestrator_ ? orchestrator_->ActiveGroupCount() : 0;
    size_t index = orchestrator_ ? orchestrator_->CurrentGroupIndex() : 0;
    double scale = count > 0 ? static_cast<double>(std::max<size_t>(1, count)) : 1.0;
    if (on_scale_)
        on_scale_(scale);
    std::lock_guard<std::mutex> lk(mu_);
    group_count_ = count;
    current_index_ = (count == 0) ? 0 : std::min(index, count - 1);
    mode_dirty_ = false;
}

} // namespace micro_sentinel
