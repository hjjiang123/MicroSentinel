#include "micro_sentinel/perf_consumer.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <errno.h>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <thread>

#ifdef MS_WITH_LIBBPF
extern "C" {
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/perf_event.h>
}
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace micro_sentinel {

namespace {

constexpr size_t kDefaultRingPages = 8;

#ifdef MS_WITH_LIBBPF
int PerfEventOpen(perf_event_attr *attr, int pid, int cpu, int group_fd, unsigned long flags) {
    return static_cast<int>(syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags));
}
#endif

std::vector<int> ParseCpuList() {
    std::ifstream in("/sys/devices/system/cpu/online");
    std::string line;
    if (!std::getline(in, line) || line.empty())
        return {0};

    std::vector<int> cpus;
    size_t pos = 0;
    while (pos < line.size()) {
        size_t comma = line.find(',', pos);
        std::string token = line.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
        size_t dash = token.find('-');
        if (dash == std::string::npos) {
            cpus.push_back(std::stoi(token));
        } else {
            int start = std::stoi(token.substr(0, dash));
            int end = std::stoi(token.substr(dash + 1));
            for (int cpu = start; cpu <= end; ++cpu)
                cpus.push_back(cpu);
        }
        if (comma == std::string::npos)
            break;
        pos = comma + 1;
    }
    std::sort(cpus.begin(), cpus.end());
    cpus.erase(std::unique(cpus.begin(), cpus.end()), cpus.end());
    if (cpus.empty())
        cpus.push_back(0);
    return cpus;
}

} // namespace

PerfConsumer::PerfConsumer(PerfConsumerConfig cfg) : cfg_(std::move(cfg)) {}

PerfConsumer::~PerfConsumer() {
    Stop();
}

void PerfConsumer::Start(const std::function<void(const Sample &, const LbrStack &)> &cb) {
    callback_ = cb;
    running_.store(true, std::memory_order_relaxed);

#ifdef MS_WITH_LIBBPF
    if (!cfg_.mock_mode && InitPerfEvents()) {
        for (size_t i = 0; i < workers_.size(); ++i) {
            workers_[i].thread = std::thread(&PerfConsumer::RunPerfLoop, this, i);
        }
        if (!workers_.empty())
            return;
    }
#endif

    cfg_.mock_mode = true;
    mock_thread_ = std::thread(&PerfConsumer::RunMockLoop, this);
}

void PerfConsumer::Stop() {
    bool expected = true;
    if (!running_.compare_exchange_strong(expected, false))
        running_.store(false, std::memory_order_relaxed);
    if (mock_thread_.joinable())
        mock_thread_.join();

#ifdef MS_WITH_LIBBPF
    StopWorkers();
    ClosePerfEvents();
#endif
}

void PerfConsumer::RunPerfLoop(size_t worker_idx) {
#ifdef MS_WITH_LIBBPF
    if (worker_idx >= workers_.size())
        return;
    auto &worker = workers_[worker_idx];
    if (worker.epoll_fd < 0)
        return;

    constexpr int kMaxEvents = 16;
    epoll_event events[kMaxEvents];
    while (running_.load(std::memory_order_relaxed)) {
        int n = epoll_wait(worker.epoll_fd, events, kMaxEvents, 250);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            std::perror("epoll_wait");
            break;
        }
        if (n == 0)
            continue;
        for (int i = 0; i < n; ++i) {
            int idx = static_cast<int>(events[i].data.u32);
            DrainCpu(idx);
        }
    }
#else
    (void)worker_idx;
#endif
}

bool PerfConsumer::InitPerfEvents() {
#ifdef MS_WITH_LIBBPF
    if (cfg_.events_map_fd < 0)
        return false;

    auto cpus = ResolveCpus();
    if (cpus.empty())
        return false;

    bool any = false;
    if (!cfg_.numa_workers)
        EnsureWorkerForNode(-1);

    for (int cpu : cpus) {
        size_t worker_idx = 0;
        if (cfg_.numa_workers)
            worker_idx = EnsureWorkerForNode(CpuToNode(cpu));
        else
            worker_idx = EnsureWorkerForNode(-1);
        if (worker_idx == static_cast<size_t>(-1))
            continue;
        any |= SetupCpuContext(cpu, worker_idx);
    }

    if (!any) {
        ClosePerfEvents();
        return false;
    }
    return true;
#else
    return false;
#endif
}

void PerfConsumer::RunMockLoop() {
    std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<uint32_t> flow_dist(1, 1'000'000);
    std::uniform_int_distribution<uint32_t> pmu_dist(MS_EVT_L3_MISS, MS_EVT_REMOTE_DRAM);

    while (running_.load(std::memory_order_relaxed)) {
        Sample sample{};
        sample.tsc = static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
        sample.cpu = 0;
        sample.pid = 42;
        sample.tid = 42;
        sample.pmu_event = pmu_dist(rng);
        sample.ip = 0x1;
        sample.data_addr = 0x1000;
        sample.flow_id = flow_dist(rng);
        sample.gso_segs = 1;
        sample.ingress_ifindex = 1;
        sample.l4_proto = 6;
        if (callback_)
            callback_(sample, {});
        std::this_thread::sleep_for(cfg_.mock_period);
    }
}

#ifdef MS_WITH_LIBBPF
bool PerfConsumer::SetupCpuContext(int cpu, size_t worker_idx) {
    if (worker_idx == static_cast<size_t>(-1) || worker_idx >= workers_.size())
        return false;
    auto &worker = workers_[worker_idx];
    if (worker.epoll_fd < 0)
        return false;

    perf_event_attr attr{};
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_BPF_OUTPUT;
    attr.sample_type = PERF_SAMPLE_RAW;
    attr.wakeup_events = 1;
    attr.sample_period = 1;
    attr.disabled = 0;

    int fd = PerfEventOpen(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd < 0) {
        std::perror("perf_event_open");
        return false;
    }

    size_t pages = NormalizeRingPages(cfg_.ring_pages);
    size_t page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    size_t mmap_len = (pages + 1ULL) * page_size;
    void *base = mmap(nullptr, mmap_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        std::perror("mmap");
        close(fd);
        return false;
    }

    __u32 key = static_cast<__u32>(cpu);
    if (bpf_map_update_elem(cfg_.events_map_fd, &key, &fd, BPF_ANY) < 0) {
        std::perror("bpf_map_update_elem(ms_events)");
        munmap(base, mmap_len);
        close(fd);
        return false;
    }

    size_t ctx_index = cpu_ctxs_.size();

    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.u32 = static_cast<__u32>(ctx_index);
    if (epoll_ctl(worker.epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        std::perror("epoll_ctl");
        int reset = -1;
        bpf_map_update_elem(cfg_.events_map_fd, &key, &reset, BPF_ANY);
        munmap(base, mmap_len);
        close(fd);
        return false;
    }

    CpuContext ctx;
    ctx.cpu = cpu;
    ctx.node = worker.node;
    ctx.fd = fd;
    ctx.mmap_base = base;
    ctx.mmap_len = mmap_len;
    ctx.data_size = pages * page_size;
    ctx.data_mask = ctx.data_size - 1ULL;
    cpu_ctxs_.push_back(ctx);
    return true;
}

void PerfConsumer::DrainCpu(int index) {
    if (index < 0 || static_cast<size_t>(index) >= cpu_ctxs_.size())
        return;
    auto &ctx = cpu_ctxs_[index];
    if (!ctx.mmap_base)
        return;

    auto *meta = reinterpret_cast<perf_event_mmap_page *>(ctx.mmap_base);
    auto *data = reinterpret_cast<char *>(ctx.mmap_base) + sysconf(_SC_PAGESIZE);

    while (true) {
        uint64_t head = __atomic_load_n(&meta->data_head, __ATOMIC_ACQUIRE);
        uint64_t tail = meta->data_tail;
        if (tail == head)
            break;

        auto *record = reinterpret_cast<perf_event_header *>(data + (tail & ctx.data_mask));
        if (record->size == 0)
            break;

        if (record->type == PERF_RECORD_SAMPLE) {
            void *payload = record + 1;
            size_t payload_size = record->size - sizeof(*record);
            DispatchSample(payload, payload_size);
        } else if (record->type == PERF_RECORD_LOST) {
            struct LostPayload {
                uint64_t id;
                uint64_t lost;
            };
            auto *lost = reinterpret_cast<const LostPayload *>(record + 1);
            std::cerr << "Perf buffer lost " << (lost ? lost->lost : 0) << " samples on CPU " << ctx.cpu << std::endl;
        }

        tail += record->size;
        meta->data_tail = tail;
        __atomic_thread_fence(__ATOMIC_RELEASE);
    }
}

void PerfConsumer::DispatchSample(const void *data, size_t size) {
    if (!callback_ || size < sizeof(Sample))
        return;
    Sample sample{};
    std::memcpy(&sample, data, std::min<size_t>(sizeof(Sample), size));
    LbrStack stack;
    if (sample.lbr_nr > 0 && sample.lbr_nr <= MS_LBR_MAX) {
        stack.resize(sample.lbr_nr);
        for (size_t i = 0; i < stack.size(); ++i)
            stack[i] = sample.lbr[i];
    }
    callback_(sample, stack);
}

void PerfConsumer::TearDownCpuContext(CpuContext &ctx) {
    if (ctx.fd >= 0) {
        __u32 key = static_cast<__u32>(ctx.cpu);
        int dummy = -1;
        if (cfg_.events_map_fd >= 0)
            bpf_map_update_elem(cfg_.events_map_fd, &key, &dummy, BPF_ANY);
        close(ctx.fd);
        ctx.fd = -1;
    }
    if (ctx.mmap_base && ctx.mmap_len)
        munmap(ctx.mmap_base, ctx.mmap_len);
    ctx.mmap_base = nullptr;
    ctx.mmap_len = 0;
}

void PerfConsumer::ClosePerfEvents() {
#ifdef MS_WITH_LIBBPF
    for (auto &ctx : cpu_ctxs_)
        TearDownCpuContext(ctx);
    cpu_ctxs_.clear();
    for (auto &worker : workers_) {
        if (worker.epoll_fd >= 0) {
            close(worker.epoll_fd);
            worker.epoll_fd = -1;
        }
    }
    workers_.clear();
#endif
}

size_t PerfConsumer::EnsureWorkerForNode(int node) {
#ifdef MS_WITH_LIBBPF
    for (size_t i = 0; i < workers_.size(); ++i) {
        if (workers_[i].node == node)
            return i;
    }
    Worker worker;
    worker.node = node;
    worker.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (worker.epoll_fd < 0) {
        std::perror("epoll_create1");
        return static_cast<size_t>(-1);
    }
    workers_.push_back(std::move(worker));
    return workers_.size() - 1;
#else
    (void)node;
    return static_cast<size_t>(-1);
#endif
}

void PerfConsumer::StopWorkers() {
#ifdef MS_WITH_LIBBPF
    for (auto &worker : workers_) {
        if (worker.thread.joinable())
            worker.thread.join();
    }
#endif
}

int PerfConsumer::CpuToNode(int cpu) const {
    if (cpu < 0)
        return -1;
    std::ostringstream path;
    path << "/sys/devices/system/cpu/cpu" << cpu << "/topology/physical_package_id";
    std::ifstream in(path.str());
    int node = -1;
    if (in.good())
        in >> node;
    return node;
}

std::vector<int> PerfConsumer::ResolveCpus() const {
    if (!cfg_.cpus.empty())
        return cfg_.cpus;
    return ParseCpuList();
}

size_t PerfConsumer::NormalizeRingPages(size_t pages) const {
    if (pages == 0)
        pages = kDefaultRingPages;
    size_t normalized = 1;
    while (normalized < pages)
        normalized <<= 1;
    return normalized;
}
#endif

} // namespace micro_sentinel
