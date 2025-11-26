#include "micro_sentinel/clickhouse_sink.h"

#include <arpa/inet.h>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <netdb.h>
#include <sstream>
#include <sys/socket.h>
#include <unistd.h>

namespace {

std::string JsonEscape(const std::string &value) {
    std::string out;
    out.reserve(value.size());
    for (char c : value) {
        switch (c) {
        case '\\':
            out += "\\\\";
            break;
        case '"':
            out += "\\\"";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            out += c;
        }
    }
    return out;
}

} // namespace

namespace micro_sentinel {

ClickHouseSink::ClickHouseSink(ClickHouseConfig cfg) : cfg_(std::move(cfg)) {
    char host[256];
    if (gethostname(host, sizeof(host)) == 0)
        agent_hostname_ = host;
    else
        agent_hostname_ = "unknown";
}

ClickHouseSink::~ClickHouseSink() {
    Stop();
}

void ClickHouseSink::Start() {
    if (running_.exchange(true))
        return;
    worker_ = std::thread(&ClickHouseSink::RunLoop, this);
}

void ClickHouseSink::Stop() {
    if (!running_.exchange(false))
        return;
    if (worker_.joinable())
        worker_.join();
    FlushBatch();
}

void ClickHouseSink::SetBucketWidth(uint64_t ns) {
    bucket_width_ns_ = ns;
}

void ClickHouseSink::Enqueue(const AggregationKey &key, const AggregatedValue &value) {
    bool should_flush = false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        batch_.emplace_back(key, value);
        should_flush = batch_.size() >= cfg_.batch_size;
    }
    if (should_flush)
        FlushBatch();
}

void ClickHouseSink::EnqueueStack(const StackTrace &trace) {
    if (trace.frames.empty())
        return;
    bool should_flush = false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        stack_batch_.push_back(trace);
        should_flush = stack_batch_.size() >= cfg_.batch_size;
    }
    if (should_flush)
        FlushBatch();
}

void ClickHouseSink::EnqueueRawSample(const Sample &sample, const LbrStack &stack, double norm_cost) {
    bool should_flush = false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        raw_batch_.push_back(RawRow{sample, stack, norm_cost});
        should_flush = raw_batch_.size() >= cfg_.batch_size;
    }
    if (should_flush)
        FlushBatch();
}

void ClickHouseSink::EnqueueDataObject(const DataSymbol &symbol) {
    if (symbol.id == 0)
        return;
    bool should_flush = false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        data_batch_.push_back(symbol);
        should_flush = data_batch_.size() >= cfg_.batch_size;
    }
    if (should_flush)
        FlushBatch();
}

void ClickHouseSink::RunLoop() {
    while (running_.load()) {
        std::this_thread::sleep_for(cfg_.flush_interval);
        FlushBatch();
    }
}

bool ClickHouseSink::ParseEndpoint() {
    if (cfg_.endpoint.rfind("http://", 0) != 0)
        return false;
    std::string rest = cfg_.endpoint.substr(7);
    auto slash = rest.find('/');
    std::string host_port = slash == std::string::npos ? rest : rest.substr(0, slash);
    endpoint_.path = slash == std::string::npos ? "/" : rest.substr(slash);
    auto colon = host_port.find(':');
    if (colon == std::string::npos) {
        endpoint_.host = host_port;
        endpoint_.port = 8123;
    } else {
        endpoint_.host = host_port.substr(0, colon);
        endpoint_.port = static_cast<uint16_t>(std::stoi(host_port.substr(colon + 1)));
    }
    endpoint_.valid = !endpoint_.host.empty();
    return endpoint_.valid;
}

bool ClickHouseSink::SendPayload(const std::string &body) {
    if (!endpoint_.valid && !ParseEndpoint())
        return false;

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    std::string port = std::to_string(endpoint_.port);
    addrinfo *res = nullptr;
    if (getaddrinfo(endpoint_.host.c_str(), port.c_str(), &hints, &res) != 0)
        return false;

    int fd = -1;
    for (addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
            break;
        ::close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0)
        return false;

    std::ostringstream req;
    req << "POST " << endpoint_.path << " HTTP/1.1\r\n";
    req << "Host: " << endpoint_.host << "\r\n";
    req << "Content-Type: text/plain\r\n";
    req << "Content-Length: " << body.size() << "\r\n";
    req << "Connection: close\r\n\r\n";
    req << body;
    std::string data = req.str();
    size_t sent = 0;
    while (sent < data.size()) {
        ssize_t n = ::send(fd, data.data() + sent, data.size() - sent, 0);
        if (n <= 0) {
            ::close(fd);
            return false;
        }
        sent += static_cast<size_t>(n);
    }
    char buf[256];
    ssize_t n = ::recv(fd, buf, sizeof(buf) - 1, 0);
    ::close(fd);
    if (n <= 0)
        return false;
    buf[n] = '\0';
    return std::string(buf).find("200") != std::string::npos;
}

void ClickHouseSink::FlushBatch() {
    std::vector<std::pair<AggregationKey, AggregatedValue>> pending;
    std::vector<StackTrace> stack_pending;
    std::vector<RawRow> raw_pending;
    std::vector<DataSymbol> data_pending;

    {
        std::lock_guard<std::mutex> lk(mu_);
        pending.swap(batch_);
        stack_pending.swap(stack_batch_);
        raw_pending.swap(raw_batch_);
        data_pending.swap(data_batch_);
    }
    if (!pending.empty()) {
        std::ostringstream payload;
        payload << "INSERT INTO " << cfg_.table << " FORMAT JSONEachRow\n";
        for (const auto &kv : pending) {
            uint64_t bucket_start_ns = kv.first.bucket * bucket_width_ns_;
            double window_start = static_cast<double>(bucket_start_ns) / 1'000'000'000.0;
            payload << '{'
                    << "\"window_start\":" << std::fixed << std::setprecision(9) << window_start << ','
                    << "\"host\":\"" << JsonEscape(agent_hostname_) << "\"," 
                    << "\"flow_id\":" << kv.first.flow_id << ','
                    << "\"function_id\":" << kv.first.function_hash << ','
                    << "\"callstack_id\":" << kv.first.callstack_id << ','
                    << "\"pmu_event\":" << kv.first.pmu_event << ','
                    << "\"numa_node\":" << kv.first.numa_node << ','
                    << "\"direction\":" << static_cast<uint32_t>(kv.first.direction) << ','
                    << "\"interference_class\":" << static_cast<uint32_t>(kv.first.interference_class) << ','
                    << "\"data_object_id\":" << kv.first.data_object_id << ','
                    << "\"samples\":" << kv.second.samples << ','
                    << "\"norm_cost\":" << kv.second.norm_cost
                    << "}\n";
        }

        if (!SendPayload(payload.str()))
            std::cerr << "Failed to flush ClickHouse batch" << std::endl;
    }

    if (!stack_pending.empty()) {
        std::ostringstream payload;
        payload << "INSERT INTO " << cfg_.stack_table << " FORMAT JSONEachRow\n";
        for (const auto &trace : stack_pending) {
            payload << '{'
                    << "\"stack_id\":" << trace.id << ','
                    << "\"host\":\"" << JsonEscape(agent_hostname_) << "\"," 
                    << "\"frames\":[";
            for (size_t i = 0; i < trace.frames.size(); ++i) {
                const auto &frame = trace.frames[i];
                if (i > 0)
                    payload << ',';
                payload << '{'
                        << "\"binary\":\"" << JsonEscape(frame.binary) << "\"," 
                        << "\"function\":\"" << JsonEscape(frame.function) << "\"," 
                        << "\"file\":\"" << JsonEscape(frame.source_file) << "\"," 
                        << "\"line\":" << frame.line
                        << "}";
            }
            payload << "]}\n";
        }

        if (!SendPayload(payload.str()))
            std::cerr << "Failed to flush ClickHouse stack batch" << std::endl;
    }

    if (!raw_pending.empty()) {
        std::ostringstream payload;
        payload << "INSERT INTO " << cfg_.raw_table << " FORMAT JSONEachRow\n";
        for (const auto &entry : raw_pending) {
            const Sample &s = entry.sample;
            const LbrStack &stack = entry.stack;
            double ts = static_cast<double>(s.tsc) / 1'000'000'000.0;
            payload << '{'
                    << "\"ts\":" << std::fixed << std::setprecision(9) << ts << ','
                    << "\"host\":\"" << JsonEscape(agent_hostname_) << "\"," 
                    << "\"cpu\":" << s.cpu << ','
                    << "\"pid\":" << s.pid << ','
                    << "\"tid\":" << s.tid << ','
                    << "\"flow_id\":" << s.flow_id << ','
                    << "\"pmu_event\":" << s.pmu_event << ','
                    << "\"ip\":" << s.ip << ','
                    << "\"data_addr\":" << s.data_addr << ','
                    << "\"gso_segs\":" << s.gso_segs << ','
                    << "\"ifindex\":" << s.ingress_ifindex << ','
                    << "\"direction\":" << static_cast<uint32_t>(s.direction) << ','
                    << "\"numa_node\":" << s.numa_node << ','
                    << "\"l4_proto\":" << static_cast<uint32_t>(s.l4_proto) << ','
                    << "\"norm_cost\":" << entry.norm_cost << ','
                    << "\"lbr\":[";
            for (size_t i = 0; i < stack.size(); ++i) {
                if (i > 0)
                    payload << ',';
                payload << '[' << stack[i].from << ',' << stack[i].to << ']';
            }
            payload << "]}\n";
        }

        if (!SendPayload(payload.str()))
            std::cerr << "Failed to flush raw ClickHouse batch" << std::endl;
    }

    if (!data_pending.empty()) {
        std::ostringstream payload;
        payload << "INSERT INTO " << cfg_.data_table << " FORMAT JSONEachRow\n";
        for (const auto &symbol : data_pending) {
                payload << '{'
                    << "\"object_id\":" << symbol.id << ','
                    << "\"host\":\"" << JsonEscape(agent_hostname_) << "\"," 
                    << "\"mapping\":\"" << JsonEscape(symbol.object.mapping) << "\"," 
                    << "\"base\":" << symbol.object.base << ','
                    << "\"size\":" << symbol.object.size << ','
                    << "\"permissions\":\"" << JsonEscape(symbol.object.permissions) << "\"}\n";
        }

        if (!SendPayload(payload.str()))
            std::cerr << "Failed to flush ClickHouse data object batch" << std::endl;
    }
}

} // namespace micro_sentinel
