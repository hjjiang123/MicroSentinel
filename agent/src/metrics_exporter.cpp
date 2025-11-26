#include "micro_sentinel/metrics_exporter.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <sstream>

namespace micro_sentinel {

MetricsExporter::MetricsExporter(MetricsConfig cfg) : cfg_(std::move(cfg)) {}

MetricsExporter::~MetricsExporter() {
    Stop();
}

void MetricsExporter::Start() {
    if (running_.exchange(true))
        return;
    worker_ = std::thread(&MetricsExporter::ServerLoop, this);
}

void MetricsExporter::Stop() {
    if (!running_.exchange(false))
        return;
    if (worker_.joinable())
        worker_.join();
}

void MetricsExporter::SetGauge(const std::string &name, double value) {
    std::lock_guard<std::mutex> lk(mu_);
    gauges_[name] = value;
}

std::string MetricsExporter::RenderMetrics() {
    std::ostringstream oss;
    std::lock_guard<std::mutex> lk(mu_);
    for (const auto &kv : gauges_) {
        oss << kv.first << " " << kv.second << "\n";
    }
    return oss.str();
}

void MetricsExporter::ServerLoop() {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(cfg_.listen_port);
    addr.sin_addr.s_addr = inet_addr(cfg_.listen_address.c_str());

    int enable = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

    if (bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        return;
    }

    if (listen(fd, 8) < 0) {
        ::close(fd);
        return;
    }

    while (running_.load()) {
        sockaddr_in cli{};
        socklen_t len = sizeof(cli);
        int client = accept(fd, reinterpret_cast<sockaddr *>(&cli), &len);
        if (client < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        std::string body = RenderMetrics();
        std::ostringstream resp;
        resp << "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
             << body.size() << "\r\nConnection: close\r\n\r\n" << body;
        auto data = resp.str();
        ::send(client, data.data(), data.size(), 0);
        ::close(client);
    }

    ::close(fd);
}

} // namespace micro_sentinel
