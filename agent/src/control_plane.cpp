#include "micro_sentinel/control_plane.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cctype>
#include <cerrno>
#include <cstring>
#include <sstream>

namespace micro_sentinel {

namespace {

constexpr size_t kMaxRequestSize = 8192;

AgentMode ParseMode(const std::string &value, bool &ok) {
    std::string lower;
    lower.reserve(value.size());
    for (char c : value)
        lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    if (lower == "diagnostic" || lower == "diag") {
        ok = true;
        return AgentMode::Diagnostic;
    }
    if (lower == "sentinel") {
        ok = true;
        return AgentMode::Sentinel;
    }
    ok = false;
    return AgentMode::Sentinel;
}

} // namespace

ControlPlane::ControlPlane(ControlPlaneConfig cfg) : cfg_(std::move(cfg)) {}

ControlPlane::~ControlPlane() {
    Stop();
}

void ControlPlane::Start() {
    if (running_.exchange(true))
        return;
    worker_ = std::thread(&ControlPlane::ServerLoop, this);
}

void ControlPlane::Stop() {
    if (!running_.exchange(false))
        return;
    if (worker_.joinable())
        worker_.join();
}

void ControlPlane::SetModeCallback(const std::function<void(AgentMode)> &cb) {
    on_mode_ = cb;
}

void ControlPlane::SetBudgetCallback(const std::function<void(const BucketUpdateRequest &)> &cb) {
    on_budget_ = cb;
}

void ControlPlane::SetPmuConfigCallback(const std::function<void(const PmuConfigUpdate &)> &cb) {
    on_pmu_config_ = cb;
}

void ControlPlane::SetJitRegionCallback(const std::function<void(const JitRegionRequest &)> &cb) {
    on_jit_region_ = cb;
}

void ControlPlane::SetDataObjectCallback(const std::function<void(const DataObjectRequest &)> &cb) {
    on_data_object_ = cb;
}

void ControlPlane::SetTargetCallback(const std::function<void(const TargetUpdateRequest &)> &cb) {
    on_targets_ = cb;
}

void ControlPlane::ServerLoop() {
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

    while (running_.load(std::memory_order_relaxed)) {
        sockaddr_in cli{};
        socklen_t len = sizeof(cli);
        int client = accept(fd, reinterpret_cast<sockaddr *>(&cli), &len);
        if (client < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        char buffer[kMaxRequestSize];
        ssize_t n = recv(client, buffer, sizeof(buffer) - 1, 0);
        if (n <= 0) {
            ::close(client);
            continue;
        }
        buffer[n] = '\0';
        std::string request(buffer);
        bool ok = HandleRequest(client, request);
        if (!ok)
            SendResponse(client, 400, "invalid request");
        ::close(client);
    }

    ::close(fd);
}

bool ControlPlane::HandleRequest(int client_fd, const std::string &request) {
    std::istringstream iss(request);
    std::string line;
    if (!std::getline(iss, line))
        return false;
    std::istringstream first(line);
    std::string method;
    std::string path;
    first >> method >> path;
    if (method != "POST")
        return false;

    auto body_pos = request.find("\r\n\r\n");
    if (body_pos == std::string::npos)
        return false;
    std::string body = request.substr(body_pos + 4);

    bool result = false;
    if (path == "/api/v1/mode")
        result = HandleModeRequest(body);
    else if (path == "/api/v1/token-bucket")
        result = HandleBudgetRequest(body);
    else if (path == "/api/v1/pmu-config")
        result = HandlePmuConfigRequest(body);
    else if (path == "/api/v1/symbols/jit")
        result = HandleJitRequest(body);
    else if (path == "/api/v1/symbols/data")
        result = HandleDataObjectRequest(body);
    else if (path == "/api/v1/targets")
        result = HandleTargetRequest(body);
    else
        return false;

    if (result)
        SendResponse(client_fd, 200, "ok");
    return result;
}

bool ControlPlane::HandleModeRequest(const std::string &body) {
    bool ok = false;
    auto mode_str = ExtractJsonString(body, "mode");
    AgentMode mode = ParseMode(mode_str, ok);
    if (!ok || !on_mode_)
        return false;
    on_mode_(mode);
    return true;
}

bool ControlPlane::HandleBudgetRequest(const std::string &body) {
    if (!on_budget_)
        return false;

    BucketUpdateRequest req;
    bool any = false;
    bool ok = false;

    uint64_t sentinel = ExtractJsonUint(body, "sentinel_samples_per_sec", ok);
    if (ok && sentinel > 0) {
        req.has_sentinel = true;
        req.sentinel_budget = sentinel;
        any = true;
    }

    ok = false;
    uint64_t diag = ExtractJsonUint(body, "diagnostic_samples_per_sec", ok);
    if (ok && diag > 0) {
        req.has_diagnostic = true;
        req.diagnostic_budget = diag;
        any = true;
    }

    ok = false;
    uint64_t hard_drop = ExtractJsonUint(body, "hard_drop_ns", ok);
    if (ok && hard_drop > 0) {
        req.has_hard_drop = true;
        req.hard_drop_ns = hard_drop;
        any = true;
    }

    if (!any) {
        ok = false;
        uint64_t legacy = ExtractJsonUint(body, "samples_per_sec", ok);
        if (!ok || legacy == 0)
            return false;
        req.has_sentinel = true;
        req.sentinel_budget = legacy;
    }

    on_budget_(req);
    return true;
}

bool ControlPlane::HandlePmuConfigRequest(const std::string &body) {
    if (!on_pmu_config_)
        return false;
    PmuConfigUpdate update;
    if (!ParsePmuConfig(body, update))
        return false;
    if (!update.has_sentinel && !update.has_diagnostic)
        return false;
    on_pmu_config_(update);
    return true;
}

bool ControlPlane::HandleJitRequest(const std::string &body) {
    if (!on_jit_region_)
        return false;
    JsonValue root;
    std::string err;
    if (!ParseJson(body, root, err) || !root.IsObject())
        return false;
    const auto &obj = root.AsObject();
    auto pid_it = obj.find("pid");
    auto start_it = obj.find("start");
    auto end_it = obj.find("end");
    auto path_it = obj.find("path");
    if (pid_it == obj.end() || start_it == obj.end() || end_it == obj.end() || path_it == obj.end())
        return false;
    if (!pid_it->second || !start_it->second || !end_it->second || !path_it->second)
        return false;
    if (!pid_it->second->IsNumber() || !start_it->second->IsNumber() || !end_it->second->IsNumber() || !path_it->second->IsString())
        return false;
    JitRegionRequest req;
    req.pid = static_cast<uint32_t>(pid_it->second->AsNumber());
    req.start = static_cast<uint64_t>(start_it->second->AsNumber());
    req.end = static_cast<uint64_t>(end_it->second->AsNumber());
    req.path = path_it->second->AsString();
    auto build_it = obj.find("build_id");
    if (build_it != obj.end() && build_it->second && build_it->second->IsString())
        req.build_id = build_it->second->AsString();
    if (req.pid == 0 || req.start == 0 || req.end <= req.start || req.path.empty())
        return false;
    on_jit_region_(req);
    return true;
}

bool ControlPlane::HandleDataObjectRequest(const std::string &body) {
    if (!on_data_object_)
        return false;
    JsonValue root;
    std::string err;
    if (!ParseJson(body, root, err) || !root.IsObject())
        return false;
    const auto &obj = root.AsObject();
    auto pid_it = obj.find("pid");
    auto addr_it = obj.find("address");
    auto name_it = obj.find("name");
    if (pid_it == obj.end() || addr_it == obj.end() || name_it == obj.end())
        return false;
    if (!pid_it->second || !addr_it->second || !name_it->second)
        return false;
    if (!pid_it->second->IsNumber() || !addr_it->second->IsNumber() || !name_it->second->IsString())
        return false;
    DataObjectRequest req;
    req.pid = static_cast<uint32_t>(pid_it->second->AsNumber());
    req.address = static_cast<uint64_t>(addr_it->second->AsNumber());
    req.name = name_it->second->AsString();
    auto type_it = obj.find("type");
    if (type_it != obj.end() && type_it->second && type_it->second->IsString())
        req.type = type_it->second->AsString();
    auto size_it = obj.find("size");
    if (size_it != obj.end() && size_it->second && size_it->second->IsNumber())
        req.size = static_cast<uint64_t>(size_it->second->AsNumber());
    if (req.pid == 0 || req.address == 0 || req.name.empty())
        return false;
    on_data_object_(req);
    return true;
}

bool ControlPlane::HandleTargetRequest(const std::string &body) {
    if (!on_targets_)
        return false;
    TargetUpdateRequest req;
    if (!ParseTargets(body, req))
        return false;
    on_targets_(req);
    return true;
}

std::string ControlPlane::ExtractJsonString(const std::string &body, const std::string &key) {
    auto key_pos = body.find('"' + key + '"');
    if (key_pos == std::string::npos)
        return {};
    auto colon = body.find(':', key_pos);
    if (colon == std::string::npos)
        return {};
    auto first_quote = body.find('"', colon + 1);
    if (first_quote == std::string::npos)
        return {};
    auto second_quote = body.find('"', first_quote + 1);
    if (second_quote == std::string::npos)
        return {};
    return body.substr(first_quote + 1, second_quote - first_quote - 1);
}

uint64_t ControlPlane::ExtractJsonUint(const std::string &body, const std::string &key, bool &ok) {
    auto key_pos = body.find('"' + key + '"');
    if (key_pos == std::string::npos) {
        ok = false;
        return 0;
    }
    auto colon = body.find(':', key_pos);
    if (colon == std::string::npos) {
        ok = false;
        return 0;
    }
    size_t idx = colon + 1;
    while (idx < body.size() && std::isspace(static_cast<unsigned char>(body[idx])))
        idx++;
    size_t end = idx;
    while (end < body.size() && std::isdigit(static_cast<unsigned char>(body[end])))
        end++;
    if (end == idx) {
        ok = false;
        return 0;
    }
    try {
        uint64_t value = std::stoull(body.substr(idx, end - idx));
        ok = true;
        return value;
    } catch (...) {
        ok = false;
        return 0;
    }
}

void ControlPlane::SendResponse(int fd, int status, const std::string &body) {
    std::ostringstream resp;
    resp << "HTTP/1.1 " << status << "\r\nContent-Type: text/plain\r\nContent-Length: "
         << body.size() << "\r\nConnection: close\r\n\r\n" << body;
    auto data = resp.str();
    ::send(fd, data.data(), data.size(), 0);
}


namespace {

ms_pmu_event_type ParseLogicalEvent(const JsonValue &value, bool &ok) {
    ok = false;
    if (value.IsNumber()) {
        ok = true;
        return static_cast<ms_pmu_event_type>(static_cast<int>(value.AsNumber()));
    }
    if (!value.IsString())
        return MS_EVT_L3_MISS;
    std::string lower = value.AsString();
    for (auto &c : lower)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (lower == "l3_miss") {
        ok = true;
        return MS_EVT_L3_MISS;
    }
    if (lower == "branch_mispred" || lower == "branch") {
        ok = true;
        return MS_EVT_BRANCH_MISPRED;
    }
    if (lower == "icache" || lower == "icache_stall") {
        ok = true;
        return MS_EVT_ICACHE_STALL;
    }
    if (lower == "avx" || lower == "avx_downclock") {
        ok = true;
        return MS_EVT_AVX_DOWNCLOCK;
    }
    if (lower == "stall_backend" || lower == "backend") {
        ok = true;
        return MS_EVT_STALL_BACKEND;
    }
    if (lower == "xsnp_hitm" || lower == "hitm") {
        ok = true;
        return MS_EVT_XSNP_HITM;
    }
    if (lower == "remote_dram" || lower == "remote") {
        ok = true;
        return MS_EVT_REMOTE_DRAM;
    }
    return MS_EVT_L3_MISS;
}

} // namespace

bool ControlPlane::ParsePmuConfig(const std::string &body, PmuConfigUpdate &update) {
    JsonValue root;
    std::string err;
    if (!ParseJson(body, root, err) || !root.IsObject())
        return false;
    const auto &obj = root.AsObject();
    auto sentinel = obj.find("sentinel");
    auto diagnostic = obj.find("diagnostic");
    bool ok = false;
    if (sentinel != obj.end()) {
        if (!sentinel->second || !ParsePmuGroups(*sentinel->second, update.sentinel_groups))
            return false;
        update.has_sentinel = true;
        ok = true;
    }
    if (diagnostic != obj.end()) {
        if (!diagnostic->second || !ParsePmuGroups(*diagnostic->second, update.diagnostic_groups))
            return false;
        update.has_diagnostic = true;
        ok = true;
    }
    return ok;
}

bool ControlPlane::ParsePmuGroups(const JsonValue &node, std::vector<PmuGroupConfig> &groups) {
    if (!node.IsArray())
        return false;
    std::vector<PmuGroupConfig> parsed;
    for (const auto &entry : node.AsArray()) {
        if (!entry || !entry->IsObject())
            return false;
        PmuGroupConfig group;
        const auto &obj = entry->AsObject();
        auto name_it = obj.find("name");
        if (name_it != obj.end() && name_it->second && name_it->second->IsString())
            group.name = name_it->second->AsString();
        auto events_it = obj.find("events");
        if (events_it == obj.end() || !events_it->second || !events_it->second->IsArray())
            return false;
        for (const auto &ev_node : events_it->second->AsArray()) {
            if (!ev_node)
                return false;
            PmuEventDesc desc;
            if (!ParseEventDesc(*ev_node, desc))
                return false;
            group.events.push_back(std::move(desc));
        }
        if (group.events.empty())
            return false;
        parsed.push_back(std::move(group));
    }
    groups = std::move(parsed);
    return true;
}

bool ControlPlane::ParseEventDesc(const JsonValue &node, PmuEventDesc &desc) {
    if (!node.IsObject())
        return false;
    const auto &obj = node.AsObject();
    auto name_it = obj.find("name");
    if (name_it != obj.end() && name_it->second && name_it->second->IsString())
        desc.name = name_it->second->AsString();
    auto type_it = obj.find("type");
    if (type_it != obj.end() && type_it->second && type_it->second->IsNumber())
        desc.type = static_cast<uint32_t>(type_it->second->AsNumber());
    auto config_it = obj.find("config");
    if (config_it != obj.end() && config_it->second && config_it->second->IsNumber())
        desc.config = static_cast<uint64_t>(config_it->second->AsNumber());
    auto period_it = obj.find("sample_period");
    if (period_it != obj.end() && period_it->second && period_it->second->IsNumber())
        desc.sample_period = static_cast<uint64_t>(period_it->second->AsNumber());
    auto precise_it = obj.find("precise");
    if (precise_it != obj.end() && precise_it->second && precise_it->second->IsBool())
        desc.precise = precise_it->second->AsBool();
    auto logical_it = obj.find("logical");
    if (logical_it != obj.end() && logical_it->second) {
        bool ok = false;
        ms_pmu_event_type logical = ParseLogicalEvent(*logical_it->second, ok);
        if (ok)
            desc.logical = logical;
    }
    return true;
}

bool ControlPlane::ParseTargets(const std::string &body, TargetUpdateRequest &req) {
    JsonValue root;
    std::string err;
    if (!ParseJson(body, root, err) || !root.IsObject())
        return false;
    const auto &obj = root.AsObject();
    auto targets_it = obj.find("targets");
    if (targets_it == obj.end() || !targets_it->second || !targets_it->second->IsArray())
        return false;
    TargetUpdateRequest out;
    for (const auto &item : targets_it->second->AsArray()) {
        if (!item)
            continue;
        TargetSpec spec;
        if (!ParseSingleTarget(*item, spec))
            return false;
        out.targets.push_back(spec);
    }
    req = std::move(out);
    return true;
}

bool ControlPlane::ParseSingleTarget(const JsonValue &node, TargetSpec &spec) {
    if (!node.IsObject())
        return false;
    const auto &obj = node.AsObject();
    auto type_it = obj.find("type");
    if (type_it == obj.end() || !type_it->second || !type_it->second->IsString())
        return false;
    std::string type = type_it->second->AsString();
    for (auto &c : type)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (type == "all") {
        spec.type = TargetType::All;
        return true;
    }
    if (type == "cgroup") {
        auto path_it = obj.find("path");
        if (path_it == obj.end() || !path_it->second || !path_it->second->IsString())
            return false;
        spec.type = TargetType::Cgroup;
        spec.path = path_it->second->AsString();
        return true;
    }
    if (type == "process" || type == "pid") {
        auto pid_it = obj.find("pid");
        if (pid_it == obj.end() || !pid_it->second || !pid_it->second->IsNumber())
            return false;
        spec.type = TargetType::Process;
        spec.pid = static_cast<uint32_t>(pid_it->second->AsNumber());
        return true;
    }
    if (type == "flow") {
        spec.type = TargetType::Flow;
        auto if_it = obj.find("ingress_ifindex");
        if (if_it != obj.end() && if_it->second && if_it->second->IsNumber())
            spec.flow.ingress_ifindex = static_cast<uint16_t>(if_it->second->AsNumber());
        auto proto_it = obj.find("l4_proto");
        if (proto_it != obj.end() && proto_it->second && proto_it->second->IsNumber())
            spec.flow.l4_proto = static_cast<uint8_t>(proto_it->second->AsNumber());
        return true;
    }
    return false;
}

} // namespace micro_sentinel
