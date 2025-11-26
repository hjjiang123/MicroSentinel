#include "micro_sentinel/config_loader.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <fstream>
#include <limits>
#include <sstream>
#include <unordered_map>
#include <vector>

namespace micro_sentinel {
namespace {

std::string Trim(const std::string &input) {
    auto begin = std::find_if_not(input.begin(), input.end(), [](unsigned char c) { return std::isspace(c); });
    auto end = std::find_if_not(input.rbegin(), input.rend(), [](unsigned char c) { return std::isspace(c); }).base();
    if (begin >= end)
        return {};
    return std::string(begin, end);
}

std::string ToLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

bool ParseBool(const std::string &value, bool &out, std::string &error) {
    auto lowered = ToLower(value);
    if (lowered == "true" || lowered == "1") {
        out = true;
        return true;
    }
    if (lowered == "false" || lowered == "0") {
        out = false;
        return true;
    }
    error = "invalid boolean value: " + value;
    return false;
}

bool ParseUint64(const std::string &value, uint64_t &out, std::string &error) {
    try {
        size_t idx = 0;
        out = std::stoull(value, &idx, 10);
        if (idx != value.size()) {
            error = "invalid integer literal: " + value;
            return false;
        }
        return true;
    } catch (...) {
        error = "invalid integer literal: " + value;
        return false;
    }
}

bool ParseUint32(const std::string &value, uint32_t &out, std::string &error) {
    uint64_t tmp = 0;
    if (!ParseUint64(value, tmp, error))
        return false;
    if (tmp > std::numeric_limits<uint32_t>::max()) {
        error = "integer out of range: " + value;
        return false;
    }
    out = static_cast<uint32_t>(tmp);
    return true;
}

bool ParseDouble(const std::string &value, double &out, std::string &error) {
    try {
        size_t idx = 0;
        out = std::stod(value, &idx);
        if (idx != value.size()) {
            error = "invalid floating-point literal: " + value;
            return false;
        }
        return true;
    } catch (...) {
        error = "invalid floating-point literal: " + value;
        return false;
    }
}

bool ParseCpuList(const std::string &value, std::vector<int> &out, std::string &error) {
    std::vector<int> cpus;
    std::stringstream ss(value);
    std::string token;
    while (std::getline(ss, token, ',')) {
        token = Trim(token);
        if (token.empty())
            continue;
        auto dash = token.find('-');
        if (dash == std::string::npos) {
            uint32_t cpu = 0;
            if (!ParseUint32(token, cpu, error))
                return false;
            cpus.push_back(static_cast<int>(cpu));
        } else {
            std::string start_str = Trim(token.substr(0, dash));
            std::string end_str = Trim(token.substr(dash + 1));
            uint32_t start = 0;
            uint32_t end = 0;
            if (!ParseUint32(start_str, start, error) || !ParseUint32(end_str, end, error))
                return false;
            if (end < start) {
                error = "cpu range end < start: " + token;
                return false;
            }
            for (uint32_t v = start; v <= end; ++v)
                cpus.push_back(static_cast<int>(v));
        }
    }
    if (cpus.empty()) {
        error = "cpu list cannot be empty";
        return false;
    }
    std::sort(cpus.begin(), cpus.end());
    cpus.erase(std::unique(cpus.begin(), cpus.end()), cpus.end());
    out = std::move(cpus);
    return true;
}

bool ApplyConfigKey(const std::string &key_raw, const std::string &value_raw, AgentConfig &cfg, std::string &error) {
    const std::string key = ToLower(Trim(key_raw));
    const std::string value = Trim(value_raw);

    if (key == "diagnostic_mode" || key == "mode") {
        bool diag = cfg.diagnostic_mode;
        if (!ParseBool(value, diag, error))
            return false;
        cfg.diagnostic_mode = diag;
        return true;
    }
    if (key == "sentinel_budget") {
        uint64_t budget = 0;
        if (!ParseUint64(value, budget, error))
            return false;
        cfg.perf.sentinel_sample_budget = budget;
        return true;
    }
    if (key == "diagnostic_budget") {
        uint64_t budget = 0;
        if (!ParseUint64(value, budget, error))
            return false;
        cfg.perf.diagnostic_sample_budget = budget;
        return true;
    }
    if (key == "clickhouse_endpoint") {
        cfg.ch.endpoint = value;
        return true;
    }
    if (key == "clickhouse_table") {
        cfg.ch.table = value;
        return true;
    }
    if (key == "clickhouse_stack_table") {
        cfg.ch.stack_table = value;
        return true;
    }
    if (key == "clickhouse_raw_table") {
        cfg.ch.raw_table = value;
        return true;
    }
    if (key == "clickhouse_flush_ms") {
        uint64_t flush = 0;
        if (!ParseUint64(value, flush, error))
            return false;
        cfg.ch.flush_interval = std::chrono::milliseconds(flush);
        return true;
    }
    if (key == "clickhouse_batch_size") {
        uint64_t batch = 0;
        if (!ParseUint64(value, batch, error))
            return false;
        cfg.ch.batch_size = static_cast<std::size_t>(batch);
        return true;
    }
    if (key == "metrics_port") {
        uint32_t port = 0;
        if (!ParseUint32(value, port, error))
            return false;
        cfg.metrics.listen_port = static_cast<uint16_t>(port);
        return true;
    }
    if (key == "metrics_address") {
        cfg.metrics.listen_address = value;
        return true;
    }
    if (key == "control_address") {
        cfg.control.listen_address = value;
        return true;
    }
    if (key == "agg_window_ns") {
        uint64_t window = 0;
        if (!ParseUint64(value, window, error))
            return false;
        cfg.aggregator.time_window_ns = window;
        return true;
    }
    if (key == "agg_flush_ms") {
        uint64_t flush = 0;
        if (!ParseUint64(value, flush, error))
            return false;
        cfg.aggregator.flush_interval = std::chrono::milliseconds(flush);
        return true;
    }
    if (key == "anomaly_enabled") {
        bool enabled = cfg.anomaly.enabled;
        if (!ParseBool(value, enabled, error))
            return false;
        cfg.anomaly.enabled = enabled;
        return true;
    }
    if (key == "anomaly_interfaces") {
        std::vector<std::string> ifaces;
        std::stringstream ss(value);
        std::string token;
        while (std::getline(ss, token, ',')) {
            token = Trim(token);
            if (!token.empty())
                ifaces.push_back(token);
        }
        cfg.anomaly.interfaces = std::move(ifaces);
        return true;
    }
    if (key == "anomaly_interval_ms") {
        uint64_t ms = 0;
        if (!ParseUint64(value, ms, error))
            return false;
        cfg.anomaly.sample_interval = std::chrono::milliseconds(ms);
        return true;
    }
    if (key == "anomaly_throughput_ratio") {
        double ratio = 0.0;
        if (!ParseDouble(value, ratio, error))
            return false;
        cfg.anomaly.throughput_ratio_trigger = ratio;
        cfg.thresholds.throughput_ratio_trigger = ratio;
        return true;
    }
    if (key == "anomaly_latency_ratio") {
        double ratio = 0.0;
        if (!ParseDouble(value, ratio, error))
            return false;
        cfg.anomaly.latency_ratio_trigger = ratio;
        cfg.thresholds.latency_ratio_trigger = ratio;
        return true;
    }
    if (key == "anomaly_latency_path") {
        cfg.anomaly.latency_probe_path = value;
        return true;
    }
    if (key == "anomaly_throughput_alpha") {
        double alpha = 0.0;
        if (!ParseDouble(value, alpha, error))
            return false;
        cfg.anomaly.throughput_ewma_alpha = alpha;
        return true;
    }
    if (key == "anomaly_latency_alpha") {
        double alpha = 0.0;
        if (!ParseDouble(value, alpha, error))
            return false;
        cfg.anomaly.latency_ewma_alpha = alpha;
        return true;
    }
    if (key == "anomaly_refractory_ms") {
        uint64_t ms = 0;
        if (!ParseUint64(value, ms, error))
            return false;
        cfg.anomaly.refractory_period = std::chrono::milliseconds(ms);
        cfg.thresholds.anomaly_quiet_period = cfg.anomaly.refractory_period;
        return true;
    }
    if (key == "control_port") {
        uint32_t port = 0;
        if (!ParseUint32(value, port, error))
            return false;
        cfg.control.listen_port = static_cast<uint16_t>(port);
        return true;
    }
    if (key == "tsc_calibration_enabled") {
        bool enabled = cfg.tsc_calibration.enabled;
        if (!ParseBool(value, enabled, error))
            return false;
        cfg.tsc_calibration.enabled = enabled;
        return true;
    }
    if (key == "tsc_slope_alpha") {
        double alpha = 0.0;
        if (!ParseDouble(value, alpha, error))
            return false;
        cfg.tsc_calibration.slope_alpha = alpha;
        return true;
    }
    if (key == "tsc_offset_alpha") {
        double alpha = 0.0;
        if (!ParseDouble(value, alpha, error))
            return false;
        cfg.tsc_calibration.offset_alpha = alpha;
        return true;
    }
    if (key == "mock_period_ms") {
        uint64_t mock_period = 0;
        if (!ParseUint64(value, mock_period, error))
            return false;
        cfg.perf.mock_period = std::chrono::milliseconds(mock_period);
        return true;
    }
    if (key == "perf_mock_mode") {
        bool enabled = cfg.perf.mock_mode;
        if (!ParseBool(value, enabled, error))
            return false;
        cfg.perf.mock_mode = enabled;
        return true;
    }
    if (key == "cpus") {
        std::vector<int> cpus;
        if (!ParseCpuList(value, cpus, error))
            return false;
        cfg.perf.cpus = std::move(cpus);
        return true;
    }

    error = "unknown config key: " + key;
    return false;
}

} // namespace

bool LoadAgentConfigFile(const std::string &path, AgentConfig &cfg, std::string &error) {
    std::ifstream in(path);
    if (!in.is_open()) {
        error = "failed to open config file: " + path;
        return false;
    }
    std::string line;
    size_t line_no = 0;
    while (std::getline(in, line)) {
        ++line_no;
        auto trimmed = Trim(line);
        if (trimmed.empty() || trimmed[0] == '#')
            continue;
        auto pos = trimmed.find('=');
        if (pos == std::string::npos) {
            error = "invalid config line " + std::to_string(line_no);
            return false;
        }
        std::string key = trimmed.substr(0, pos);
        std::string value = trimmed.substr(pos + 1);
        if (!ApplyConfigKey(key, value, cfg, error)) {
            error += " (line " + std::to_string(line_no) + ")";
            return false;
        }
    }
    return true;
}

bool ApplyConfigOverride(const std::string &key, const std::string &value, AgentConfig &cfg, std::string &error) {
    return ApplyConfigKey(key, value, cfg, error);
}

bool ApplyCliFlag(const std::string &flag, AgentConfig &cfg, std::string &error) {
    if (flag == "--diagnostic") {
        cfg.diagnostic_mode = true;
        return true;
    }
    if (flag == "--sentinel") {
        cfg.diagnostic_mode = false;
        return true;
    }
    if (flag == "--perf-mock") {
        cfg.perf.mock_mode = true;
        return true;
    }
    if (flag == "--no-perf-mock") {
        cfg.perf.mock_mode = false;
        return true;
    }
    auto eq = flag.find('=');
    if (eq == std::string::npos || flag.rfind("--", 0) != 0) {
        error = "unknown flag: " + flag;
        return false;
    }
    std::string key = flag.substr(2, eq - 2);
    std::string value = flag.substr(eq + 1);
    if (key == "mode") {
        bool diag = false;
        auto lowered = ToLower(Trim(value));
        if (lowered == "diagnostic" || lowered == "diag")
            diag = true;
        else if (lowered == "sentinel")
            diag = false;
        else {
            error = "unknown mode: " + value;
            return false;
        }
        cfg.diagnostic_mode = diag;
        return true;
    }

    static const std::unordered_map<std::string, std::string> alias_map = {
        {"mock-period-ms", "mock_period_ms"},
        {"sentinel-budget", "sentinel_budget"},
        {"diagnostic-budget", "diagnostic_budget"},
        {"clickhouse-endpoint", "clickhouse_endpoint"},
        {"clickhouse-table", "clickhouse_table"},
        {"clickhouse-stack-table", "clickhouse_stack_table"},
        {"clickhouse-raw-table", "clickhouse_raw_table"},
        {"clickhouse-flush-ms", "clickhouse_flush_ms"},
        {"clickhouse-batch-size", "clickhouse_batch_size"},
        {"metrics-port", "metrics_port"},
        {"metrics-address", "metrics_address"},
        {"control-port", "control_port"},
        {"control-address", "control_address"},
        {"agg-window-ns", "agg_window_ns"},
        {"agg-flush-ms", "agg_flush_ms"},
        {"cpus", "cpus"},
        {"perf-mock-mode", "perf_mock_mode"},
        {"tsc-calibration-enabled", "tsc_calibration_enabled"},
        {"tsc-slope-alpha", "tsc_slope_alpha"},
        {"tsc-offset-alpha", "tsc_offset_alpha"},
        {"anomaly-enabled", "anomaly_enabled"},
        {"anomaly-interfaces", "anomaly_interfaces"},
        {"anomaly-interval-ms", "anomaly_interval_ms"},
        {"anomaly-throughput-ratio", "anomaly_throughput_ratio"},
        {"anomaly-latency-ratio", "anomaly_latency_ratio"},
        {"anomaly-latency-path", "anomaly_latency_path"},
        {"anomaly-throughput-alpha", "anomaly_throughput_alpha"},
        {"anomaly-latency-alpha", "anomaly_latency_alpha"},
        {"anomaly-refractory-ms", "anomaly_refractory_ms"}
    };

    auto it = alias_map.find(key);
    if (it == alias_map.end()) {
        error = "unknown flag: " + flag;
        return false;
    }

    return ApplyConfigKey(it->second, value, cfg, error);
}

} // namespace micro_sentinel
