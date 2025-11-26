#include <chrono>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "micro_sentinel/config.h"
#include "micro_sentinel/config_loader.h"
#include "micro_sentinel/runtime.h"

using micro_sentinel::AgentConfig;
using micro_sentinel::AgentRuntime;
using micro_sentinel::AgentMode;

static void PrintUsage(const char *argv0) {
    std::cerr << "Usage: " << argv0 << " [--config=FILE] [--diagnostic|--sentinel]"
              << " [--mode=sentinel|diagnostic]"
              << " [--mock-period-ms=N] [--sentinel-budget=N] [--diagnostic-budget=N]"
              << " [--clickhouse-endpoint=URL] [--metrics-port=N] [--cpus=LIST]"
              << std::endl;
}

int main(int argc, char **argv) {
    AgentConfig cfg;
    std::string config_path;
    std::vector<std::string> deferred_flags;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            PrintUsage(argv[0]);
            return 0;
        }
        if (arg.rfind("--config=", 0) == 0) {
            config_path = arg.substr(strlen("--config="));
            continue;
        }
        deferred_flags.push_back(arg);
    }

    if (!config_path.empty()) {
        std::string error;
        if (!LoadAgentConfigFile(config_path, cfg, error)) {
            std::cerr << "Config error: " << error << std::endl;
            return 1;
        }
    }

    for (const auto &flag : deferred_flags) {
        std::string error;
        if (!ApplyCliFlag(flag, cfg, error)) {
            std::cerr << error << std::endl;
            PrintUsage(argv[0]);
            return 1;
        }
    }

    if (cfg.diagnostic_mode)
        cfg.thresholds.sentinel_to_diag = 0.0;

    AgentRuntime runtime(cfg);
    runtime.Start();

    std::cout << "MicroSentinel agent running. Press Ctrl+C to exit." << std::endl;
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}
