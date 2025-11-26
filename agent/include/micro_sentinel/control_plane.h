#pragma once

#include <atomic>
#include <functional>
#include <string>
#include <thread>

#include "micro_sentinel/bucket_update.h"
#include "micro_sentinel/config.h"
#include "micro_sentinel/control_messages.h"
#include "micro_sentinel/json.h"
#include "micro_sentinel/mode_controller.h"

namespace micro_sentinel {

class ControlPlane {
public:
    explicit ControlPlane(ControlPlaneConfig cfg);
    ~ControlPlane();

    void Start();
    void Stop();

    void SetModeCallback(const std::function<void(AgentMode)> &cb);
    void SetBudgetCallback(const std::function<void(const BucketUpdateRequest &)> &cb);
    void SetPmuConfigCallback(const std::function<void(const PmuConfigUpdate &)> &cb);
    void SetJitRegionCallback(const std::function<void(const JitRegionRequest &)> &cb);
    void SetDataObjectCallback(const std::function<void(const DataObjectRequest &)> &cb);
    void SetTargetCallback(const std::function<void(const TargetUpdateRequest &)> &cb);

private:
    void ServerLoop();
    bool HandleRequest(int client_fd, const std::string &request);
    bool HandleModeRequest(const std::string &body);
    bool HandleBudgetRequest(const std::string &body);
    bool HandlePmuConfigRequest(const std::string &body);
    bool HandleJitRequest(const std::string &body);
    bool HandleDataObjectRequest(const std::string &body);
    bool HandleTargetRequest(const std::string &body);
    static std::string ExtractJsonString(const std::string &body, const std::string &key);
    static uint64_t ExtractJsonUint(const std::string &body, const std::string &key, bool &ok);
    static void SendResponse(int fd, int status, const std::string &body);
    bool ParsePmuConfig(const std::string &body, PmuConfigUpdate &update);
    bool ParsePmuGroups(const class JsonValue &node, std::vector<PmuGroupConfig> &groups);
    static bool ParseEventDesc(const class JsonValue &node, PmuEventDesc &desc);
    bool ParseTargets(const std::string &body, TargetUpdateRequest &req);
    static bool ParseSingleTarget(const class JsonValue &node, TargetSpec &spec);

    ControlPlaneConfig cfg_;
    std::atomic<bool> running_{false};
    std::thread worker_;
    std::function<void(AgentMode)> on_mode_;
    std::function<void(const BucketUpdateRequest &)> on_budget_;
    std::function<void(const PmuConfigUpdate &)> on_pmu_config_;
    std::function<void(const JitRegionRequest &)> on_jit_region_;
    std::function<void(const DataObjectRequest &)> on_data_object_;
    std::function<void(const TargetUpdateRequest &)> on_targets_;
};

} // namespace micro_sentinel
