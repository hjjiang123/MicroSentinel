#pragma once

#include <string>

#include "micro_sentinel/config.h"

namespace micro_sentinel {

bool LoadAgentConfigFile(const std::string &path, AgentConfig &cfg, std::string &error);
bool ApplyConfigOverride(const std::string &key, const std::string &value, AgentConfig &cfg, std::string &error);
bool ApplyCliFlag(const std::string &flag, AgentConfig &cfg, std::string &error);

} // namespace micro_sentinel
