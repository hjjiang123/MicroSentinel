#pragma once

#include <iostream>

namespace micro_sentinel {

class ScopeLogger {
public:
    explicit ScopeLogger(const char *name) : name_(name) {
        if (name_)
            std::cout << "[" << name_ << "] enter" << std::endl;
    }
    ~ScopeLogger() {
        if (name_)
            std::cout << "[" << name_ << "] exit" << std::endl;
    }

private:
    const char *name_;
};

} // namespace micro_sentinel

#ifdef MS_SCOPE_LOG
#undef MS_SCOPE_LOG
#endif
#define MS_SCOPE_LOG(tag) ::micro_sentinel::ScopeLogger scope_logger_##__LINE__(tag)
