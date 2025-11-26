#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "micro_sentinel/sample.h"

namespace micro_sentinel {

struct CodeLocation {
    std::string binary;
    std::string function;
    std::string source_file;
    int line{0};
};

struct DataObject {
    std::string mapping;
    uint64_t base{0};
    uint64_t offset{0};
    std::string permissions;
    std::string name;
    std::string type;
    uint64_t size{0};
};

struct DataSymbol {
    uint64_t id{0};
    DataObject object;
};

struct StackTrace {
    uint64_t id{0};
    std::vector<CodeLocation> frames;
};

class Symbolizer {
public:
    CodeLocation Resolve(uint32_t pid, uint64_t ip) const;
    uint64_t InternFunction(uint32_t pid, uint64_t ip);
    uint64_t InternStack(uint32_t pid, uint64_t ip, const LbrStack &lbr);
    uint64_t InternDataObject(uint32_t pid, uint64_t addr, DataObject *out = nullptr);
    DataObject ResolveData(uint32_t pid, uint64_t addr) const;
    std::vector<StackTrace> ConsumeStacks();
    std::vector<DataSymbol> ConsumeDataObjects();
    void DropProcess(uint32_t pid);
    void RegisterJitRegion(uint32_t pid,
                           uint64_t start,
                           uint64_t end,
                           const std::string &path,
                           const std::string &build_id);
    void RegisterDataObject(uint32_t pid,
                            uint64_t address,
                            const std::string &name,
                            const std::string &type,
                            uint64_t size);

private:
    struct MemoryRegion {
        uint64_t start;
        uint64_t end;
        uint64_t file_offset;
        std::string path;
        std::string perms;
    };

    struct OverrideRegion {
        uint64_t start;
        uint64_t end;
        MemoryRegion region;
    };

    struct DataOverride {
        uint64_t start;
        uint64_t end;
        DataObject object;
    };

    struct ProcMapCache {
        std::vector<MemoryRegion> regions;
        uint64_t last_refresh_ns{0};
    };

    struct CodeCacheKey {
        uint32_t pid;
        uint64_t ip;
        bool operator==(const CodeCacheKey &other) const {
            return pid == other.pid && ip == other.ip;
        }
    };

    struct CodeCacheHash {
        std::size_t operator()(const CodeCacheKey &key) const noexcept {
            return std::hash<uint64_t>{}((static_cast<uint64_t>(key.pid) << 32) ^ key.ip);
        }
    };

    mutable std::mutex mu_;
    mutable std::unordered_map<CodeCacheKey, CodeLocation, CodeCacheHash> intern_table_;
    mutable std::unordered_map<uint32_t, ProcMapCache> proc_maps_;
    mutable std::unordered_map<uint64_t, StackTrace> stack_table_;
    mutable std::vector<uint64_t> dirty_stacks_;
    mutable std::unordered_map<uint64_t, DataSymbol> data_table_;
    mutable std::vector<uint64_t> dirty_data_;
    mutable std::unordered_map<uint32_t, std::vector<OverrideRegion>> jit_regions_;
    mutable std::unordered_map<uint32_t, std::vector<DataOverride>> data_overrides_;

    CodeLocation BuildLocation(uint32_t pid, uint64_t ip) const;
    bool RefreshProcMapsLocked(uint32_t pid) const;
    bool MapAddressLocked(uint32_t pid, uint64_t ip, MemoryRegion &region) const;
    bool LookupJitRegionLocked(uint32_t pid, uint64_t ip, MemoryRegion &region) const;
    bool LookupDataOverrideLocked(uint32_t pid, uint64_t addr, DataObject &object) const;
    void MaybeAutoRegisterRegionLocked(uint32_t pid, const MemoryRegion &region) const;
    CodeLocation SymbolizeAddress(const MemoryRegion &region, uint64_t ip) const;
};

} // namespace micro_sentinel
