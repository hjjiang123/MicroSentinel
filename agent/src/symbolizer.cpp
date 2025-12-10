#include "micro_sentinel/symbolizer.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <sstream>
#include <iostream>

namespace micro_sentinel {

namespace {

uint64_t NowNs() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                     std::chrono::steady_clock::now().time_since_epoch())
                                     .count());
}

constexpr uint64_t kMapsTtlNs = 5'000'000'000ULL; // 5 seconds

} // namespace

static std::string ReadComm(uint32_t pid) {
    std::filesystem::path comm = std::filesystem::path("/proc") / std::to_string(pid) / "comm";
    std::ifstream in(comm);
    std::string name;
    if (in.good())
        std::getline(in, name);
    return name.empty() ? std::string("unknown") : name;
}

bool Symbolizer::RefreshProcMapsLocked(uint32_t pid) const {
    std::filesystem::path maps_path = std::filesystem::path("/proc") / std::to_string(pid) / "maps";
    std::ifstream maps(maps_path);
    if (!maps.good())
        return false;
    std::vector<MemoryRegion> regions;
    std::string line;
    while (std::getline(maps, line)) {
        if (line.empty())
            continue;
        std::istringstream iss(line);
        std::string range;
        std::string perms;
        std::string offset_hex;
        std::string dev;
        std::string inode;
        if (!(iss >> range >> perms >> offset_hex >> dev >> inode))
            continue;
        std::string path;
        std::getline(iss, path);
        if (!path.empty()) {
            auto first = path.find_first_not_of(' ');
            if (first != std::string::npos)
                path.erase(0, first);
        }
        if (path.empty())
            continue;
        auto dash = range.find('-');
        if (dash == std::string::npos)
            continue;
        uint64_t start = std::stoull(range.substr(0, dash), nullptr, 16);
        uint64_t end = std::stoull(range.substr(dash + 1), nullptr, 16);
        uint64_t file_off = std::stoull(offset_hex, nullptr, 16);
        regions.push_back(MemoryRegion{start, end, file_off, path, perms});
    }
    ProcMapCache cache;
    cache.regions = std::move(regions);
    cache.last_refresh_ns = NowNs();
    proc_maps_[pid] = std::move(cache);
    return true;
}

bool Symbolizer::LookupJitRegionLocked(uint32_t pid, uint64_t ip, MemoryRegion &region) const {
    auto it = jit_regions_.find(pid);
    if (it == jit_regions_.end())
        return false;
    for (const auto &override_region : it->second) {
        if (ip >= override_region.start && ip < override_region.end) {
            region = override_region.region;
            return true;
        }
    }
    return false;
}

bool Symbolizer::LookupDataOverrideLocked(uint32_t pid, uint64_t addr, DataObject &object) const {
    auto it = data_overrides_.find(pid);
    if (it == data_overrides_.end())
        return false;
    for (const auto &entry : it->second) {
        if (addr >= entry.start && addr < entry.end) {
            object = entry.object;
            object.base = entry.start;
            object.offset = addr - entry.start;
            if (entry.end > entry.start)
                object.size = entry.end - entry.start;
            return true;
        }
    }
    return false;
}

bool Symbolizer::MapAddressLocked(uint32_t pid, uint64_t ip, MemoryRegion &region) const {
    if (LookupJitRegionLocked(pid, ip, region))
        return true;
    auto now = NowNs();
    auto it = proc_maps_.find(pid);
    if (it == proc_maps_.end() || it->second.regions.empty() || now - it->second.last_refresh_ns > kMapsTtlNs) {
        if (!RefreshProcMapsLocked(pid))
            return false;
        it = proc_maps_.find(pid);
        if (it == proc_maps_.end())
            return false;
    }
    for (const auto &entry : it->second.regions) {
        if (ip >= entry.start && ip < entry.end) {
            region = entry;
            return true;
        }
    }
    if (!RefreshProcMapsLocked(pid))
        return false;
    it = proc_maps_.find(pid);
    if (it == proc_maps_.end())
        return false;
    for (const auto &entry : it->second.regions) {
        if (ip >= entry.start && ip < entry.end) {
            region = entry;
            return true;
        }
    }
    return false;
}

CodeLocation Symbolizer::SymbolizeAddress(const MemoryRegion &region, uint64_t ip) const {
    CodeLocation loc;
    loc.binary = region.path;
    uint64_t rel = region.file_offset + (ip - region.start);
    std::ostringstream cmd;
    cmd << "addr2line -C -f -e \"" << region.path << "\" 0x" << std::hex << rel;
    std::array<char, 512> buffer{};
    FILE *pipe = popen(cmd.str().c_str(), "r");
    if (!pipe) {
        loc.function = "0x" + [&]() {
            std::ostringstream tmp;
            tmp << std::hex << ip;
            return tmp.str();
        }();
        loc.source_file = region.path;
        return loc;
    }
    if (fgets(buffer.data(), buffer.size(), pipe)) {
        std::string fn(buffer.data());
        fn.erase(fn.find_last_not_of("\r\n") + 1);
        loc.function = fn;
    }
    if (fgets(buffer.data(), buffer.size(), pipe)) {
        std::string file_line(buffer.data());
        file_line.erase(file_line.find_last_not_of("\r\n") + 1);
        auto colon = file_line.rfind(':');
        if (colon != std::string::npos) {
            loc.source_file = file_line.substr(0, colon);
            std::string line_part = file_line.substr(colon + 1);
            auto first_digit = line_part.find_first_not_of(' ');
            if (first_digit != std::string::npos)
                line_part.erase(0, first_digit);
            char *endptr = nullptr;
            long parsed = std::strtol(line_part.c_str(), &endptr, 10);
            if (endptr && endptr != line_part.c_str())
                loc.line = static_cast<int>(parsed);
        } else {
            loc.source_file = file_line;
        }
    }
    pclose(pipe);
    if (loc.function.empty()) {
        std::ostringstream oss;
        oss << "0x" << std::hex << ip;
        loc.function = oss.str();
    }
    if (loc.source_file.empty())
        loc.source_file = region.path;
    return loc;
}

CodeLocation Symbolizer::BuildLocation(uint32_t pid, uint64_t ip) const {
    MemoryRegion region{};
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (!MapAddressLocked(pid, ip, region)) {
            CodeLocation fallback;
            fallback.binary = ReadComm(pid);
            std::ostringstream oss;
            oss << "0x" << std::hex << ip;
            fallback.function = oss.str();
            fallback.source_file = "<unknown>";
            return fallback;
        }
    }
    return SymbolizeAddress(region, ip);
}

CodeLocation Symbolizer::Resolve(uint32_t pid, uint64_t ip) const {
    CodeCacheKey key{pid, ip};
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = intern_table_.find(key);
        if (it != intern_table_.end())
            return it->second;
    }

    CodeLocation loc = BuildLocation(pid, ip);

    {
        std::lock_guard<std::mutex> lk(mu_);
        intern_table_.try_emplace(key, loc);
    }

    return loc;
}

static uint64_t HashString(const std::string &data, uint64_t fallback) {
    uint64_t digest = std::hash<std::string>{}(data);
    if (digest != 0)
        return digest;
    return fallback ? fallback : 1ULL;
}

uint64_t Symbolizer::InternFunction(uint32_t pid, uint64_t ip) {
    CodeLocation loc = Resolve(pid, ip);
    std::ostringstream oss;
    oss << loc.binary << '|' << loc.function << '|' << loc.source_file << ':' << loc.line;
    return HashString(oss.str(), ip);
}

uint64_t Symbolizer::InternStack(uint32_t pid, uint64_t ip, const LbrStack &lbr) {
    std::vector<CodeLocation> frames;
    frames.reserve(1 + lbr.size());
    frames.push_back(Resolve(pid, ip));
    for (const auto &edge : lbr) {
        if (edge.from == 0)
            continue;
        frames.push_back(Resolve(pid, edge.from));
    }

    std::ostringstream oss;
    for (const auto &frame : frames) {
        oss << frame.binary << '|' << frame.function << '|' << frame.source_file << ':' << frame.line << ';';
    }
    uint64_t stack_id = HashString(oss.str(), ip);

    {
        std::lock_guard<std::mutex> lk(mu_);
        auto [it, inserted] = stack_table_.try_emplace(stack_id);
        if (inserted) {
            it->second.id = stack_id;
            it->second.frames = frames;
            dirty_stacks_.push_back(stack_id);
        }
    }

    return stack_id;
}

DataObject Symbolizer::ResolveData(uint32_t pid, uint64_t addr) const {
    MemoryRegion region{};
    {
        std::lock_guard<std::mutex> lk(mu_);
        DataObject override_obj;
        if (LookupDataOverrideLocked(pid, addr, override_obj))
            return override_obj;
        if (!MapAddressLocked(pid, addr, region)) {
            DataObject unknown;
            unknown.mapping = "[unknown]";
            unknown.offset = addr;
            return unknown;
        }
        MaybeAutoRegisterRegionLocked(pid, region);
        if (LookupDataOverrideLocked(pid, addr, override_obj))
            return override_obj;
    }
    DataObject obj;
    obj.mapping = region.path;
    obj.base = region.start;
    obj.offset = addr - region.start;
    obj.permissions = region.perms;
    return obj;
}

void Symbolizer::MaybeAutoRegisterRegionLocked(uint32_t pid, const MemoryRegion &region) const {
    if (region.path.empty())
        return;
    if (region.end <= region.start)
        return;
    auto &entries = data_overrides_[pid];
    for (const auto &entry : entries) {
        if (region.start >= entry.start && region.end <= entry.end && entry.object.mapping == region.path)
            return;
    }

    DataOverride auto_obj;
    auto_obj.start = region.start;
    auto_obj.end = region.end;
    auto_obj.object.mapping = region.path;
    auto_obj.object.base = region.start;
    auto_obj.object.offset = 0;
    auto_obj.object.permissions = region.perms;
    auto_obj.object.name = region.path;
    auto_obj.object.type = "mapping";
    auto_obj.object.size = region.end - region.start;
    entries.push_back(std::move(auto_obj));
}

std::vector<StackTrace> Symbolizer::ConsumeStacks() {
    std::vector<StackTrace> result;
    std::lock_guard<std::mutex> lk(mu_);
    result.reserve(dirty_stacks_.size());
    for (auto id : dirty_stacks_) {
        auto it = stack_table_.find(id);
        if (it != stack_table_.end())
            result.push_back(it->second);
    }
    dirty_stacks_.clear();
    return result;
}

uint64_t Symbolizer::InternDataObject(uint32_t pid, uint64_t addr, DataObject *out) {
    if (addr == 0) {
        if (out)
            *out = DataObject{};
        return 0;
    }

    DataObject obj = ResolveData(pid, addr);
    if (out)
        *out = obj;

    std::ostringstream oss;
    oss << obj.mapping << '|' << obj.permissions << '|' << std::hex << obj.base;
    uint64_t id = HashString(oss.str(), addr);

    {
        std::lock_guard<std::mutex> lk(mu_);
        auto [it, inserted] = data_table_.try_emplace(id);
        if (inserted) {
            it->second.id = id;
            it->second.object = obj;
            dirty_data_.push_back(id);
        }
    }

    return id;
}

std::vector<DataSymbol> Symbolizer::ConsumeDataObjects() {
    std::vector<DataSymbol> result;
    std::lock_guard<std::mutex> lk(mu_);
    result.reserve(dirty_data_.size());
    for (auto id : dirty_data_) {
        auto it = data_table_.find(id);
        if (it != data_table_.end())
            result.push_back(it->second);
    }
    dirty_data_.clear();
    return result;
}

void Symbolizer::DropProcess(uint32_t pid) {
    std::lock_guard<std::mutex> lk(mu_);
    proc_maps_.erase(pid);
    jit_regions_.erase(pid);
    data_overrides_.erase(pid);
    for (auto it = intern_table_.begin(); it != intern_table_.end();) {
        if (it->first.pid == pid)
            it = intern_table_.erase(it);
        else
            ++it;
    }
}

void Symbolizer::RegisterJitRegion(uint32_t pid,
                                   uint64_t start,
                                   uint64_t end,
                                   const std::string &path,
                                   const std::string &build_id) {
    if (pid == 0 || start == 0 || end <= start)
        return;
    MemoryRegion region{};
    region.start = start;
    region.end = end;
    region.file_offset = 0;
    region.path = path.empty() ? ("[jit:" + std::to_string(pid) + "]") : path;
    if (!build_id.empty())
        region.path += "#" + build_id;
    region.perms = "r-xp";
    OverrideRegion override{start, end, region};

    std::lock_guard<std::mutex> lk(mu_);
    auto &entries = jit_regions_[pid];
    entries.erase(std::remove_if(entries.begin(), entries.end(), [&](const OverrideRegion &existing) {
        return !(existing.end <= start || existing.start >= end);
    }), entries.end());
    entries.push_back(override);
}

void Symbolizer::RegisterDataObject(uint32_t pid,
                                    uint64_t address,
                                    const std::string &name,
                                    const std::string &type,
                                    uint64_t size) {
    if (pid == 0 || address == 0)
        return;
    uint64_t length = size ? size : 1;
    DataObject obj;
    obj.mapping = name.empty() ? std::string{"[user-data]"} : name;
    obj.base = address;
    obj.offset = 0;
    obj.permissions = "rw-p";
    obj.name = name;
    obj.type = type;
    obj.size = length;

    DataOverride override{address, address + length, obj};
    std::lock_guard<std::mutex> lk(mu_);
    auto &entries = data_overrides_[pid];
    entries.erase(std::remove_if(entries.begin(), entries.end(), [&](const DataOverride &existing) {
        return !(existing.end <= override.start || existing.start >= override.end);
    }), entries.end());
    entries.push_back(override);
}

} // namespace micro_sentinel
