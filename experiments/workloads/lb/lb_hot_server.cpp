// g++ -O2 -g -std=c++20 -pthread experiments/workloads/lb/lb_hot_server.cpp -o /tmp/lb_hot_server_test && /tmp/lb_hot_server_test --help | head

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cinttypes>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace {

constexpr uint64_t MS_FNV64_OFFSET = 1469598103934665603ULL;
constexpr uint64_t MS_FNV64_PRIME = 1099511628211ULL;

static inline uint64_t fnv64_mix(uint64_t h, uint64_t data) {
    h ^= (data & 0xFFFFFFFFFFFFFFFFULL);
    h = (h * MS_FNV64_PRIME) & 0xFFFFFFFFFFFFFFFFULL;
    return h;
}

static inline uint32_t ipv4_be32(const in_addr &addr) {
    return addr.s_addr; // already network byte order
}

static uint64_t compute_ms_flow_id_v4(const sockaddr_in &src, const sockaddr_in &dst, uint8_t proto = 6, uint8_t direction = 0) {
    // Match experiments/workloads/lb/lb_client.py::compute_ms_flow_id_v4 and
    // bpf/micro_sentinel_kern.bpf.c::hash_flow_tuple() assumptions.
    uint64_t h = MS_FNV64_OFFSET;
    h = fnv64_mix(h, direction);
    h = fnv64_mix(h, proto);

    const uint32_t src_port = ntohs(src.sin_port);
    const uint32_t dst_port = ntohs(dst.sin_port);
    h = fnv64_mix(h, (static_cast<uint64_t>(src_port & 0xFFFF) << 32) | (dst_port & 0xFFFF));

    const uint32_t src_ip = ipv4_be32(src.sin_addr);
    const uint32_t dst_ip = ipv4_be32(dst.sin_addr);
    h = fnv64_mix(h, (static_cast<uint64_t>(src_ip) << 32) | static_cast<uint64_t>(dst_ip));
    return h ? h : 1ULL;
}

struct HotConfig {
    size_t bytes_per_func = 0;
    size_t stride = 64;
    int rounds = 1;
    int funcs = 64;
};

static HotConfig g_hot;
static std::vector<uint8_t *> g_hot_bufs;
static std::vector<void *> g_hot_allocs;
static std::vector<size_t> g_hot_alloc_sizes;
static thread_local uint64_t tls_sink = 0;

static void init_hot_buffers(const HotConfig &cfg) {
    g_hot = cfg;
    g_hot_bufs.clear();
    g_hot_allocs.clear();
    g_hot_alloc_sizes.clear();
    if (cfg.bytes_per_func == 0 || cfg.funcs <= 0 || cfg.stride == 0 || cfg.rounds <= 0)
        return;

    g_hot_bufs.reserve(static_cast<size_t>(cfg.funcs));
    g_hot_allocs.reserve(static_cast<size_t>(cfg.funcs));
    g_hot_alloc_sizes.reserve(static_cast<size_t>(cfg.funcs));

    // Allocate per-function working sets aligned to 64 bytes.
    for (int i = 0; i < cfg.funcs; ++i) {
        size_t bytes = cfg.bytes_per_func;
        // posix_memalign requires alignment to be power-of-two multiple of sizeof(void*).
        void *ptr = nullptr;
        int rc = posix_memalign(&ptr, 64, bytes);
        if (rc != 0 || !ptr) {
            std::cerr << "[lb-hot] posix_memalign failed: " << std::strerror(rc) << std::endl;
            std::exit(1);
        }
        // Fill with deterministic but varying content.
        auto *buf = reinterpret_cast<uint8_t *>(ptr);
        for (size_t off = 0; off < bytes; ++off) {
            buf[off] = static_cast<uint8_t>((off + static_cast<size_t>(i) * 131) & 0xFF);
        }
        g_hot_allocs.push_back(ptr);
        g_hot_alloc_sizes.push_back(bytes);
        g_hot_bufs.push_back(buf);
    }
}

static inline void hot_touch(int idx) {
    if (g_hot.bytes_per_func == 0 || idx < 0 || idx >= static_cast<int>(g_hot_bufs.size()))
        return;
    volatile uint8_t *buf = g_hot_bufs[static_cast<size_t>(idx)];
    uint64_t local = tls_sink;

    // Strided scan to create cache pressure. Keep a data dependency.
    for (int r = 0; r < g_hot.rounds; ++r) {
        for (size_t off = 0; off < g_hot.bytes_per_func; off += g_hot.stride) {
            local += buf[off];
        }
        // Touch a pseudo-random location dependent on local.
        size_t extra = (static_cast<size_t>(local) * 1315423911ULL) % g_hot.bytes_per_func;
        local ^= buf[extra];
    }

    tls_sink = local;
    asm volatile("" : : "r,m"(tls_sink) : "memory");
}

// Generate distinct symbol names: hot_func_0 .. hot_func_255.
#define DECL_HOT_FUNC(i) __attribute__((noinline)) void hot_func_##i() { hot_touch(i); }

DECL_HOT_FUNC(0)
DECL_HOT_FUNC(1)
DECL_HOT_FUNC(2)
DECL_HOT_FUNC(3)
DECL_HOT_FUNC(4)
DECL_HOT_FUNC(5)
DECL_HOT_FUNC(6)
DECL_HOT_FUNC(7)
DECL_HOT_FUNC(8)
DECL_HOT_FUNC(9)
DECL_HOT_FUNC(10)
DECL_HOT_FUNC(11)
DECL_HOT_FUNC(12)
DECL_HOT_FUNC(13)
DECL_HOT_FUNC(14)
DECL_HOT_FUNC(15)
DECL_HOT_FUNC(16)
DECL_HOT_FUNC(17)
DECL_HOT_FUNC(18)
DECL_HOT_FUNC(19)
DECL_HOT_FUNC(20)
DECL_HOT_FUNC(21)
DECL_HOT_FUNC(22)
DECL_HOT_FUNC(23)
DECL_HOT_FUNC(24)
DECL_HOT_FUNC(25)
DECL_HOT_FUNC(26)
DECL_HOT_FUNC(27)
DECL_HOT_FUNC(28)
DECL_HOT_FUNC(29)
DECL_HOT_FUNC(30)
DECL_HOT_FUNC(31)
DECL_HOT_FUNC(32)
DECL_HOT_FUNC(33)
DECL_HOT_FUNC(34)
DECL_HOT_FUNC(35)
DECL_HOT_FUNC(36)
DECL_HOT_FUNC(37)
DECL_HOT_FUNC(38)
DECL_HOT_FUNC(39)
DECL_HOT_FUNC(40)
DECL_HOT_FUNC(41)
DECL_HOT_FUNC(42)
DECL_HOT_FUNC(43)
DECL_HOT_FUNC(44)
DECL_HOT_FUNC(45)
DECL_HOT_FUNC(46)
DECL_HOT_FUNC(47)
DECL_HOT_FUNC(48)
DECL_HOT_FUNC(49)
DECL_HOT_FUNC(50)
DECL_HOT_FUNC(51)
DECL_HOT_FUNC(52)
DECL_HOT_FUNC(53)
DECL_HOT_FUNC(54)
DECL_HOT_FUNC(55)
DECL_HOT_FUNC(56)
DECL_HOT_FUNC(57)
DECL_HOT_FUNC(58)
DECL_HOT_FUNC(59)
DECL_HOT_FUNC(60)
DECL_HOT_FUNC(61)
DECL_HOT_FUNC(62)
DECL_HOT_FUNC(63)
DECL_HOT_FUNC(64)
DECL_HOT_FUNC(65)
DECL_HOT_FUNC(66)
DECL_HOT_FUNC(67)
DECL_HOT_FUNC(68)
DECL_HOT_FUNC(69)
DECL_HOT_FUNC(70)
DECL_HOT_FUNC(71)
DECL_HOT_FUNC(72)
DECL_HOT_FUNC(73)
DECL_HOT_FUNC(74)
DECL_HOT_FUNC(75)
DECL_HOT_FUNC(76)
DECL_HOT_FUNC(77)
DECL_HOT_FUNC(78)
DECL_HOT_FUNC(79)
DECL_HOT_FUNC(80)
DECL_HOT_FUNC(81)
DECL_HOT_FUNC(82)
DECL_HOT_FUNC(83)
DECL_HOT_FUNC(84)
DECL_HOT_FUNC(85)
DECL_HOT_FUNC(86)
DECL_HOT_FUNC(87)
DECL_HOT_FUNC(88)
DECL_HOT_FUNC(89)
DECL_HOT_FUNC(90)
DECL_HOT_FUNC(91)
DECL_HOT_FUNC(92)
DECL_HOT_FUNC(93)
DECL_HOT_FUNC(94)
DECL_HOT_FUNC(95)
DECL_HOT_FUNC(96)
DECL_HOT_FUNC(97)
DECL_HOT_FUNC(98)
DECL_HOT_FUNC(99)
DECL_HOT_FUNC(100)
DECL_HOT_FUNC(101)
DECL_HOT_FUNC(102)
DECL_HOT_FUNC(103)
DECL_HOT_FUNC(104)
DECL_HOT_FUNC(105)
DECL_HOT_FUNC(106)
DECL_HOT_FUNC(107)
DECL_HOT_FUNC(108)
DECL_HOT_FUNC(109)
DECL_HOT_FUNC(110)
DECL_HOT_FUNC(111)
DECL_HOT_FUNC(112)
DECL_HOT_FUNC(113)
DECL_HOT_FUNC(114)
DECL_HOT_FUNC(115)
DECL_HOT_FUNC(116)
DECL_HOT_FUNC(117)
DECL_HOT_FUNC(118)
DECL_HOT_FUNC(119)
DECL_HOT_FUNC(120)
DECL_HOT_FUNC(121)
DECL_HOT_FUNC(122)
DECL_HOT_FUNC(123)
DECL_HOT_FUNC(124)
DECL_HOT_FUNC(125)
DECL_HOT_FUNC(126)
DECL_HOT_FUNC(127)
DECL_HOT_FUNC(128)
DECL_HOT_FUNC(129)
DECL_HOT_FUNC(130)
DECL_HOT_FUNC(131)
DECL_HOT_FUNC(132)
DECL_HOT_FUNC(133)
DECL_HOT_FUNC(134)
DECL_HOT_FUNC(135)
DECL_HOT_FUNC(136)
DECL_HOT_FUNC(137)
DECL_HOT_FUNC(138)
DECL_HOT_FUNC(139)
DECL_HOT_FUNC(140)
DECL_HOT_FUNC(141)
DECL_HOT_FUNC(142)
DECL_HOT_FUNC(143)
DECL_HOT_FUNC(144)
DECL_HOT_FUNC(145)
DECL_HOT_FUNC(146)
DECL_HOT_FUNC(147)
DECL_HOT_FUNC(148)
DECL_HOT_FUNC(149)
DECL_HOT_FUNC(150)
DECL_HOT_FUNC(151)
DECL_HOT_FUNC(152)
DECL_HOT_FUNC(153)
DECL_HOT_FUNC(154)
DECL_HOT_FUNC(155)
DECL_HOT_FUNC(156)
DECL_HOT_FUNC(157)
DECL_HOT_FUNC(158)
DECL_HOT_FUNC(159)
DECL_HOT_FUNC(160)
DECL_HOT_FUNC(161)
DECL_HOT_FUNC(162)
DECL_HOT_FUNC(163)
DECL_HOT_FUNC(164)
DECL_HOT_FUNC(165)
DECL_HOT_FUNC(166)
DECL_HOT_FUNC(167)
DECL_HOT_FUNC(168)
DECL_HOT_FUNC(169)
DECL_HOT_FUNC(170)
DECL_HOT_FUNC(171)
DECL_HOT_FUNC(172)
DECL_HOT_FUNC(173)
DECL_HOT_FUNC(174)
DECL_HOT_FUNC(175)
DECL_HOT_FUNC(176)
DECL_HOT_FUNC(177)
DECL_HOT_FUNC(178)
DECL_HOT_FUNC(179)
DECL_HOT_FUNC(180)
DECL_HOT_FUNC(181)
DECL_HOT_FUNC(182)
DECL_HOT_FUNC(183)
DECL_HOT_FUNC(184)
DECL_HOT_FUNC(185)
DECL_HOT_FUNC(186)
DECL_HOT_FUNC(187)
DECL_HOT_FUNC(188)
DECL_HOT_FUNC(189)
DECL_HOT_FUNC(190)
DECL_HOT_FUNC(191)
DECL_HOT_FUNC(192)
DECL_HOT_FUNC(193)
DECL_HOT_FUNC(194)
DECL_HOT_FUNC(195)
DECL_HOT_FUNC(196)
DECL_HOT_FUNC(197)
DECL_HOT_FUNC(198)
DECL_HOT_FUNC(199)
DECL_HOT_FUNC(200)
DECL_HOT_FUNC(201)
DECL_HOT_FUNC(202)
DECL_HOT_FUNC(203)
DECL_HOT_FUNC(204)
DECL_HOT_FUNC(205)
DECL_HOT_FUNC(206)
DECL_HOT_FUNC(207)
DECL_HOT_FUNC(208)
DECL_HOT_FUNC(209)
DECL_HOT_FUNC(210)
DECL_HOT_FUNC(211)
DECL_HOT_FUNC(212)
DECL_HOT_FUNC(213)
DECL_HOT_FUNC(214)
DECL_HOT_FUNC(215)
DECL_HOT_FUNC(216)
DECL_HOT_FUNC(217)
DECL_HOT_FUNC(218)
DECL_HOT_FUNC(219)
DECL_HOT_FUNC(220)
DECL_HOT_FUNC(221)
DECL_HOT_FUNC(222)
DECL_HOT_FUNC(223)
DECL_HOT_FUNC(224)
DECL_HOT_FUNC(225)
DECL_HOT_FUNC(226)
DECL_HOT_FUNC(227)
DECL_HOT_FUNC(228)
DECL_HOT_FUNC(229)
DECL_HOT_FUNC(230)
DECL_HOT_FUNC(231)
DECL_HOT_FUNC(232)
DECL_HOT_FUNC(233)
DECL_HOT_FUNC(234)
DECL_HOT_FUNC(235)
DECL_HOT_FUNC(236)
DECL_HOT_FUNC(237)
DECL_HOT_FUNC(238)
DECL_HOT_FUNC(239)
DECL_HOT_FUNC(240)
DECL_HOT_FUNC(241)
DECL_HOT_FUNC(242)
DECL_HOT_FUNC(243)
DECL_HOT_FUNC(244)
DECL_HOT_FUNC(245)
DECL_HOT_FUNC(246)
DECL_HOT_FUNC(247)
DECL_HOT_FUNC(248)
DECL_HOT_FUNC(249)
DECL_HOT_FUNC(250)
DECL_HOT_FUNC(251)
DECL_HOT_FUNC(252)
DECL_HOT_FUNC(253)
DECL_HOT_FUNC(254)
DECL_HOT_FUNC(255)

#undef DECL_HOT_FUNC

static inline void dispatch_hot(int idx) {
    switch (idx) {
#define CASE_HOT(i) \
    case i:         \
        hot_func_##i(); \
        break;
        CASE_HOT(0)
        CASE_HOT(1)
        CASE_HOT(2)
        CASE_HOT(3)
        CASE_HOT(4)
        CASE_HOT(5)
        CASE_HOT(6)
        CASE_HOT(7)
        CASE_HOT(8)
        CASE_HOT(9)
        CASE_HOT(10)
        CASE_HOT(11)
        CASE_HOT(12)
        CASE_HOT(13)
        CASE_HOT(14)
        CASE_HOT(15)
        CASE_HOT(16)
        CASE_HOT(17)
        CASE_HOT(18)
        CASE_HOT(19)
        CASE_HOT(20)
        CASE_HOT(21)
        CASE_HOT(22)
        CASE_HOT(23)
        CASE_HOT(24)
        CASE_HOT(25)
        CASE_HOT(26)
        CASE_HOT(27)
        CASE_HOT(28)
        CASE_HOT(29)
        CASE_HOT(30)
        CASE_HOT(31)
        CASE_HOT(32)
        CASE_HOT(33)
        CASE_HOT(34)
        CASE_HOT(35)
        CASE_HOT(36)
        CASE_HOT(37)
        CASE_HOT(38)
        CASE_HOT(39)
        CASE_HOT(40)
        CASE_HOT(41)
        CASE_HOT(42)
        CASE_HOT(43)
        CASE_HOT(44)
        CASE_HOT(45)
        CASE_HOT(46)
        CASE_HOT(47)
        CASE_HOT(48)
        CASE_HOT(49)
        CASE_HOT(50)
        CASE_HOT(51)
        CASE_HOT(52)
        CASE_HOT(53)
        CASE_HOT(54)
        CASE_HOT(55)
        CASE_HOT(56)
        CASE_HOT(57)
        CASE_HOT(58)
        CASE_HOT(59)
        CASE_HOT(60)
        CASE_HOT(61)
        CASE_HOT(62)
        CASE_HOT(63)
        CASE_HOT(64)
        CASE_HOT(65)
        CASE_HOT(66)
        CASE_HOT(67)
        CASE_HOT(68)
        CASE_HOT(69)
        CASE_HOT(70)
        CASE_HOT(71)
        CASE_HOT(72)
        CASE_HOT(73)
        CASE_HOT(74)
        CASE_HOT(75)
        CASE_HOT(76)
        CASE_HOT(77)
        CASE_HOT(78)
        CASE_HOT(79)
        CASE_HOT(80)
        CASE_HOT(81)
        CASE_HOT(82)
        CASE_HOT(83)
        CASE_HOT(84)
        CASE_HOT(85)
        CASE_HOT(86)
        CASE_HOT(87)
        CASE_HOT(88)
        CASE_HOT(89)
        CASE_HOT(90)
        CASE_HOT(91)
        CASE_HOT(92)
        CASE_HOT(93)
        CASE_HOT(94)
        CASE_HOT(95)
        CASE_HOT(96)
        CASE_HOT(97)
        CASE_HOT(98)
        CASE_HOT(99)
        CASE_HOT(100)
        CASE_HOT(101)
        CASE_HOT(102)
        CASE_HOT(103)
        CASE_HOT(104)
        CASE_HOT(105)
        CASE_HOT(106)
        CASE_HOT(107)
        CASE_HOT(108)
        CASE_HOT(109)
        CASE_HOT(110)
        CASE_HOT(111)
        CASE_HOT(112)
        CASE_HOT(113)
        CASE_HOT(114)
        CASE_HOT(115)
        CASE_HOT(116)
        CASE_HOT(117)
        CASE_HOT(118)
        CASE_HOT(119)
        CASE_HOT(120)
        CASE_HOT(121)
        CASE_HOT(122)
        CASE_HOT(123)
        CASE_HOT(124)
        CASE_HOT(125)
        CASE_HOT(126)
        CASE_HOT(127)
        CASE_HOT(128)
        CASE_HOT(129)
        CASE_HOT(130)
        CASE_HOT(131)
        CASE_HOT(132)
        CASE_HOT(133)
        CASE_HOT(134)
        CASE_HOT(135)
        CASE_HOT(136)
        CASE_HOT(137)
        CASE_HOT(138)
        CASE_HOT(139)
        CASE_HOT(140)
        CASE_HOT(141)
        CASE_HOT(142)
        CASE_HOT(143)
        CASE_HOT(144)
        CASE_HOT(145)
        CASE_HOT(146)
        CASE_HOT(147)
        CASE_HOT(148)
        CASE_HOT(149)
        CASE_HOT(150)
        CASE_HOT(151)
        CASE_HOT(152)
        CASE_HOT(153)
        CASE_HOT(154)
        CASE_HOT(155)
        CASE_HOT(156)
        CASE_HOT(157)
        CASE_HOT(158)
        CASE_HOT(159)
        CASE_HOT(160)
        CASE_HOT(161)
        CASE_HOT(162)
        CASE_HOT(163)
        CASE_HOT(164)
        CASE_HOT(165)
        CASE_HOT(166)
        CASE_HOT(167)
        CASE_HOT(168)
        CASE_HOT(169)
        CASE_HOT(170)
        CASE_HOT(171)
        CASE_HOT(172)
        CASE_HOT(173)
        CASE_HOT(174)
        CASE_HOT(175)
        CASE_HOT(176)
        CASE_HOT(177)
        CASE_HOT(178)
        CASE_HOT(179)
        CASE_HOT(180)
        CASE_HOT(181)
        CASE_HOT(182)
        CASE_HOT(183)
        CASE_HOT(184)
        CASE_HOT(185)
        CASE_HOT(186)
        CASE_HOT(187)
        CASE_HOT(188)
        CASE_HOT(189)
        CASE_HOT(190)
        CASE_HOT(191)
        CASE_HOT(192)
        CASE_HOT(193)
        CASE_HOT(194)
        CASE_HOT(195)
        CASE_HOT(196)
        CASE_HOT(197)
        CASE_HOT(198)
        CASE_HOT(199)
        CASE_HOT(200)
        CASE_HOT(201)
        CASE_HOT(202)
        CASE_HOT(203)
        CASE_HOT(204)
        CASE_HOT(205)
        CASE_HOT(206)
        CASE_HOT(207)
        CASE_HOT(208)
        CASE_HOT(209)
        CASE_HOT(210)
        CASE_HOT(211)
        CASE_HOT(212)
        CASE_HOT(213)
        CASE_HOT(214)
        CASE_HOT(215)
        CASE_HOT(216)
        CASE_HOT(217)
        CASE_HOT(218)
        CASE_HOT(219)
        CASE_HOT(220)
        CASE_HOT(221)
        CASE_HOT(222)
        CASE_HOT(223)
        CASE_HOT(224)
        CASE_HOT(225)
        CASE_HOT(226)
        CASE_HOT(227)
        CASE_HOT(228)
        CASE_HOT(229)
        CASE_HOT(230)
        CASE_HOT(231)
        CASE_HOT(232)
        CASE_HOT(233)
        CASE_HOT(234)
        CASE_HOT(235)
        CASE_HOT(236)
        CASE_HOT(237)
        CASE_HOT(238)
        CASE_HOT(239)
        CASE_HOT(240)
        CASE_HOT(241)
        CASE_HOT(242)
        CASE_HOT(243)
        CASE_HOT(244)
        CASE_HOT(245)
        CASE_HOT(246)
        CASE_HOT(247)
        CASE_HOT(248)
        CASE_HOT(249)
        CASE_HOT(250)
        CASE_HOT(251)
        CASE_HOT(252)
        CASE_HOT(253)
        CASE_HOT(254)
        CASE_HOT(255)
#undef CASE_HOT
    default:
        hot_func_0();
        break;
    }
}

static bool read_full(int fd, void *buf, size_t len) {
    auto *p = reinterpret_cast<uint8_t *>(buf);
    size_t off = 0;
    while (off < len) {
        ssize_t n = ::recv(fd, p + off, len - off, 0);
        if (n == 0)
            return false;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        off += static_cast<size_t>(n);
    }
    return true;
}

static bool write_full(int fd, const void *buf, size_t len) {
    const auto *p = reinterpret_cast<const uint8_t *>(buf);
    size_t off = 0;
    while (off < len) {
        ssize_t n = ::send(fd, p + off, len - off, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR)
                continue;
            return false;
        }
        off += static_cast<size_t>(n);
    }
    return true;
}

struct ServerConfig {
    std::string host = "0.0.0.0";
    uint16_t port = 7100;
    int workers = 4;
    size_t payload_bytes = 512;
    int flow_tag_bytes = 0;
    int hot_funcs = 64;
};

static std::atomic<uint64_t> g_conn_accepted{0};

static void handle_connection(int fd, const ServerConfig &cfg) {
    sockaddr_in peer{};
    sockaddr_in local{};
    socklen_t alen = sizeof(peer);
    socklen_t blen = sizeof(local);
    if (::getpeername(fd, reinterpret_cast<sockaddr *>(&peer), &alen) != 0) {
        // best-effort
    }
    if (::getsockname(fd, reinterpret_cast<sockaddr *>(&local), &blen) != 0) {
        // best-effort
    }
    (void)compute_ms_flow_id_v4(peer, local);

    std::vector<uint8_t> buf(cfg.payload_bytes);
    while (true) {
        if (!read_full(fd, buf.data(), buf.size()))
            break;

        int func_idx = 0;
        if (cfg.flow_tag_bytes == 4 && buf.size() >= 4) {
            uint32_t tag = 0;
            std::memcpy(&tag, buf.data(), sizeof(tag));
            func_idx = static_cast<int>(tag);
        } else if (cfg.flow_tag_bytes == 2 && buf.size() >= 2) {
            uint16_t tag = 0;
            std::memcpy(&tag, buf.data(), sizeof(tag));
            func_idx = static_cast<int>(tag);
        }
        if (cfg.hot_funcs > 0) {
            func_idx %= cfg.hot_funcs;
            if (func_idx < 0)
                func_idx += cfg.hot_funcs;
        }

        dispatch_hot(func_idx);

        if (!write_full(fd, buf.data(), buf.size()))
            break;
    }
    ::close(fd);
}

static int create_listen_socket(const std::string &host, uint16_t port, bool reuseport) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        std::perror("socket");
        return -1;
    }

    int one = 1;
    (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef SO_REUSEPORT
    if (reuseport) {
        (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    }
#else
    (void)reuseport;
#endif

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        std::cerr << "invalid --host: " << host << std::endl;
        ::close(fd);
        return -1;
    }

    if (::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
        std::perror("bind");
        ::close(fd);
        return -1;
    }
    if (::listen(fd, 4096) != 0) {
        std::perror("listen");
        ::close(fd);
        return -1;
    }
    return fd;
}

static void worker_loop(int listen_fd, const ServerConfig &cfg) {
    while (true) {
        int cfd = ::accept(listen_fd, nullptr, nullptr);
        if (cfd < 0) {
            if (errno == EINTR)
                continue;
            std::perror("accept");
            continue;
        }
        g_conn_accepted.fetch_add(1, std::memory_order_relaxed);
        std::thread([cfd, &cfg]() { handle_connection(cfd, cfg); }).detach();
    }
}

static void usage(const char *argv0) {
    std::cerr
        << "Usage: " << argv0
        << " --host <ip> --port <port> --workers <n> [--payload-bytes N] [--flow-tag-bytes 0|2|4]"
           " [--hot-bytes-per-func N] [--hot-stride N] [--hot-rounds N] [--hot-funcs N]\n";
}

} // namespace

int main(int argc, char **argv) {
    ServerConfig cfg;
    HotConfig hot;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto need = [&](const char *name) -> const char * {
            if (i + 1 >= argc) {
                std::cerr << "missing value for " << name << std::endl;
                usage(argv[0]);
                std::exit(2);
            }
            return argv[++i];
        };

        if (a == "--host") {
            cfg.host = need("--host");
        } else if (a == "--port") {
            cfg.port = static_cast<uint16_t>(std::stoi(need("--port")));
        } else if (a == "--workers") {
            cfg.workers = std::stoi(need("--workers"));
        } else if (a == "--payload-bytes") {
            cfg.payload_bytes = static_cast<size_t>(std::stoull(need("--payload-bytes")));
        } else if (a == "--flow-tag-bytes") {
            cfg.flow_tag_bytes = std::stoi(need("--flow-tag-bytes"));
        } else if (a == "--hot-bytes-per-func") {
            hot.bytes_per_func = static_cast<size_t>(std::stoull(need("--hot-bytes-per-func")));
        } else if (a == "--hot-stride") {
            hot.stride = static_cast<size_t>(std::stoull(need("--hot-stride")));
        } else if (a == "--hot-rounds") {
            hot.rounds = std::stoi(need("--hot-rounds"));
        } else if (a == "--hot-funcs") {
            cfg.hot_funcs = std::stoi(need("--hot-funcs"));
            hot.funcs = cfg.hot_funcs;
        } else if (a == "--help" || a == "-h") {
            usage(argv[0]);
            return 0;
        } else {
            // Ignore unknown args so it can coexist with other LB configs.
        }
    }

    if (cfg.workers <= 0)
        cfg.workers = 1;
    if (cfg.hot_funcs <= 0)
        cfg.hot_funcs = 1;
    if (cfg.hot_funcs > 256) {
        std::cerr << "--hot-funcs capped at 256 (got " << cfg.hot_funcs << ")" << std::endl;
        cfg.hot_funcs = 256;
        hot.funcs = 256;
    }

    init_hot_buffers(hot);

    std::cerr << "[lb-hot] listening on " << cfg.host << ":" << cfg.port
              << " workers=" << cfg.workers << " payload=" << cfg.payload_bytes
              << " tag_bytes=" << cfg.flow_tag_bytes << " hot_funcs=" << cfg.hot_funcs
              << " hot_bytes=" << hot.bytes_per_func << " hot_stride=" << hot.stride
              << " hot_rounds=" << hot.rounds << std::endl;

    // Use reuseport so each worker has its own accept queue, improving per-flow stability.
    std::vector<int> listen_fds;
    listen_fds.reserve(static_cast<size_t>(cfg.workers));
    for (int w = 0; w < cfg.workers; ++w) {
        int fd = create_listen_socket(cfg.host, cfg.port, true);
        if (fd < 0) {
            std::cerr << "failed to create listen socket" << std::endl;
            return 1;
        }
        listen_fds.push_back(fd);
    }

    std::vector<std::thread> threads;
    threads.reserve(static_cast<size_t>(cfg.workers));
    for (int w = 0; w < cfg.workers; ++w) {
        threads.emplace_back([fd = listen_fds[static_cast<size_t>(w)], &cfg]() { worker_loop(fd, cfg); });
    }

    for (auto &t : threads)
        t.join();

    return 0;
}
