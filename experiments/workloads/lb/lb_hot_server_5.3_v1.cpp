/*
 * Experiment 5.3: Data Object / Cache Line Attribution Workload
 * 
 * This workload implements the specific requirements for the Data Object Attribution experiment:
 * 1. Two global arrays (A, B) aligned to cache lines.
 * 2. Two heap objects (o1, o2) allocated at runtime.
 * 3. Request handling logic that maps specific flows (via tag) to specific objects.
 * 4. Strided memory access pattern to generate L3 misses.
 * 5. Output of memory layout for ground-truth verification.
 */

#include <iostream>
#include <vector>
#include <thread>
#include <atomic>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <cassert>

// 32MB size for each object to ensure L3 misses (L3 is ~27.5MB)
constexpr size_t OBJ_SIZE_BYTES = 32 * 1024 * 1024;
constexpr size_t OBJ_INT_COUNT = OBJ_SIZE_BYTES / sizeof(int);

// Global Arrays
alignas(64) int g_array_A[OBJ_INT_COUNT];
alignas(64) int g_array_B[OBJ_INT_COUNT];

// Heap Object Structures
struct Obj1 {
    alignas(64) int data[OBJ_INT_COUNT];
};

struct Obj2 {
    alignas(64) int data[OBJ_INT_COUNT];
};

// Global pointers to heap objects
Obj1* g_heap_o1 = nullptr;
Obj2* g_heap_o2 = nullptr;

struct Config {
    std::string host = "0.0.0.0";
    uint16_t port = 7100;
    int workers = 4;
    size_t payload_bytes = 512;
    int stride_bytes = 256; // Stride > cache line size to ensure misses
    int rounds = 1000;      // Access iterations per request to generate load
};

// Helper to touch memory with stride
// We use volatile to prevent compiler optimization
// __attribute__((noinline)) to ensure it shows up in symbols if needed
__attribute__((noinline))
static void touch_memory(int* base, size_t count, int stride_bytes, int rounds) {
    size_t stride_ints = stride_bytes / sizeof(int);
    if (stride_ints == 0) stride_ints = 1;

    for (int r = 0; r < rounds; ++r) {
        for (size_t i = 0; i < count; i += stride_ints) {
            // Read and write to ensure dirty
            volatile int val = base[i];
            base[i] = val + 1;
        }
    }
}

static bool read_full(int fd, void *buf, size_t len) {
    auto *p = reinterpret_cast<uint8_t *>(buf);
    size_t off = 0;
    while (off < len) {
        ssize_t n = ::recv(fd, p + off, len - off, 0);
        if (n == 0) return false;
        if (n < 0) {
            if (errno == EINTR) continue;
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
            if (n < 0 && errno == EINTR) continue;
            return false;
        }
        off += static_cast<size_t>(n);
    }
    return true;
}

static void handle_connection(int fd, const Config &cfg) {
    std::vector<uint8_t> buf(cfg.payload_bytes);
    
    while (true) {
        if (!read_full(fd, buf.data(), buf.size())) break;

        // Determine target object from first 4 bytes of payload (tag)
        // If payload < 4 bytes, default to 0
        uint32_t tag = 0;
        if (buf.size() >= 4) {
            std::memcpy(&tag, buf.data(), sizeof(tag));
        }
        
        // Map tag to object: 0->A, 1->B, 2->o1, 3->o2
        int target = tag % 4;

        switch (target) {
            case 0: // Global A
                touch_memory(g_array_A, OBJ_INT_COUNT, cfg.stride_bytes, cfg.rounds);
                break;
            case 1: // Global B
                touch_memory(g_array_B, OBJ_INT_COUNT, cfg.stride_bytes, cfg.rounds);
                break;
            case 2: // Heap o1
                if (g_heap_o1) touch_memory(g_heap_o1->data, OBJ_INT_COUNT, cfg.stride_bytes, cfg.rounds);
                break;
            case 3: // Heap o2
                if (g_heap_o2) touch_memory(g_heap_o2->data, OBJ_INT_COUNT, cfg.stride_bytes, cfg.rounds);
                break;
        }

        if (!write_full(fd, buf.data(), buf.size())) break;
    }
    ::close(fd);
}

static int create_listen_socket(const std::string &host, uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        std::perror("socket");
        return -1;
    }

    int one = 1;
    (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));

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

static void worker_loop(int listen_fd, const Config &cfg) {
    while (true) {
        int cfd = ::accept(listen_fd, nullptr, nullptr);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            std::perror("accept");
            continue;
        }
        std::thread([cfd, &cfg]() { handle_connection(cfd, cfg); }).detach();
    }
}

static void usage(const char *argv0) {
    std::cerr
        << "Usage: " << argv0
        << " --host <ip> --port <port> --workers <n> [--payload-bytes N] [--stride-bytes N] [--rounds N]\n";
}

int main(int argc, char **argv) {
    Config cfg;

    static struct option long_options[] = {
        {"host", required_argument, 0, 'h'},
        {"port", required_argument, 0, 'p'},
        {"workers", required_argument, 0, 'w'},
        {"payload-bytes", required_argument, 0, 'b'},
        {"stride-bytes", required_argument, 0, 's'},
        {"rounds", required_argument, 0, 'r'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "h:p:w:b:s:r:", long_options, &option_index)) != -1) {
        switch (opt) {
        case 'h': cfg.host = optarg; break;
        case 'p': cfg.port = std::stoi(optarg); break;
        case 'w': cfg.workers = std::stoi(optarg); break;
        case 'b': cfg.payload_bytes = std::stoul(optarg); break;
        case 's': cfg.stride_bytes = std::stoi(optarg); break;
        case 'r': cfg.rounds = std::stoi(optarg); break;
        default: usage(argv[0]); return 1;
        }
    }

    // Initialize Heap Objects
    g_heap_o1 = new Obj1();
    g_heap_o2 = new Obj2();

    // Initialize memory to avoid page faults during measurement
    std::memset(g_array_A, 0, sizeof(g_array_A));
    std::memset(g_array_B, 0, sizeof(g_array_B));
    std::memset(g_heap_o1->data, 0, sizeof(g_heap_o1->data));
    std::memset(g_heap_o2->data, 0, sizeof(g_heap_o2->data));

    // Print Data Layout for Analysis
    // The analysis script can parse these lines to know the ground truth addresses
    printf("[data_layout] object=A type=global start=%p end=%p size=%zu\n", 
           (void*)g_array_A, (void*)(g_array_A + OBJ_INT_COUNT), sizeof(g_array_A));
    printf("[data_layout] object=B type=global start=%p end=%p size=%zu\n", 
           (void*)g_array_B, (void*)(g_array_B + OBJ_INT_COUNT), sizeof(g_array_B));
    printf("[data_layout] object=o1 type=heap start=%p end=%p size=%zu\n", 
           (void*)g_heap_o1->data, (void*)(g_heap_o1->data + OBJ_INT_COUNT), sizeof(Obj1));
    printf("[data_layout] object=o2 type=heap start=%p end=%p size=%zu\n", 
           (void*)g_heap_o2->data, (void*)(g_heap_o2->data + OBJ_INT_COUNT), sizeof(Obj2));
    fflush(stdout);

    int listen_fd = create_listen_socket(cfg.host, cfg.port);
    if (listen_fd < 0) return 1;

    std::cout << "Server listening on " << cfg.host << ":" << cfg.port 
              << " with " << cfg.workers << " workers." << std::endl;

    // Start workers
    std::vector<std::thread> threads;
    for (int i = 0; i < cfg.workers; ++i) {
        threads.emplace_back(worker_loop, listen_fd, cfg);
    }

    for (auto &t : threads) {
        t.join();
    }

    return 0;
}
