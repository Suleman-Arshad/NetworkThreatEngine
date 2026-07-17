#include "Config.hpp"
#include "PacketInfo.hpp"
#include "PacketRingBuffer.hpp"
#include "FlowKey.hpp"
#include "FlowRecord.hpp"
#include "ThreatAlert.hpp"
#include "EWMAEngine.hpp"
#include "PortScanDetector.hpp"
#include "SynFloodDetector.hpp"
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <pcap.h>
#include <unistd.h>

namespace nte
{

    // CaptureLayer (CaptureLayer.cpp)

    class CaptureLayer;
    CaptureLayer *get_capture_layer() noexcept;
    void set_capture_layer(CaptureLayer *layer) noexcept;

    // FlowTracker (FlowTracker.cpp)

    class FlowTracker;
    FlowTracker *get_flow_tracker() noexcept;
    void set_flow_tracker(FlowTracker *ft) noexcept;

    // ThreatDetector (ThreatDetector.cpp)

    class ThreatDetector;
    ThreatDetector *get_threat_detector() noexcept;
    void set_threat_detector(ThreatDetector *td) noexcept;

    // DeliveryLayer (DeliveryLayer.cpp)

    class DeliveryLayer;
    DeliveryLayer *get_delivery_layer() noexcept;
    void set_delivery_layer(DeliveryLayer *dl) noexcept;
    void delivery_fire_alert(const ThreatAlert &alert);

    // ProtocolDissector (ProtocolDissector.cpp)

    PacketInfo dissect_packet(const CapturedPacket &raw);
    std::string format_tcp_flags(uint8_t flags);

    // EngineStats (defined below, used by DeliveryLayer dashboard)

    struct EngineStats
    {
        uint64_t packets_captured{0};
        uint64_t packets_dropped_ring{0};
        uint64_t packets_dropped_kernel{0};
        std::size_t ring_queue_depth{0};
        std::size_t active_flows{0};
        uint64_t total_alerts{0};
        double capture_pps{0.0};
        double drop_rate_pct{0.0};
    };

} // namespace nte

static std::atomic<bool> g_shutdown_flag{false};
static std::unique_ptr<nte::CaptureLayer> g_capture;
static std::unique_ptr<nte::PacketRingBuffer> g_ring_buffer;
static std::unique_ptr<nte::FlowTracker> g_flow_tracker;
static std::unique_ptr<nte::ThreatDetector> g_threat_detector;
static std::unique_ptr<nte::DeliveryLayer> g_delivery;

// Performance tracking globals (read by dashboard stats provider)
static std::atomic<uint64_t> g_consumer_packets_processed{0};
static std::chrono::steady_clock::time_point g_start_time{};

// Signal handler
static void signal_handler(int signum)
{
    g_shutdown_flag.store(true, std::memory_order_release);

    // Wake the Producer thread by breaking out of pcap_loop()
    nte::CaptureLayer *cap = nte::get_capture_layer();
    if (cap != nullptr)
    {
        extern pcap_t *nte_get_pcap_handle_for_signal() noexcept;
        pcap_t *handle = nte_get_pcap_handle_for_signal();
        if (handle != nullptr)
        {
            pcap_breakloop(handle);
        }
    }

    // Wake the Consumer thread if it is blocked on ring_buffer.pop()
    if (g_ring_buffer != nullptr)
    {
        g_ring_buffer->shutdown();
    }

    // Write a minimal async-signal-safe message
    const char *msg = "\n[SIGNAL] Shutdown initiated...\n";
    (void)write(STDERR_FILENO, msg, strlen(msg));

    (void)signum;
}
#include "Config.hpp" // already included but idempotent via #pragma once
// CLI argument parsing
static void print_usage(const char *argv0)
{
    std::cout
        << "\nUsage: " << argv0 << " [OPTIONS]\n\n"
        << "Options:\n"
        << "  -i <interface>   Network interface to capture on "
           "(default: auto-discover)\n"
        << "  -d <path>        SQLite3 alert database path "
           "(default: alerts.db)\n"
        << "  -s <seconds>     Alert suppression interval "
           "(default: 5.0)\n"
        << "  -w <seconds>     Port scan detection window "
           "(default: 10.0)\n"
        << "  -p <count>       Port scan distinct port threshold "
           "(default: 20)\n"
        << "  -r <pps>         SYN flood rate threshold pps "
           "(default: 50.0)\n"
        << "  -e <alpha>       EWMA smoothing factor 0.0-1.0 "
           "(default: 0.125)\n"
        << "  -b <MB>          Kernel ring buffer size MB "
           "(default: 20)\n"
        << "  -R <seconds>     Dashboard refresh interval ms "
           "(default: 500)\n"
        << "  -h               Print this help message\n\n"
        << "Examples:\n"
        << "  sudo " << argv0 << " -i eth0\n"
        << "  sudo " << argv0 << " -i eth0 -d /var/log/nids/alerts.db "
                                 "-s 10.0 -p 30\n\n"
        << "Privileges:\n"
        << "  Raw socket capture requires CAP_NET_RAW.\n"
        << "  Run as root or: sudo setcap cap_net_raw+ep " << argv0 << "\n\n";
}

static nte::Config parse_args(int argc, char *argv[])
{
    nte::Config config{};
    int opt = 0;

    while ((opt = getopt(argc, argv, "i:d:s:w:p:r:e:b:R:h")) != -1)
    {
        switch (opt)
        {
        case 'i':
            config.capture.interface = optarg;
            break;

        case 'd':
            config.delivery.db_path = optarg;
            break;

        case 's':
        {
            const double val = std::stod(optarg);
            if (val > 0.0)
                config.delivery.alert_suppression_sec = val;
            break;
        }

        case 'w':
        {
            const double val = std::stod(optarg);
            if (val > 0.0)
                config.port_scan.window_sec = val;
            break;
        }

        case 'p':
        {
            const int val = std::stoi(optarg);
            if (val > 0)
                config.port_scan.distinct_port_threshold =
                    static_cast<uint32_t>(val);
            break;
        }

        case 'r':
        {
            const double val = std::stod(optarg);
            if (val > 0.0)
                config.syn_flood.syn_rate_pps = val;
            break;
        }

        case 'e':
        {
            const double val = std::stod(optarg);
            if (val > 0.0 && val < 1.0)
                config.ewma.alpha = val;
            break;
        }

        case 'b':
        {
            const int val = std::stoi(optarg);
            if (val > 0)
                config.capture.kernel_buffer_bytes = val * 1024 * 1024;
            break;
        }

        case 'R':
        {
            const int val = std::stoi(optarg);
            if (val > 0)
                config.delivery.dashboard_refresh_ms = val;
            break;
        }

        case 'h':
            print_usage(argv[0]);
            std::exit(EXIT_SUCCESS);

        default:
            print_usage(argv[0]);
            std::exit(EXIT_FAILURE);
        }
    }

    return config;
}

// Consumer thread function
// Pops CapturedPackets from the ring buffer, dissects them through all pipeline layers, and drives the threat detection engine.

static void consumer_thread_func(const nte::Config &config)
{
    (void)config;

    std::cout << "[Consumer] Thread started.\n";
    std::cout.flush();

    nte::CapturedPacket pkt;

    while (g_ring_buffer->pop(pkt))
    {
        // Layer 2: Protocol Dissection
        nte::PacketInfo info = nte::dissect_packet(pkt);

        // Layer 3: Flow Tracking
        nte::FlowRecord *flow = nullptr;

        if (info.valid && nte::get_flow_tracker() != nullptr)
        {
            flow = nte::get_flow_tracker()->update(info);
        }

        // Layer 4: Threat Detection
        if (info.valid && nte::get_threat_detector() != nullptr)
        {
            const auto now = std::chrono::steady_clock::now();
            nte::get_threat_detector()->inspect(info, flow, now);
        }

        ++g_consumer_packets_processed;

        // Check shutdown flag between packets to ensure timely exit
        if (g_shutdown_flag.load(std::memory_order_relaxed))
        {
            break;
        }
    }

    std::cout << "[Consumer] Thread exiting. Packets processed: "
              << g_consumer_packets_processed.load(std::memory_order_relaxed)
              << "\n";
    std::cout.flush();
}

// Stats provider for DeliveryLayer dashboard
static nte::EngineStats collect_stats()
{
    nte::EngineStats stats;

    if (g_ring_buffer)
    {
        stats.packets_captured = g_ring_buffer->pushed_count();
        stats.packets_dropped_ring = g_ring_buffer->dropped_count();
        stats.ring_queue_depth = g_ring_buffer->size();
        stats.drop_rate_pct = g_ring_buffer->drop_rate_percent();
    }

    if (nte::get_flow_tracker())
    {
        stats.active_flows = nte::get_flow_tracker()->active_flow_count();
    }

    if (nte::get_delivery_layer())
    {
        stats.total_alerts = nte::get_delivery_layer()->total_persisted();
    }

    // Compute approximate capture rate since engine start
    const auto now = std::chrono::steady_clock::now();
    const double uptime =
        std::chrono::duration<double>(now - g_start_time).count();

    if (uptime > 0.0)
    {
        stats.capture_pps =
            static_cast<double>(stats.packets_captured) / uptime;
    }

    return stats;
}

// Session summary
static void print_session_summary()
{
    const auto now = std::chrono::steady_clock::now();
    const double uptime =
        std::chrono::duration<double>(now - g_start_time).count();

    const nte::EngineStats stats = collect_stats();

    std::cout
        << "\n"
        << "==============================================================\n"
        << "  Network Threat Engine - Session Summary\n"
        << "==============================================================\n"
        << std::fixed << std::setprecision(1)
        << "  Uptime              : " << uptime << " seconds\n"
        << "  Packets captured    : " << stats.packets_captured << "\n"
        << "  Packets processed   : "
        << g_consumer_packets_processed.load(std::memory_order_relaxed)
        << "\n"
        << "  Ring buffer drops   : " << stats.packets_dropped_ring << "\n"
        << "  Drop rate           : "
        << std::setprecision(4) << stats.drop_rate_pct << "%\n"
        << "  Active flows        : " << stats.active_flows << "\n";

    if (nte::get_flow_tracker())
    {
        std::cout
            << "  Total flows created : "
            << nte::get_flow_tracker()->total_flows_created() << "\n"
            << "  Total flows evicted : "
            << nte::get_flow_tracker()->total_flows_evicted() << "\n";
    }

    std::cout
        << "  Alerts fired        : " << stats.total_alerts << "\n"
        << "==============================================================\n\n";
    std::cout.flush();
}

namespace nte
{
    // Defined in CaptureLayer.cpp - returns the active pcap handle so the signal handler can call pcap_breakloop().
    class CaptureLayer
    {
    public:
        [[nodiscard]] pcap_t *pcap_handle() const noexcept;
        void start();
        void stop() noexcept;
        [[nodiscard]] uint64_t captured_count() const noexcept;
        [[nodiscard]] uint64_t dropped_by_ring() const noexcept;
        [[nodiscard]] bool is_running() const noexcept;
        [[nodiscard]] const std::string &active_interface() const noexcept;

        explicit CaptureLayer(const Config &config,
                              PacketRingBuffer &ring_buffer);
        ~CaptureLayer();
        CaptureLayer(const CaptureLayer &) = delete;
        CaptureLayer &operator=(const CaptureLayer &) = delete;
        CaptureLayer(CaptureLayer &&) = delete;
        CaptureLayer &operator=(CaptureLayer &&) = delete;

    private:
        // Implementation detail — opaque from main.cpp's perspective
        struct Impl;
        std::unique_ptr<Impl> impl_;
    };

    class FlowTracker
    {
    public:
        explicit FlowTracker(const Config &config);
        ~FlowTracker();
        FlowTracker(const FlowTracker &) = delete;
        FlowTracker &operator=(const FlowTracker &) = delete;
        FlowTracker(FlowTracker &&) = delete;
        FlowTracker &operator=(FlowTracker &&) = delete;

        void start_reaper();
        void stop_reaper() noexcept;
        FlowRecord *update(const PacketInfo &info);

        [[nodiscard]] std::size_t active_flow_count() const noexcept;
        [[nodiscard]] uint64_t total_flows_created() const noexcept;
        [[nodiscard]] uint64_t total_flows_evicted() const noexcept;

    private:
        struct Impl;
        std::unique_ptr<Impl> impl_;
    };

    class ThreatDetector
    {
    public:
        explicit ThreatDetector(const Config &config);
        ~ThreatDetector();
        ThreatDetector(const ThreatDetector &) = delete;
        ThreatDetector &operator=(const ThreatDetector &) = delete;
        ThreatDetector(ThreatDetector &&) = delete;
        ThreatDetector &operator=(ThreatDetector &&) = delete;

        void inspect(const PacketInfo &info,
                     const FlowRecord *flow,
                     std::chrono::steady_clock::time_point now);
        [[nodiscard]] uint64_t total_alerts_fired() const noexcept;

    private:
        struct Impl;
        std::unique_ptr<Impl> impl_;
    };

    class DeliveryLayer
    {
    public:
        explicit DeliveryLayer(const Config &config, StatsProvider stats_fn);
        ~DeliveryLayer();
        DeliveryLayer(const DeliveryLayer &) = delete;
        DeliveryLayer &operator=(const DeliveryLayer &) = delete;
        DeliveryLayer(DeliveryLayer &&) = delete;
        DeliveryLayer &operator=(DeliveryLayer &&) = delete;

        void start();
        void stop() noexcept;
        void enqueue_alert(const ThreatAlert &alert);
        [[nodiscard]] uint64_t total_persisted() const noexcept;

    private:
        struct Impl;
        std::unique_ptr<Impl> impl_;
    };

    using StatsProvider = std::function<EngineStats()>;

} // namespace nte

// The signal handler needs a pcap_t* — expose a simple free function that the signal handler can call.
pcap_t *nte_get_pcap_handle_for_signal() noexcept
{
    nte::CaptureLayer *cap = nte::get_capture_layer();
    if (cap == nullptr)
        return nullptr;
    return cap->pcap_handle();
}

int main(int argc, char *argv[])
{
    // Banner
    std::cout
        << "\n"
        << "=================================================================\n"
        << "         Network Threat Engine  v"
        << nte::Config::version()
        << "                          \n"
        << "         Real-Time NIDS - 5-Layer Detection Pipeline           \n"
        << "=================================================================\n"
        << "\n";

    // Parse CLI arguments
    nte::Config config;

    try
    {
        config = parse_args(argc, argv);
    }
    catch (const std::exception &ex)
    {
        std::cerr << "[FATAL] Argument parsing failed: " << ex.what() << "\n";
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    std::cout
        << "[main] Configuration:\n"
        << "  Interface          : "
        << (config.capture.interface.empty()
                ? "(auto)"
                : config.capture.interface)
        << "\n"
        << "  Kernel buffer      : "
        << (config.capture.kernel_buffer_bytes / (1024 * 1024)) << " MB\n"
        << "  Alert DB           : " << config.delivery.db_path << "\n"
        << "  Suppression        : "
        << config.delivery.alert_suppression_sec << "s\n"
        << "  EWMA alpha         : " << config.ewma.alpha << "\n"
        << "  Port scan window   : " << config.port_scan.window_sec << "s\n"
        << "  Port scan threshold: "
        << config.port_scan.distinct_port_threshold << " ports\n"
        << "  SYN flood threshold: "
        << config.syn_flood.syn_rate_pps << " pps\n"
        << "\n";
    std::cout.flush();

    // Record start time
    g_start_time = std::chrono::steady_clock::now();

    // Install signal handlers
    struct sigaction sa{};
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    if (sigaction(SIGINT, &sa, nullptr) != 0 ||
        sigaction(SIGTERM, &sa, nullptr) != 0)
    {
        std::cerr << "[WARN] sigaction() failed; using legacy signal().\n";
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);
    }

    // Construct pipeline layers

    int exit_code = EXIT_SUCCESS;

    try
    {
        // Layer 0: Ring buffer (shared between Capture and Consumer)
        g_ring_buffer = std::make_unique<nte::PacketRingBuffer>(
            config.ring_buffer);

        // Layer 1: Capture
        g_capture = std::make_unique<nte::CaptureLayer>(
            config, *g_ring_buffer);
        nte::set_capture_layer(g_capture.get());

        // Layer 3: Flow tracker
        g_flow_tracker = std::make_unique<nte::FlowTracker>(config);
        nte::set_flow_tracker(g_flow_tracker.get());

        // Layer 4: Threat detector
        g_threat_detector = std::make_unique<nte::ThreatDetector>(config);
        nte::set_threat_detector(g_threat_detector.get());

        // Layer 5: Delivery
        g_delivery = std::make_unique<nte::DeliveryLayer>(
            config, collect_stats);
        nte::set_delivery_layer(g_delivery.get());

        // Start layers in dependency order
        // Delivery must start before threat detector can fire alerts
        g_delivery->start();

        // Flow tracker reaper thread
        g_flow_tracker->start_reaper();

        // Consumer thread (reads from ring buffer, runs Layers 2-4)
        std::thread consumer(consumer_thread_func, std::cref(config));

        std::cout
            << "[main] All layers initialised. Spawning Consumer thread.\n"
            << "[main] Starting capture on ";

        if (config.capture.interface.empty())
            std::cout << "(auto-discovered interface)";
        else
            std::cout << config.capture.interface;

        std::cout << "...\n"
                  << "[main] Press Ctrl-C to stop.\n\n";
        std::cout.flush();

        g_capture->start();

        consumer.join();

        std::cout << "[main] Consumer thread joined.\n";

        // Orderly shutdown

        // 1. Stop the capture producer
        g_capture->stop();
        std::cout << "[main] CaptureLayer stopped.\n";

        // 2. Stop the flow tracker reaper
        g_flow_tracker->stop_reaper();
        std::cout << "[main] FlowTracker reaper stopped.\n";

        // 3. Drain and stop delivery layer (flushes alert queue + SQLite)
        g_delivery->stop();
        std::cout << "[main] DeliveryLayer stopped.\n";
    }
    catch (const std::exception &ex)
    {
        std::cerr << "\n[FATAL] " << ex.what() << "\n";
        exit_code = EXIT_FAILURE;

        // Attempt emergency cleanup
        g_shutdown_flag.store(true, std::memory_order_release);

        if (g_ring_buffer)
            g_ring_buffer->shutdown();
        if (g_delivery)
            g_delivery->stop();
        if (g_flow_tracker)
            g_flow_tracker->stop_reaper();
        if (g_capture)
            g_capture->stop();
    }

    // Final session summary
    print_session_summary();

    // Cleanup global pointers in reverse-construction order
    nte::set_delivery_layer(nullptr);
    nte::set_threat_detector(nullptr);
    nte::set_flow_tracker(nullptr);
    nte::set_capture_layer(nullptr);

    g_delivery.reset();
    g_threat_detector.reset();
    g_flow_tracker.reset();
    g_capture.reset();
    g_ring_buffer.reset();

    std::cout << "[main] Engine shutdown complete.\n\n";
    return exit_code;
}