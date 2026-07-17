// ─────────────────────────────────────────────────────────────────────────────
// src/main.cpp
//
// Network Threat Engine — Entry Point and Pipeline Orchestration
// ─────────────────────────────────────────────────────────────────────────────

#include "Config.hpp"
#include "PacketInfo.hpp"
#include "PacketRingBuffer.hpp"
#include "FlowKey.hpp"
#include "FlowRecord.hpp"
#include "ThreatAlert.hpp"
#include "EWMAEngine.hpp"
#include "PortScanDetector.hpp"
#include "SynFloodDetector.hpp"
#include "CaptureLayer.hpp"
#include "FlowTracker.hpp"
#include "ThreatDetector.hpp"
#include "DeliveryLayer.hpp"

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

// ─────────────────────────────────────────────────────────────────────────────
// ProtocolDissector free functions (ProtocolDissector.cpp)
// ─────────────────────────────────────────────────────────────────────────────

namespace nte
{
    PacketInfo dissect_packet(const CapturedPacket &raw);
    std::string format_tcp_flags(uint8_t flags);
}

// ─────────────────────────────────────────────────────────────────────────────
// Global shutdown flag
// ─────────────────────────────────────────────────────────────────────────────

static std::atomic<bool> g_shutdown_flag{false};

// ─────────────────────────────────────────────────────────────────────────────
// Global pipeline objects (owned here, accessed via get/set accessors)
// ─────────────────────────────────────────────────────────────────────────────

static std::unique_ptr<nte::PacketRingBuffer> g_ring_buffer;
static std::unique_ptr<nte::CaptureLayer> g_capture;
static std::unique_ptr<nte::FlowTracker> g_flow_tracker;
static std::unique_ptr<nte::ThreatDetector> g_threat_detector;
static std::unique_ptr<nte::DeliveryLayer> g_delivery;

// ─────────────────────────────────────────────────────────────────────────────
// Performance counters
// ─────────────────────────────────────────────────────────────────────────────

static std::atomic<uint64_t> g_consumer_packets_processed{0};
static std::chrono::steady_clock::time_point g_start_time{};

// ─────────────────────────────────────────────────────────────────────────────
// Signal handler (async-signal-safe)
// ─────────────────────────────────────────────────────────────────────────────

static void signal_handler(int signum)
{
    g_shutdown_flag.store(true, std::memory_order_release);

    // Unblock pcap_loop() in the Producer thread
    nte::CaptureLayer *cap = nte::get_capture_layer();
    if (cap != nullptr)
    {
        pcap_t *handle = cap->pcap_handle();
        if (handle != nullptr)
        {
            pcap_breakloop(handle);
        }
    }

    // Unblock Consumer thread blocked on ring_buffer.pop()
    if (g_ring_buffer != nullptr)
    {
        g_ring_buffer->shutdown();
    }

    const char *msg = "\n[SIGNAL] Shutdown initiated...\n";
    (void)::write(STDERR_FILENO, msg, ::strlen(msg));

    (void)signum;
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI argument parsing
// ─────────────────────────────────────────────────────────────────────────────

static void print_usage(const char *argv0)
{
    std::cout
        << "\nUsage: " << argv0 << " [OPTIONS]\n\n"
        << "Options:\n"
        << "  -i <iface>   Network interface (default: auto-discover)\n"
        << "  -d <path>    SQLite3 alert DB path (default: alerts.db)\n"
        << "  -s <sec>     Alert suppression interval (default: 5.0)\n"
        << "  -w <sec>     Port scan window seconds (default: 10.0)\n"
        << "  -p <count>   Port scan port threshold (default: 20)\n"
        << "  -r <pps>     SYN flood rate threshold (default: 50.0)\n"
        << "  -e <alpha>   EWMA smoothing factor 0-1 (default: 0.125)\n"
        << "  -b <MB>      Kernel ring buffer MB (default: 20)\n"
        << "  -R <ms>      Dashboard refresh ms (default: 500)\n"
        << "  -h           Print this help\n\n"
        << "Requires root or: sudo setcap cap_net_raw+ep " << argv0 << "\n\n";
}

static nte::Config parse_args(int argc, char *argv[])
{
    nte::Config config{};
    int opt = 0;

    while ((opt = ::getopt(argc, argv, "i:d:s:w:p:r:e:b:R:h")) != -1)
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
            const double v = std::stod(optarg);
            if (v > 0.0)
                config.delivery.alert_suppression_sec = v;
            break;
        }

        case 'w':
        {
            const double v = std::stod(optarg);
            if (v > 0.0)
                config.port_scan.window_sec = v;
            break;
        }

        case 'p':
        {
            const int v = std::stoi(optarg);
            if (v > 0)
                config.port_scan.distinct_port_threshold =
                    static_cast<uint32_t>(v);
            break;
        }

        case 'r':
        {
            const double v = std::stod(optarg);
            if (v > 0.0)
                config.syn_flood.syn_rate_pps = v;
            break;
        }

        case 'e':
        {
            const double v = std::stod(optarg);
            if (v > 0.0 && v < 1.0)
                config.ewma.alpha = v;
            break;
        }

        case 'b':
        {
            const int v = std::stoi(optarg);
            if (v > 0)
                config.capture.kernel_buffer_bytes = v * 1024 * 1024;
            break;
        }

        case 'R':
        {
            const int v = std::stoi(optarg);
            if (v > 0)
                config.delivery.dashboard_refresh_ms = v;
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

// ─────────────────────────────────────────────────────────────────────────────
// Stats provider for DeliveryLayer dashboard
// ─────────────────────────────────────────────────────────────────────────────

static nte::EngineStats collect_stats()
{
    nte::EngineStats stats{};

    if (g_ring_buffer)
    {
        stats.packets_captured = g_ring_buffer->pushed_count();
        stats.packets_dropped_ring = g_ring_buffer->dropped_count();
        stats.ring_queue_depth = g_ring_buffer->size();
        stats.drop_rate_pct = g_ring_buffer->drop_rate_percent();
    }

    if (nte::get_flow_tracker())
    {
        stats.active_flows =
            nte::get_flow_tracker()->active_flow_count();
    }

    if (nte::get_delivery_layer())
    {
        stats.total_alerts =
            nte::get_delivery_layer()->total_persisted();
    }

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

// ─────────────────────────────────────────────────────────────────────────────
// Consumer thread
// ─────────────────────────────────────────────────────────────────────────────

static void consumer_thread_func(const nte::Config & /*config*/)
{
    std::cout << "[Consumer] Thread started.\n";
    std::cout.flush();

    nte::CapturedPacket pkt;

    while (g_ring_buffer->pop(pkt))
    {
        // Layer 2: Dissect
        nte::PacketInfo info = nte::dissect_packet(pkt);

        // Layer 3: Flow tracking
        nte::FlowRecord *flow = nullptr;
        if (info.valid && nte::get_flow_tracker() != nullptr)
        {
            flow = nte::get_flow_tracker()->update(info);
        }

        // Layer 4: Threat detection
        if (info.valid && nte::get_threat_detector() != nullptr)
        {
            const auto now = std::chrono::steady_clock::now();
            nte::get_threat_detector()->inspect(info, flow, now);
        }

        ++g_consumer_packets_processed;

        if (g_shutdown_flag.load(std::memory_order_relaxed))
            break;
    }

    std::cout
        << "[Consumer] Thread exiting. Processed: "
        << g_consumer_packets_processed.load(std::memory_order_relaxed)
        << " packets.\n";
    std::cout.flush();
}

// ─────────────────────────────────────────────────────────────────────────────
// Session summary
// ─────────────────────────────────────────────────────────────────────────────

static void print_session_summary()
{
    const auto now = std::chrono::steady_clock::now();
    const double uptime =
        std::chrono::duration<double>(now - g_start_time).count();

    const nte::EngineStats stats = collect_stats();

    std::cout
        << "\n"
        << "══════════════════════════════════════════════════════════════\n"
        << "  Network Threat Engine — Session Summary\n"
        << "══════════════════════════════════════════════════════════════\n"
        << std::fixed << std::setprecision(1)
        << "  Uptime              : " << uptime << " s\n"
        << "  Packets captured    : " << stats.packets_captured << "\n"
        << "  Packets processed   : "
        << g_consumer_packets_processed.load() << "\n"
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
        << "══════════════════════════════════════════════════════════════\n\n";
    std::cout.flush();
}

// ─────────────────────────────────────────────────────────────────────────────
// main()
// ─────────────────────────────────────────────────────────────────────────────

int main(int argc, char *argv[])
{
    std::cout
        << "\n"
        << "╔══════════════════════════════════════════════════════════════╗\n"
        << "║       Network Threat Engine  v"
        << nte::Config::version()
        << "                          ║\n"
        << "║       Real-Time NIDS — 5-Layer Detection Pipeline           ║\n"
        << "╚══════════════════════════════════════════════════════════════╝\n"
        << "\n";

    nte::Config config;
    try
    {
        config = parse_args(argc, argv);
    }
    catch (const std::exception &ex)
    {
        std::cerr << "[FATAL] Argument parsing: " << ex.what() << "\n";
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    std::cout
        << "[main] Interface    : "
        << (config.capture.interface.empty()
                ? "(auto)"
                : config.capture.interface)
        << "\n"
        << "[main] Alert DB     : " << config.delivery.db_path << "\n"
        << "[main] EWMA alpha   : " << config.ewma.alpha << "\n"
        << "[main] Scan window  : " << config.port_scan.window_sec << "s\n"
        << "[main] Scan thresh  : "
        << config.port_scan.distinct_port_threshold << " ports\n"
        << "[main] SYN thresh   : "
        << config.syn_flood.syn_rate_pps << " pps\n\n";
    std::cout.flush();

    g_start_time = std::chrono::steady_clock::now();

    // ── Signal handlers ───────────────────────────────────────────────────────
    struct sigaction sa{};
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    if (::sigaction(SIGINT, &sa, nullptr) != 0 ||
        ::sigaction(SIGTERM, &sa, nullptr) != 0)
    {
        std::cerr << "[WARN] sigaction failed; using legacy signal().\n";
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);
    }

    int exit_code = EXIT_SUCCESS;

    try
    {
        // ── Construct all pipeline objects ────────────────────────────────────
        g_ring_buffer =
            std::make_unique<nte::PacketRingBuffer>(config.ring_buffer);

        g_capture =
            std::make_unique<nte::CaptureLayer>(config, *g_ring_buffer);
        nte::set_capture_layer(g_capture.get());

        g_flow_tracker =
            std::make_unique<nte::FlowTracker>(config);
        nte::set_flow_tracker(g_flow_tracker.get());

        g_threat_detector =
            std::make_unique<nte::ThreatDetector>(config);
        nte::set_threat_detector(g_threat_detector.get());

        g_delivery =
            std::make_unique<nte::DeliveryLayer>(config, collect_stats);
        nte::set_delivery_layer(g_delivery.get());

        // ── Start layers ──────────────────────────────────────────────────────
        g_delivery->start();
        g_flow_tracker->start_reaper();

        std::thread consumer(consumer_thread_func, std::cref(config));

        std::cout << "[main] Pipeline live. Press Ctrl-C to stop.\n\n";
        std::cout.flush();

        // Capture loop runs inside CaptureLayer's Producer thread
        g_capture->start();

        // Block main thread until Consumer drains and exits
        consumer.join();
        std::cout << "[main] Consumer joined.\n";

        // ── Orderly shutdown ──────────────────────────────────────────────────
        g_capture->stop();
        std::cout << "[main] CaptureLayer stopped.\n";

        g_flow_tracker->stop_reaper();
        std::cout << "[main] FlowTracker reaper stopped.\n";

        g_delivery->stop();
        std::cout << "[main] DeliveryLayer stopped.\n";
    }
    catch (const std::exception &ex)
    {
        std::cerr << "\n[FATAL] " << ex.what() << "\n";
        exit_code = EXIT_FAILURE;

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

    print_session_summary();

    // Destroy in reverse-construction order
    nte::set_delivery_layer(nullptr);
    nte::set_threat_detector(nullptr);
    nte::set_flow_tracker(nullptr);
    nte::set_capture_layer(nullptr);

    g_delivery.reset();
    g_threat_detector.reset();
    g_flow_tracker.reset();
    g_capture.reset();
    g_ring_buffer.reset();

    std::cout << "[main] Shutdown complete.\n\n";
    return exit_code;
}