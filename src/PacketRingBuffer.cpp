#include "PacketRingBuffer.hpp"
#include "ProtocolDissector.hpp"
#include <arpa/inet.h>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
// libpcap — packet capture library
#include <pcap.h>

using namespace std;

#ifndef NTE_VERSION_MAJOR
#define NTE_VERSION_MAJOR 1
#endif
#ifndef NTE_VERSION_MINOR
#define NTE_VERSION_MINOR 0
#endif
#ifndef NTE_VERSION_PATCH
#define NTE_VERSION_PATCH 0
#endif

PacketRingBuffer g_ring_buffer;
static pcap_t *g_pcap_handle = nullptr;

namespace config
{
    constexpr int SNAPLEN = 65535;
    constexpr int PROMISCUOUS = 1;
    constexpr int KERNEL_BUFFER_BYTES = 20 * 1024 * 1024; // 20 MB
    constexpr int READ_TIMEOUT_MS = 1000;
    constexpr int PCAP_LOOP_INFINITE = -1;
    constexpr uint64_t STATS_INTERVAL = 500;
}

static void signal_handler(int signal_number)
{
    const char *msg = "\n[SIGNAL] Shutdown initiated — draining pipeline...\n";
    ssize_t written = write(STDERR_FILENO, msg, strlen(msg));
    (void)written; // Suppress unused variable warning
    if (g_pcap_handle != nullptr)
    {
        pcap_breakloop(g_pcap_handle);
    }
    g_ring_buffer.shutdown();
    (void)signal_number; // Suppress unused variable warning
}

[[maybe_unused]] static std::string format_timestamp(int64_t ts_us)
{
    // Split into whole seconds and microsecond remainder
    const time_t seconds = static_cast<time_t>(ts_us / 1'000'000LL);
    const long micros = static_cast<long>(ts_us % 1'000'000LL);
    struct tm tm_info{};
    localtime_r(&seconds, &tm_info);

    // Format as ISO-8601 with microsecond precision
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_info);

    std::ostringstream oss;
    oss << buf << '.' << std::setw(6) << std::setfill('0') << micros;
    return oss.str();
}

static void consumer_thread_func()
{
    uint64_t packet_index = 0;

    // Table ki formatting aur separators ko IPv6 ke mutabik 146 characters par align kar diya hai
    std::cout
        << "\n"
        << std::left
        << std::setw(8) << "INDEX"
        << std::setw(40) << "SRC_IP" // 18 se badha kar 40 kar diya
        << std::setw(40) << "DST_IP" // 18 se badha kar 40 kar diya
        << std::setw(8) << "SPORT"
        << std::setw(8) << "DPORT"
        << std::setw(8) << "PROTO"
        << std::setw(14) << "TCP_FLAGS"
        << std::setw(10) << "CAP(B)"
        << std::setw(10) << "Q_DEPTH"
        << "\n"
        << std::string(146, '-') // Line length 102 se badha kar 146 kar di
        << "\n";
    std::cout.flush();

    CapturedPacket pkt;

    while (g_ring_buffer.pop(pkt))
    {
        ++packet_index;

        const std::size_t q_depth = g_ring_buffer.size();

        // Hand the raw captured bytes off to the Protocol Dissection Engine.
        DissectionResult diss = dissect_packet(pkt.data.data(), pkt.captured_length);

        // Resolve a short protocol label for the fixed-width column.
        std::string proto_label = "OTHER";

        if (diss.l4_protocol == L4Protocol::TCP)
        {
            proto_label = "TCP";
        }
        else if (diss.l4_protocol == L4Protocol::UDP)
        {
            proto_label = "UDP";
        }
        else if (diss.l4_protocol == L4Protocol::ICMP)
        {
            proto_label = "ICMP";
        }
        else if (diss.l3_protocol == L3Protocol::ARP)
        {
            proto_label = "ARP";
        }

        // Only show flags for TCP; leave the column blank otherwise.
        const std::string flags_str =
            (diss.l4_protocol == L4Protocol::TCP) ? format_tcp_flags(diss.tcp_flags) : "";

        // Row values ko bhi perfectly 40 width ke sath align kar diya hai
        std::cout
            << std::left
            << std::setw(8) << packet_index
            << std::setw(40) << (diss.valid ? diss.src_ip : std::string("-")) // 40 width for IPv6
            << std::setw(40) << (diss.valid ? diss.dst_ip : std::string("-")) // 40 width for IPv6
            << std::setw(8) << (diss.src_port != 0 ? std::to_string(diss.src_port) : "-")
            << std::setw(8) << (diss.dst_port != 0 ? std::to_string(diss.dst_port) : "-")
            << std::setw(8) << proto_label
            << std::setw(14) << flags_str
            << std::setw(10) << pkt.captured_length
            << std::setw(10) << q_depth
            << "\n";

        if (diss.dns.has_value())
        {
            std::cout
                << "         |- DNS  query=" << diss.dns->query_name
                << "  qtype=" << diss.dns->query_type
                << "\n";
        }

        if (diss.http.has_value())
        {
            std::cout
                << "         |- HTTP " << diss.http->method
                << " host=" << diss.http->host
                << " uri=" << diss.http->uri
                << "\n";
        }

        if (diss.tls.has_value())
        {
            std::cout
                << "         |- TLS  sni=" << diss.tls->sni
                << "\n";
        }

        // Stats section ke lines ko bhi 146 characters par adjust kar diya hai
        if (packet_index % config::STATS_INTERVAL == 0)
        {
            std::cout
                << std::string(146, '-')
                << "\n"
                << "[STATS] Processed=" << packet_index
                << "  |  Pushed=" << g_ring_buffer.pushed_count()
                << "  |  Dropped=" << g_ring_buffer.dropped_count()
                << "  |  Drop Rate=" << std::fixed << std::setprecision(3)
                << g_ring_buffer.drop_rate_percent() << "%"
                << "  |  Q_Depth=" << q_depth
                << "\n"
                << std::string(146, '-')
                << "\n";

            std::cout.flush();
        }
    }

    std::cout
        << "\n[CONSUMER] Queue drained.  Total processed: "
        << packet_index
        << "\n";
    std::cout.flush();
}

static void packet_callback(u_char *user,
                            const struct pcap_pkthdr *pkthdr,
                            const u_char *packet)
{
    (void)user;

    // Convert pcap timeval to 64-bit microsecond epoch
    const int64_t ts_us =
        static_cast<int64_t>(pkthdr->ts.tv_sec) * 1'000'000LL +
        static_cast<int64_t>(pkthdr->ts.tv_usec);

    CapturedPacket captured(
        reinterpret_cast<const uint8_t *>(packet),
        pkthdr->caplen,
        pkthdr->len,
        ts_us);

    g_ring_buffer.push(std::move(captured));
}

static std::string discover_capture_device()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs = nullptr;

    if (pcap_findalldevs(&alldevs, errbuf) != 0)
    {
        std::cerr
            << "[FATAL] pcap_findalldevs() failed: " << errbuf << "\n"
            << "        Ensure you have CAP_NET_RAW privileges (run as root or\n"
            << "        grant: sudo setcap cap_net_raw+ep ./packet_analyzer)\n";
        std::exit(EXIT_FAILURE);
    }

    if (alldevs == nullptr)
    {
        std::cerr
            << "[FATAL] No network interfaces found.  Verify that at least one\n"
            << "        network interface is configured and that you have root\n"
            << "        privileges.\n";
        std::exit(EXIT_FAILURE);
    }

    std::cout << "[INFO]  Available capture interfaces:\n";

    std::string selected_device;
    std::string first_device;

    for (const pcap_if_t *dev = alldevs; dev != nullptr; dev = dev->next)
    {
        const bool is_up = (dev->flags & PCAP_IF_UP) != 0;
        const bool is_loopback = (dev->flags & PCAP_IF_LOOPBACK) != 0;
        const bool is_running = (dev->flags & PCAP_IF_RUNNING) != 0;

        std::cout
            << "         "
            << std::left << std::setw(20) << dev->name
            << (is_up ? " UP" : " DOWN")
            << (is_running ? " RUNNING" : "")
            << (is_loopback ? " LOOPBACK" : "")
            << (dev->description ? std::string("  — ") + dev->description : "")
            << "\n";

        if (first_device.empty())
        {
            first_device = dev->name;
        }

        if (selected_device.empty() && is_up && is_running && !is_loopback)
        {
            selected_device = dev->name;
        }
    }

    pcap_freealldevs(alldevs);

    if (selected_device.empty())
    {
        selected_device = first_device;
        std::cout
            << "[WARN]  No active non-loopback interface found; "
               "falling back to: "
            << selected_device << "\n";
    }
    else
    {
        std::cout << "[INFO]  Auto-selected interface: " << selected_device << "\n";
    }

    return selected_device;
}

static pcap_t *initialise_pcap_handle(const std::string &device_name)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_create(device_name.c_str(), errbuf);

    if (handle == nullptr)
    {
        std::cerr
            << "[FATAL] pcap_create() failed for interface '"
            << device_name << "': " << errbuf << "\n";
        std::exit(EXIT_FAILURE);
    }

    if (pcap_set_snaplen(handle, config::SNAPLEN) != 0)
    {
        std::cerr
            << "[FATAL] pcap_set_snaplen() failed: "
            << pcap_geterr(handle) << "\n";
        pcap_close(handle);
        std::exit(EXIT_FAILURE);
    }

    if (pcap_set_promisc(handle, config::PROMISCUOUS) != 0)
    {
        std::cerr
            << "[FATAL] pcap_set_promisc() failed: "
            << pcap_geterr(handle) << "\n";
        pcap_close(handle);
        std::exit(EXIT_FAILURE);
    }

    if (pcap_set_buffer_size(handle, config::KERNEL_BUFFER_BYTES) != 0)
    {
        std::cerr
            << "[WARN]  pcap_set_buffer_size(" << config::KERNEL_BUFFER_BYTES
            << ") returned non-zero: " << pcap_geterr(handle)
            << " — the kernel may have applied its own limit.\n";
    }

    if (pcap_set_timeout(handle, config::READ_TIMEOUT_MS) != 0)
    {
        std::cerr
            << "[FATAL] pcap_set_timeout() failed: "
            << pcap_geterr(handle) << "\n";
        pcap_close(handle);
        std::exit(EXIT_FAILURE);
    }

    const int activate_result = pcap_activate(handle);

    if (activate_result < 0)
    {
        std::cerr
            << "[FATAL] pcap_activate() error "
            << activate_result << ": "
            << pcap_statustostr(activate_result)
            << " — " << pcap_geterr(handle) << "\n";

        if (activate_result == PCAP_ERROR_PERM_DENIED)
        {
            std::cerr
                << "        Insufficient privileges.  Run with sudo or grant:\n"
                << "        sudo setcap cap_net_raw+ep ./packet_analyzer\n";
        }

        pcap_close(handle);
        std::exit(EXIT_FAILURE);
    }

    if (activate_result > 0)
    {
        std::cerr
            << "[WARN]  pcap_activate() warning "
            << activate_result << ": "
            << pcap_statustostr(activate_result) << "\n";
    }

    const int datalink = pcap_datalink(handle);
    std::cout
        << "[INFO]  Datalink type: "
        << datalink
        << " (" << pcap_datalink_val_to_name(datalink) << " — "
        << pcap_datalink_val_to_description(datalink) << ")\n";

    return handle;
}

int main(int argc, char *argv[])
{
    std::cout << "\n";
    std::cout << "==============================================================\n";
    std::cout << "               Network Threat Engine  v2.0.0\n";
    std::cout << "            Real-Time Multi-Layer Protocol Dissector          \n";
    std::cout << "==============================================================\n";
    std::cout << "\n";
    std::string device_name;

    if (argc >= 2)
    {
        device_name = argv[1];
        std::cout << "[INFO]  Interface specified on command line: " << device_name << "\n";
    }
    else
    {
        device_name = discover_capture_device();
    }

    std::cout
        << "[INFO]  Initialising pcap on '" << device_name << "'\n"
        << "[INFO]  Snaplen      : " << config::SNAPLEN << " bytes\n"
        << "[INFO]  Promiscuous  : " << (config::PROMISCUOUS ? "ON" : "OFF") << "\n"
        << "[INFO]  Kernel buf   : " << config::KERNEL_BUFFER_BYTES / (1024 * 1024) << " MB\n"
        << "[INFO]  Read timeout : " << config::READ_TIMEOUT_MS << " ms\n"
        << "[INFO]  Queue max    : " << PacketRingBuffer::MAX_CAPACITY << " packets\n";

    g_pcap_handle = initialise_pcap_handle(device_name);

    std::cout << "[INFO]  pcap handle activated successfully.\n";

    struct sigaction sa{};
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    if (sigaction(SIGINT, &sa, nullptr) != 0 ||
        sigaction(SIGTERM, &sa, nullptr) != 0)
    {
        std::cerr << "[WARN]  sigaction() failed; using legacy signal().\n";
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);
    }

    std::thread consumer_thread(consumer_thread_func);
    consumer_thread.detach();

    std::cout
        << "[INFO]  Consumer thread spawned and detached.\n"
        << "[INFO]  --------------------------------------------------\n"
        << "[INFO]  Capture loop starting on '" << device_name << "'\n"
        << "[INFO]  Press Ctrl-C to stop.\n"
        << "[INFO]  --------------------------------------------------\n";

    std::cout.flush();
    const int loop_result = pcap_loop(
        g_pcap_handle,
        config::PCAP_LOOP_INFINITE,
        packet_callback,
        nullptr);

    if (loop_result == PCAP_ERROR_BREAK)
    {
        std::cout << "\n[INFO]  pcap_loop() exited cleanly (breakloop signal).\n";
    }
    else if (loop_result == PCAP_ERROR)
    {
        std::cerr
            << "\n[ERROR] pcap_loop() returned an error: "
            << pcap_geterr(g_pcap_handle) << "\n";
    }
    g_ring_buffer.shutdown();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    struct pcap_stat ps{};

    if (pcap_stats(g_pcap_handle, &ps) == 0)
    {
        std::cout
            << "\n[STATS] ----- pcap kernel-level statistics -----\n"
            << "[STATS]  Packets received by kernel filter : " << ps.ps_recv << "\n"
            << "[STATS]  Packets dropped by kernel (full)  : " << ps.ps_drop << "\n"
            << "[STATS]  Packets dropped by interface      : " << ps.ps_ifdrop << "\n";
    }

    std::cout
        << "\n[STATS] ----- ring buffer statistics -----\n"
        << "[STATS]  Total pushed   : " << g_ring_buffer.pushed_count() << "\n"
        << "[STATS]  Total popped   : " << g_ring_buffer.popped_count() << "\n"
        << "[STATS]  Total dropped  : " << g_ring_buffer.dropped_count() << "\n"
        << "[STATS]  Drop rate      : " << std::fixed << std::setprecision(4)
        << g_ring_buffer.drop_rate_percent() << "%\n"
        << "[STATS]  Queue at exit  : " << g_ring_buffer.size() << " packets\n";

    pcap_close(g_pcap_handle);
    g_pcap_handle = nullptr;

    std::cout
        << "\n[INFO]  pcap handle closed.  Engine shutdown complete.\n\n";

    return EXIT_SUCCESS;
}