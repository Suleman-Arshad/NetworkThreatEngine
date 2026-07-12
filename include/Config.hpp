#pragma once
#ifndef NETWORK_THREAT_ENGINE_CONFIG_HPP
#define NETWORK_THREAT_ENGINE_CONFIG_HPP
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace nte
{
    // Capture Layer
    struct CaptureConfig
    {
        // Maximum bytes captured per frame.  65535 covers any Ethernet + payload.
        int snaplen{65535};

        // 1 = enable promiscuous mode (see all frames, not just host-addressed ones)
        int promiscuous{1};

        // Kernel-level socket receive buffer in bytes.
        // 20 MB provides large burst absorption before the userspace loop drains it.
        int kernel_buffer_bytes{20 * 1024 * 1024};

        // pcap_loop read timeout in milliseconds.  Controls SIGINT response latency.
        int read_timeout_ms{1000};

        // Network interface to capture on.  Empty = auto-discover.
        std::string interface{};
    };

    // Ring Buffer
    struct RingBufferConfig
    {
        // Maximum CapturedPacket objects held before the Producer drops packets.
        // At 1500-byte average: 10 000 slots ≈ 15 MB queue RAM.
        std::size_t max_capacity{10'000};
    };

    // Flow Tracker
    struct FlowTrackerConfig
    {
        // Seconds of idle time before a TCP flow is evicted from the table.
        double tcp_flow_timeout_sec{120.0};

        // Seconds of idle time before a UDP flow is evicted.
        double udp_flow_timeout_sec{30.0};

        // How often the reaper thread wakes to evict expired flows.
        double reaper_interval_sec{15.0};

        // Maximum number of simultaneous flows tracked.  Beyond this, new flows
        // are not inserted (and a warning counter is incremented).
        std::size_t max_flows{500'000};
    };

    // EWMA Statistical Profiler
    struct EWMAConfig
    {
        // Smoothing factor alpha belongs to (0,1).
        // alpha = 0.125 -> baseline adapts slowly; resistant to short-lived bursts.
        double alpha{0.125};

        // Seconds of silence before a stale profile is reset to cold-start.
        double stale_reset_sec{60.0};

        // Minimum observation window (seconds) before anomaly scoring begins.
        // Prevents cold-start false positives on the very first measurement.
        double min_window_sec{1.0};

        // Instantaneous rate must exceed baseline × this multiplier to trigger a MEDIUM-severity volume anomaly.
        double medium_multiplier{4.0};

        // Multiplier for HIGH-severity volume anomaly.
        double high_multiplier{8.0};

        // Noise floor: EWMA baselines below this packets/sec are not used as a denominator (avoids near-zero division producing false ratios).
        double pps_floor{1.0};
    };

    // Port Scan Detector
    struct PortScanConfig
    {
        // Rolling window length in seconds.
        double window_sec{10.0};

        // Distinct destination ports contacted within the window = scan.
        uint32_t distinct_port_threshold{20};

        // SYN-only ratio required to confirm a scan (vs. legitimate multi-service client).  0.0 disables the ratio gate.
        double syn_only_ratio{0.70};
    };

    // SYN Flood Detector
    struct SynFloodConfig
    {
        // Minimum SYN-only packets per second from one source to trigger.
        double syn_rate_pps{50.0};

        // Minimum fraction of TCP packets that are SYN-only (no ACK).
        double syn_ratio{0.85};

        // Rolling window for the SYN rate calculation.
        double window_sec{1.0};
    };

    // Brute Force Detector
    struct BruteForceConfig
    {
        // Packets per second toward a single sensitive port = brute force.
        double rate_pps{20.0};

        // Ports monitored for brute-force.
        std::vector<uint16_t> sensitive_ports{22, 23, 21, 25, 110, 143, 3389, 5900};
    };

    // DNS Tunneling Detector
    struct DnsTunnelingConfig
    {
        // Query label length considered suspiciously long.
        std::size_t max_label_length{40};

        // Total FQDN length threshold.
        std::size_t max_fqdn_length{100};

        // TXT record queries per second from one source that triggers the rule.
        double txt_rate_pps{5.0};
    };

    // Alert Delivery
    struct DeliveryConfig
    {
        // Path to the SQLite3 alert database.
        std::string db_path{"alerts.db"};

        // ncurses dashboard refresh interval in milliseconds.
        int dashboard_refresh_ms{500};

        // Minimum seconds between repeated alerts of the same type from the same source IP - prevents flooding during sustained attacks.
        double alert_suppression_sec{5.0};
    };

    // Root Configuration  (aggregates all sub-configs)
    struct Config
    {
        CaptureConfig capture{};
        RingBufferConfig ring_buffer{};
        FlowTrackerConfig flow_tracker{};
        EWMAConfig ewma{};
        PortScanConfig port_scan{};
        SynFloodConfig syn_flood{};
        BruteForceConfig brute_force{};
        DnsTunnelingConfig dns_tunneling{};
        DeliveryConfig delivery{};

        // Version string built from CMake-injected macros.
        static std::string version()
        {
#if defined(NTE_VERSION_MAJOR) && defined(NTE_VERSION_MINOR) && defined(NTE_VERSION_PATCH)
            return std::to_string(NTE_VERSION_MAJOR) + "." + std::to_string(NTE_VERSION_MINOR) + "." + std::to_string(NTE_VERSION_PATCH);
#else
            return "0.0.0";
#endif
        }
    };

    // Compile-time constants (not user-tunable at runtime)
    namespace constants
    {
        // Ethernet header fixed size in bytes (no 802.1Q VLAN tag)
        constexpr std::size_t ETHERNET_HEADER_SIZE = 14;

        // Minimum IPv4 header size (no options)
        constexpr std::size_t IPV4_MIN_HEADER_SIZE = 20;

        // Fixed IPv6 header size
        constexpr std::size_t IPV6_HEADER_SIZE = 40;

        // Minimum TCP header size (no options)
        constexpr std::size_t TCP_MIN_HEADER_SIZE = 20;

        // Fixed UDP header size
        constexpr std::size_t UDP_HEADER_SIZE = 8;

        // Fixed DNS header size
        constexpr std::size_t DNS_HEADER_SIZE = 12;

        // EtherType values (host byte order, i.e., after ntohs())
        constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
        constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;
        constexpr uint16_t ETHERTYPE_ARP = 0x0806;
        constexpr uint16_t ETHERTYPE_VLAN = 0x8100;

        // IP protocol numbers
        constexpr uint8_t IPPROTO_ICMP_V4 = 1;
        constexpr uint8_t IPPROTO_TCP_NUM = 6;
        constexpr uint8_t IPPROTO_UDP_NUM = 17;
        constexpr uint8_t IPPROTO_ICMPV6 = 58;

        // TCP flag bitmasks
        constexpr uint8_t TCP_FLAG_FIN = 0x01;
        constexpr uint8_t TCP_FLAG_SYN = 0x02;
        constexpr uint8_t TCP_FLAG_RST = 0x04;
        constexpr uint8_t TCP_FLAG_PSH = 0x08;
        constexpr uint8_t TCP_FLAG_ACK = 0x10;
        constexpr uint8_t TCP_FLAG_URG = 0x20;
        constexpr uint8_t TCP_FLAG_ECE = 0x40;
        constexpr uint8_t TCP_FLAG_CWR = 0x80;

        // Well-known ports
        constexpr uint16_t PORT_DNS = 53;
        constexpr uint16_t PORT_HTTP = 80;
        constexpr uint16_t PORT_HTTPS = 443;
        constexpr uint16_t PORT_SSH = 22;
        constexpr uint16_t PORT_RDP = 3389;

        // TLS record type for Handshake
        constexpr uint8_t TLS_CONTENT_HANDSHAKE = 0x16;
        constexpr uint8_t TLS_HANDSHAKE_CLIENT_HELLO = 0x01;
        constexpr uint16_t TLS_EXTENSION_SNI = 0x0000;

        // DNS QTYPE values
        constexpr uint16_t DNS_QTYPE_A = 1;
        constexpr uint16_t DNS_QTYPE_AAAA = 28;
        constexpr uint16_t DNS_QTYPE_CNAME = 5;
        constexpr uint16_t DNS_QTYPE_MX = 15;
        constexpr uint16_t DNS_QTYPE_TXT = 16;

        // Maximum DNS label hops before treating a name as malformed
        constexpr std::size_t DNS_MAX_LABEL_HOPS = 128;

        // ncurses dashboard column widths
        constexpr int DASHBOARD_IP_COL_WIDTH = 40;
        constexpr int DASHBOARD_PORT_COL_WIDTH = 8;
        constexpr int DASHBOARD_PROTO_COL_WIDTH = 8;
        constexpr int DASHBOARD_FLAGS_COL_WIDTH = 14;
        constexpr int DASHBOARD_SEPARATOR_LEN = 146;
    }

} // namespace nte

#endif // NETWORK_THREAT_ENGINE_CONFIG_HPP