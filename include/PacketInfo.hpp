#pragma once
#ifndef NETWORK_THREAT_ENGINE_PACKET_INFO_HPP
#define NETWORK_THREAT_ENGINE_PACKET_INFO_HPP
#include <array>
#include <cstdint>
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace nte
{
    enum class L3Protocol : uint8_t
    {
        NONE = 0,
        IPv4 = 1,
        IPv6 = 2,
        ARP = 3,
        OTHER = 4
    };

    enum class L4Protocol : uint8_t
    {
        NONE = 0,
        TCP = 1,
        UDP = 2,
        ICMP = 3,
        OTHER = 4
    };

    enum class L7Protocol : uint8_t
    {
        NONE = 0,
        DNS = 1,
        HTTP = 2,
        TLS = 3,
        OTHER = 4
    };

    // Application-layer signature payloads
    // Populated by the dissector only when the corresponding protocol is detected.
    struct DnsInfo
    {
        std::string query_name;  // decoded FQDN, e.g. "www.example.com"
        uint16_t query_type{0};  // QTYPE: A=1, AAAA=28, TXT=16, MX=15, etc.
        bool is_response{false}; // QR bit: false=query, true=response
    };

    struct HttpInfo
    {
        std::string method; // "GET", "POST", "PUT", "DELETE", etc.
        std::string host;   // value of the Host: header
        std::string uri;    // request-target, e.g. "/index.html"
    };

    struct TlsInfo
    {
        std::string sni;            // Server Name Indication from ClientHello
        uint16_t record_version{0}; // TLS record-layer version field
    };

    // CapturedPacket
    struct CapturedPacket
    {
        // Raw frame bytes copied from the kernel ring buffer.
        // Sized exactly to captured_length - no padding.
        std::vector<uint8_t> data;

        // Bytes actually captured (<= original_length if snaplen truncated).
        uint32_t captured_length{0};

        // Original wire length before kernel truncation.
        uint32_t original_length{0};

        // Kernel capture timestamp in microseconds since the Unix epoch.
        // Computed from pcap_pkthdr.ts as:
        //   tv_sec * 1_000_000 + tv_usec
        int64_t timestamp_us{0};

        // Constructors

        CapturedPacket() = default;

        CapturedPacket(const uint8_t *raw,
                       uint32_t cap_len,
                       uint32_t orig_len,
                       int64_t ts_us)
            : data(raw, raw + cap_len), captured_length(cap_len), original_length(orig_len), timestamp_us(ts_us)
        {
        }

        // Move-only
        CapturedPacket(CapturedPacket &&) noexcept = default;
        CapturedPacket &operator=(CapturedPacket &&) noexcept = default;

        // Copies explicitly disabled
        CapturedPacket(const CapturedPacket &) = delete;
        CapturedPacket &operator=(const CapturedPacket &) = delete;
    };

    struct PacketInfo
    {
        // Layer 2
        bool has_ethernet{false};
        std::array<uint8_t, 6> src_mac{};
        std::array<uint8_t, 6> dst_mac{};
        uint16_t ether_type{0}; // host byte order after ntohs()

        // Layer 3
        L3Protocol l3_proto{L3Protocol::NONE};
        std::string src_ip; // dotted-decimal (IPv4) or colon-hex (IPv6)
        std::string dst_ip;
        uint8_t ip_proto_num{0}; // raw IANA protocol number
        uint8_t ttl_or_hop_limit{0};
        uint16_t ip_total_length{0}; // host byte order
        bool ip_fragmented{false};   // MF flag set or fragment offset > 0

        // Layer 4
        L4Protocol l4_proto{L4Protocol::NONE};
        uint16_t src_port{0};
        uint16_t dst_port{0};

        // TCP-specific
        uint32_t tcp_seq{0};
        uint32_t tcp_ack{0};
        uint8_t tcp_flags{0}; // raw flag byte; use constants::TCP_FLAG_*
        uint16_t tcp_window{0};

        // Layer 7
        L7Protocol l7_proto{L7Protocol::NONE};
        std::optional<DnsInfo> dns;
        std::optional<HttpInfo> http;
        std::optional<TlsInfo> tls;

        // Non-owning pointer into the CapturedPacket's data buffer.
        const uint8_t *l7_payload{nullptr};
        std::size_t l7_payload_length{0};

        // Capture metadata
        int64_t timestamp_us{0};
        uint32_t captured_length{0};
        uint32_t original_length{0};

        // Parse diagnostics
        bool valid{false};     // true if at least L3 parsed successfully
        bool truncated{false}; // true if any header exceeded captured_length
    };

} // namespace nte

#endif // NETWORK_THREAT_ENGINE_PACKET_INFO_HPP