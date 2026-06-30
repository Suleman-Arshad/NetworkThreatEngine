#pragma once
#ifndef PROTOCOL_DISSECTOR_HPP
#define PROTOCOL_DISSECTOR_HPP
#include <array>
#include <cstdint>
#include <cstddef>
#include <optional>
#include <string>

#pragma pack(push, 1)

// Ethernet II header (14 bytes)
struct EthernetHeader
{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type; // EtherType field
};

namespace EtherType
{
    constexpr uint16_t IPv4 = 0x0800;
    constexpr uint16_t IPv6 = 0x86DD;
    constexpr uint16_t ARP = 0x0806;
    constexpr uint16_t VLAN_8021Q = 0x8100;
}

// IPv4 Header (20 bytes minimum; IHL field indicates options length)
struct IPv4Header
{
    uint8_t version_ihl; // upper nibble = version (4), lower = IHL (in 32-bit words)
    uint8_t dscp_ecn;
    uint16_t total_length;   // network byte order
    uint16_t identification; // network byte order
    uint16_t flags_fragment; // network byte orderupper 3 bits flags, lower 13 bits offset
    uint8_t ttl;
    uint8_t protocol;         // IPPROTO_TCP=6, IPPROTO_UDP=17, IPPROTO_ICMP=1
    uint16_t header_checksum; // network byte order
    uint32_t src_addr;        // network byte order
    uint32_t dst_addr;        // network byte order

    [[nodiscard]] uint8_t version() const noexcept
    {
        return static_cast<uint8_t>(version_ihl >> 4);
    }

    [[nodiscard]] uint8_t header_length_bytes() const noexcept
    {
        // IHL is in units of 32-bit (4-byte) words
        return static_cast<uint8_t>((version_ihl & 0x0F) * 4);
    }
};

// IPv6 Header (40 bytes fixed; extension headers not yet handled)
struct IPv6Header
{
    uint32_t version_class_flow; // upper 4 bits version, next 8 traffic class, lower 20 flow label
    uint16_t payload_length;     // network byte order
    uint8_t next_header;         // same value space as IPv4 protocol field
    uint8_t hop_limit;
    uint8_t src_addr[16];
    uint8_t dst_addr[16];

    [[nodiscard]] uint8_t version() const noexcept
    {
        const auto *bytes = reinterpret_cast<const uint8_t *>(&version_class_flow);
        return static_cast<uint8_t>(bytes[0] >> 4);
    }
};

// TCP Header (20 bytes minimum; data_offset field indicates options)
struct TCPHeader
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_number;
    uint32_t ack_number;
    uint8_t data_offset_reserved; // upper nibble = data offset in 32-bit words
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;

    [[nodiscard]] uint8_t header_length_bytes() const noexcept
    {
        return static_cast<uint8_t>(((data_offset_reserved & 0xF0) >> 4) * 4);
    }
};

// TCP flag bit masks (RFC 793 / RFC 3168)
namespace TCPFlag
{
    constexpr uint8_t FIN = 0x01;
    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t RST = 0x04;
    constexpr uint8_t PSH = 0x08;
    constexpr uint8_t ACK = 0x10;
    constexpr uint8_t URG = 0x20;
    constexpr uint8_t ECE = 0x40;
    constexpr uint8_t CWR = 0x80;
}

// UDP Header (8 bytes fixed)
struct UDPHeader
{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length; // network byte order — total length of UDP header + payload
    uint16_t checksum;
};

#pragma pack(pop)

// IP protocol number constants (IANA assigned)
namespace IPProtocol
{
    constexpr uint8_t ICMP = 1;
    constexpr uint8_t TCP = 6;
    constexpr uint8_t UDP = 17;
    constexpr uint8_t ICMPv6 = 58;
}

// Application layer signature Results

struct DnsSignature
{
    std::string query_name; // decoded e.g. "www.example.com"
    uint16_t query_type{0}; // A=1, AAAA=28, CNAME=5, MX=15, TXT=16, etc.
};

struct HttpSignature
{
    std::string method; // "GET", "POST", "HEAD", etc.
    std::string host;   // value of the "Host:" header
    std::string uri;    // request target, e.g. "/index.html"
};

struct TlsSignature
{
    std::string sni;         // Server Name Indication from ClientHello
    uint16_t tls_version{0}; // record-layer version field
};

enum class L3Protocol : uint8_t
{
    NONE = 0,
    IPv4,
    IPv6,
    ARP,
    OTHER
};

enum class L4Protocol : uint8_t
{
    NONE = 0,
    TCP,
    UDP,
    ICMP,
    OTHER
};

enum class L7Protocol : uint8_t
{
    NONE = 0,
    DNS,
    HTTP,
    TLS
};

struct DissectionResult
{
    // Layer 2
    bool has_ethernet{false};
    std::array<uint8_t, 6> src_mac{};
    std::array<uint8_t, 6> dst_mac{};
    uint16_t ether_type{0};

    // Layer 3
    L3Protocol l3_protocol{L3Protocol::NONE};
    std::string src_ip; // dotted-decimal (IPv4) or colon-hex (IPv6)
    std::string dst_ip;
    uint8_t ip_protocol_number{0};
    uint8_t ttl_or_hop_limit{0};
    uint16_t ip_total_length{0};

    // Layer 4
    L4Protocol l4_protocol{L4Protocol::NONE};
    uint16_t src_port{0};
    uint16_t dst_port{0};
    uint32_t tcp_seq_number{0};
    uint32_t tcp_ack_number{0};
    uint8_t tcp_flags{0};
    uint16_t tcp_window_size{0};

    // Layer 7
    L7Protocol l7_protocol{L7Protocol::NONE};
    std::optional<DnsSignature> dns;
    std::optional<HttpSignature> http;
    std::optional<TlsSignature> tls;

    // Payload reference
    const uint8_t *l7_payload{nullptr};
    std::size_t l7_payload_length{0};

    // Diagnostics
    bool truncated{false}; // true if any header didn't fully fit
    bool valid{false};     // true if at least L3 parsed successfully
};

// Public Entry Point
DissectionResult dissect_packet(const uint8_t *data, std::size_t length);

// Individual Layer Parsers
bool parse_ethernet(const uint8_t *data, std::size_t length, DissectionResult &result);
std::size_t parse_ipv4(const uint8_t *data, std::size_t length, DissectionResult &result);
std::size_t parse_ipv6(const uint8_t *data, std::size_t length, DissectionResult &result);
std::size_t parse_tcp(const uint8_t *data, std::size_t length, DissectionResult &result);
std::size_t parse_udp(const uint8_t *data, std::size_t length, DissectionResult &result);

// Layer 7 Signature Extractors
void extract_dns_signature(const uint8_t *payload, std::size_t payload_length, DissectionResult &result);
void extract_http_signature(const uint8_t *payload, std::size_t payload_length, DissectionResult &result);
void extract_tls_sni(const uint8_t *payload, std::size_t payload_length, DissectionResult &result);

// Formatting helpers
std::string format_ipv4_address(uint32_t host_order_addr);
std::string format_ipv6_address(const uint8_t addr[16]);
std::string format_mac_address(const uint8_t mac[6]);
std::string format_tcp_flags(uint8_t flags);
#endif // PROTOCOL_DISSECTOR_HPP