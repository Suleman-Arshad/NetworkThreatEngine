#include "ProtocolDissector.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <sstream>
#include <iomanip>

// Formatting Helpers
std::string format_mac_address(const uint8_t mac[6])
{
    char buf[18]; // "xx:xx:xx:xx:xx:xx" + null terminator
    std::snprintf(buf, sizeof(buf),
                  "%02x:%02x:%02x:%02x:%02x:%02x",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

std::string format_ipv4_address(uint32_t host_order_addr)
{
    char buf[16]; // "255.255.255.255" + null terminator
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  (host_order_addr >> 24) & 0xFF,
                  (host_order_addr >> 16) & 0xFF,
                  (host_order_addr >> 8) & 0xFF,
                  (host_order_addr) & 0xFF);
    return std::string(buf);
}

std::string format_ipv6_address(const uint8_t addr[16])
{
    // Build the 8 groups of 16-bit hex values first
    uint16_t groups[8];
    for (int i = 0; i < 8; ++i)
    {
        groups[i] = static_cast<uint16_t>((addr[i * 2] << 8) | addr[i * 2 + 1]);
    }
    // Find the longest run of consecutive zero groups for "::" compression
    // (RFC 5952 canonical form)
    int best_start = -1;
    int best_len = 0;
    int cur_start = -1;
    int cur_len = 0;

    for (int i = 0; i < 8; ++i)
    {
        if (groups[i] == 0)
        {
            if (cur_start == -1)
            {
                cur_start = i;
            }
            ++cur_len;

            if (cur_len > best_len)
            {
                best_len = cur_len;
                best_start = cur_start;
            }
        }
        else
        {
            cur_start = -1;
            cur_len = 0;
        }
    }
    // RFC 5952: only compress runs of 2 or more zero groups
    if (best_len < 2)
    {
        best_start = -1;
        best_len = 0;
    }

    std::ostringstream oss;
    oss << std::hex;

    for (int i = 0; i < 8;)
    {
        if (i == best_start)
        {
            oss << "::";
            i += best_len;

            // Skip the leading colon-pair handling for subsequent groups
            if (i >= 8)
            {
                break;
            }
            oss << groups[i];
            ++i;
            continue;
        }

        if (i != 0 && i != best_start + best_len)
        {
            oss << ":";
        }

        oss << groups[i];
        ++i;
    }

    return oss.str();
}

std::string format_tcp_flags(uint8_t flags)
{
    std::string out;

    auto append = [&out](const char *name)
    {
        if (!out.empty())
        {
            out += ",";
        }
        out += name;
    };
    if (flags & TCPFlag::CWR)
        append("CWR");
    if (flags & TCPFlag::ECE)
        append("ECE");
    if (flags & TCPFlag::URG)
        append("URG");
    if (flags & TCPFlag::ACK)
        append("ACK");
    if (flags & TCPFlag::PSH)
        append("PSH");
    if (flags & TCPFlag::RST)
        append("RST");
    if (flags & TCPFlag::SYN)
        append("SYN");
    if (flags & TCPFlag::FIN)
        append("FIN");

    return out.empty() ? std::string("NONE") : out;
}

// Layer 2: Ethernet
bool parse_ethernet(const uint8_t *data, std::size_t length, DissectionResult &result)
{
    if (data == nullptr || length < sizeof(EthernetHeader))
    {
        result.truncated = true;
        return false;
    }

    const auto *eth = reinterpret_cast<const EthernetHeader *>(data);

    std::memcpy(result.dst_mac.data(), eth->dst_mac, 6);
    std::memcpy(result.src_mac.data(), eth->src_mac, 6);

    // ether_type is a 16-bit field in network byte order — convert with ntohs()
    result.ether_type = ntohs(eth->ether_type);
    result.has_ethernet = true;

    return true;
}

// Layer 3: IP (IPv4 and IPv6)
std::size_t parse_ipv4(const uint8_t *data, std::size_t length, DissectionResult &result)
{
    if (data == nullptr || length < sizeof(IPv4Header))
    {
        result.truncated = true;
        return 0;
    }

    const auto *ip = reinterpret_cast<const IPv4Header *>(data);

    // Validate the IP version field actually says 4 — defends against misclassified EtherType or corrupted captures.
    if (ip->version() != 4)
    {
        return 0;
    }

    const std::size_t header_len = ip->header_length_bytes();

    if (header_len < sizeof(IPv4Header) || header_len > length)
    {
        result.truncated = true;
        return 0;
    }

    result.l3_protocol = L3Protocol::IPv4;
    result.ip_protocol_number = ip->protocol;
    result.ttl_or_hop_limit = ip->ttl;

    // total_length and addr fields are network byte order convert before use
    result.ip_total_length = ntohs(ip->total_length);
    result.src_ip = format_ipv4_address(ntohl(ip->src_addr));
    result.dst_ip = format_ipv4_address(ntohl(ip->dst_addr));

    result.valid = true;

    return header_len;
}

// IPv6
std::size_t parse_ipv6(const uint8_t *data, std::size_t length, DissectionResult &result)
{
    if (data == nullptr || length < sizeof(IPv6Header))
    {
        result.truncated = true;
        return 0;
    }

    const auto *ip = reinterpret_cast<const IPv6Header *>(data);

    if (ip->version() != 6)
    {
        return 0;
    }

    result.l3_protocol = L3Protocol::IPv6;
    result.ip_protocol_number = ip->next_header;
    result.ttl_or_hop_limit = ip->hop_limit;

    // payload_length is network byte order — convert before use.  This is the length of everything AFTER the fixed 40-byte header, not the total packet length, unlike IPv4's total_length field.
    result.ip_total_length = static_cast<uint16_t>(
        ntohs(ip->payload_length) + sizeof(IPv6Header));

    result.src_ip = format_ipv6_address(ip->src_addr);
    result.dst_ip = format_ipv6_address(ip->dst_addr);

    result.valid = true;

    return sizeof(IPv6Header);
}

// Layer 4: TCP
std::size_t parse_tcp(const uint8_t *data, std::size_t length, DissectionResult &result)
{
    if (data == nullptr || length < sizeof(TCPHeader))
    {
        result.truncated = true;
        return 0;
    }

    const auto *tcp = reinterpret_cast<const TCPHeader *>(data);

    const std::size_t header_len = tcp->header_length_bytes();

    if (header_len < sizeof(TCPHeader) || header_len > length)
    {
        result.truncated = true;
        return 0;
    }

    result.l4_protocol = L4Protocol::TCP;
    result.src_port = ntohs(tcp->src_port);
    result.dst_port = ntohs(tcp->dst_port);
    result.tcp_seq_number = ntohl(tcp->seq_number);
    result.tcp_ack_number = ntohl(tcp->ack_number);
    result.tcp_flags = tcp->flags; // single byte no byte-order conversion needed
    result.tcp_window_size = ntohs(tcp->window_size);

    return header_len;
}

// Layer 4: UDP
std::size_t parse_udp(const uint8_t *data, std::size_t length, DissectionResult &result)
{
    if (data == nullptr || length < sizeof(UDPHeader))
    {
        result.truncated = true;
        return 0;
    }

    const auto *udp = reinterpret_cast<const UDPHeader *>(data);

    result.l4_protocol = L4Protocol::UDP;
    result.src_port = ntohs(udp->src_port);
    result.dst_port = ntohs(udp->dst_port);

    return sizeof(UDPHeader);
}

// Layer 7 : DNS
namespace
{
    constexpr std::size_t DNS_HEADER_SIZE = 12;
    constexpr std::size_t MAX_DNS_LABEL_HOPS = 128; // guards against malformed loops
}

void extract_dns_signature(const uint8_t *payload, std::size_t payload_length, DissectionResult &result)
{
    if (payload == nullptr || payload_length < DNS_HEADER_SIZE + 5)
    {
        // Minimum: 12-byte header + at least 1 label byte + 0x00 terminator + QTYPE(2) + QCLASS(2)
        return;
    }

    // QDCOUNT lives at offset 4-5 in the DNS header, network byte order.
    const uint16_t qdcount = static_cast<uint16_t>(
        (payload[4] << 8) | payload[5]);

    if (qdcount == 0)
    {
        // No questions present likely a pure response or malformed packet
        return;
    }

    std::size_t offset = DNS_HEADER_SIZE;
    std::string name;
    std::size_t hop_count = 0;

    while (offset < payload_length && hop_count < MAX_DNS_LABEL_HOPS)
    {
        const uint8_t label_len = payload[offset];

        // Zero-length label marks the end of the QNAME
        if (label_len == 0)
        {
            ++offset; // consume the terminating zero byte
            break;
        }
        if ((label_len & 0xC0) == 0xC0)
        {
            return;
        }

        ++offset; // move past the length byte

        if (offset + label_len > payload_length)
        {
            // Label claims more bytes than are actually available
            return;
        }

        if (!name.empty())
        {
            name += '.';
        }

        name.append(reinterpret_cast<const char *>(payload + offset), label_len);
        offset += label_len;
        ++hop_count;
    }

    if (name.empty() || offset + 2 > payload_length)
    {
        return;
    }

    // QTYPE immediately follows the terminating zero byte, network byte order
    const uint16_t qtype = static_cast<uint16_t>(
        (payload[offset] << 8) | payload[offset + 1]);

    DnsSignature sig;
    sig.query_name = std::move(name);
    sig.query_type = qtype;

    result.dns = std::move(sig);
    result.l7_protocol = L7Protocol::DNS;
}

namespace
{
    bool starts_with(const uint8_t *data, std::size_t length, const char *prefix)
    {
        const std::size_t prefix_len = std::strlen(prefix);

        if (length < prefix_len)
        {
            return false;
        }

        return std::memcmp(data, prefix, prefix_len) == 0;
    }

    std::size_t find_line_end(const uint8_t *data, std::size_t offset, std::size_t length)
    {
        for (std::size_t i = offset; i + 1 < length; ++i)
        {
            if (data[i] == '\r' && data[i + 1] == '\n')
            {
                return i + 2;
            }
        }
        return std::string::npos;
    }
}

void extract_http_signature(const uint8_t *payload, std::size_t payload_length, DissectionResult &result)
{
    if (payload == nullptr || payload_length < 16)
    {
        return;
    }

    static constexpr const char *kMethods[] = {
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "};

    std::string detected_method;

    for (const char *method : kMethods)
    {
        if (starts_with(payload, payload_length, method))
        {
            detected_method.assign(method, std::strlen(method) - 1); // trim trailing space
            break;
        }
    }

    if (detected_method.empty())
    {
        return; // not an HTTP request we recognise
    }

    // Parse the request line: "METHOD <uri> HTTP/x.x\r\n"
    const std::size_t request_line_end = find_line_end(payload, 0, payload_length);

    if (request_line_end == std::string::npos)
    {
        return;
    }

    const std::size_t method_len = detected_method.size() + 1; // include the space
    const std::size_t uri_start = method_len;
    std::size_t uri_end = uri_start;

    while (uri_end < request_line_end && payload[uri_end] != ' ')
    {
        ++uri_end;
    }

    std::string uri(reinterpret_cast<const char *>(payload + uri_start),
                    uri_end - uri_start);

    // Scan subsequent header lines for "Host:"
    std::string host_value;
    std::size_t line_start = request_line_end;

    while (line_start < payload_length)
    {
        const std::size_t line_end = find_line_end(payload, line_start, payload_length);

        if (line_end == std::string::npos)
        {
            break;
        }

        // An empty line (just \r\n) marks the end of the header section
        if (line_end == line_start + 2)
        {
            break;
        }

        if (starts_with(payload + line_start, line_end - line_start, "Host:"))
        {
            std::size_t value_start = line_start + 5; // skip "Host:"

            // Skip a single optional leading space
            if (value_start < line_end && payload[value_start] == ' ')
            {
                ++value_start;
            }

            const std::size_t value_end = line_end - 2; // strip trailing \r\n

            if (value_end > value_start)
            {
                host_value.assign(
                    reinterpret_cast<const char *>(payload + value_start),
                    value_end - value_start);
            }

            break;
        }

        line_start = line_end;
    }

    HttpSignature sig;
    sig.method = std::move(detected_method);
    sig.uri = std::move(uri);
    sig.host = std::move(host_value);

    result.http = std::move(sig);
    result.l7_protocol = L7Protocol::HTTP;
}

namespace
{
    constexpr uint8_t TLS_CONTENT_TYPE_HANDSHAKE = 0x16;
    constexpr uint8_t TLS_HANDSHAKE_TYPE_CLIENTHELLO = 0x01;
    constexpr uint16_t TLS_EXTENSION_SNI = 0x0000;
    constexpr uint8_t SNI_NAME_TYPE_HOSTNAME = 0x00;

    uint16_t read_u16_be(const uint8_t *p)
    {
        return static_cast<uint16_t>((p[0] << 8) | p[1]);
    }

    uint32_t read_u24_be(const uint8_t *p)
    {
        return (static_cast<uint32_t>(p[0]) << 16) |
               (static_cast<uint32_t>(p[1]) << 8) |
               static_cast<uint32_t>(p[2]);
    }
}

void extract_tls_sni(const uint8_t *payload, std::size_t payload_length, DissectionResult &result)
{
    if (payload == nullptr || payload_length < 43)
    {
        return;
    }

    // TLS Record Header
    if (payload[0] != TLS_CONTENT_TYPE_HANDSHAKE)
    {
        return;
    }

    const uint16_t record_version = read_u16_be(payload + 1);
    const uint16_t record_length = read_u16_be(payload + 3);

    if (5u + record_length > payload_length)
    {
        return;
    }

    std::size_t offset = 5;

    // Handshake Header
    if (offset + 4 > payload_length || payload[offset] != TLS_HANDSHAKE_TYPE_CLIENTHELLO)
    {
        return;
    }

    const uint32_t handshake_length = read_u24_be(payload + offset + 1);
    offset += 4;

    const std::size_t handshake_end = offset + handshake_length;

    if (handshake_end > payload_length)
    {
        return;
    }

    // ClientHello Body
    if (offset + 34 > payload_length)
    {
        return;
    }
    offset += 34;

    // Session ID
    if (offset + 1 > payload_length)
    {
        return;
    }
    const uint8_t session_id_len = payload[offset];
    offset += 1 + session_id_len;

    // Cipher Suites
    if (offset + 2 > payload_length)
    {
        return;
    }
    const uint16_t cipher_suites_len = read_u16_be(payload + offset);
    offset += 2 + cipher_suites_len;

    // Compression Methods
    if (offset + 1 > payload_length)
    {
        return;
    }
    const uint8_t compression_methods_len = payload[offset];
    offset += 1 + compression_methods_len;

    // Extensions block
    if (offset + 2 > payload_length)
    {
        return;
    }
    const uint16_t extensions_total_len = read_u16_be(payload + offset);
    offset += 2;

    const std::size_t extensions_end = offset + extensions_total_len;

    if (extensions_end > payload_length || extensions_end > handshake_end)
    {
        return;
    }

    // Walk the Extension list looking for SNI (type 0x0000)
    while (offset + 4 <= extensions_end)
    {
        const uint16_t ext_type = read_u16_be(payload + offset);
        const uint16_t ext_length = read_u16_be(payload + offset + 2);
        offset += 4;

        if (offset + ext_length > extensions_end)
        {
            return; // malformed extension length
        }

        if (ext_type == TLS_EXTENSION_SNI)
        {
            std::size_t sni_offset = offset;

            if (sni_offset + 2 > offset + ext_length)
            {
                return;
            }

            const uint16_t server_name_list_len = read_u16_be(payload + sni_offset);
            sni_offset += 2;
            const std::size_t list_end = sni_offset + server_name_list_len;
            if (list_end > offset + ext_length)
            {
                return;
            }

            while (sni_offset + 3 <= list_end)
            {
                const uint8_t name_type = payload[sni_offset];
                const uint16_t name_len = read_u16_be(payload + sni_offset + 1);
                sni_offset += 3;

                if (sni_offset + name_len > list_end)
                {
                    return;
                }

                if (name_type == SNI_NAME_TYPE_HOSTNAME)
                {
                    TlsSignature sig;
                    sig.sni.assign(
                        reinterpret_cast<const char *>(payload + sni_offset),
                        name_len);
                    sig.tls_version = record_version;

                    result.tls = std::move(sig);
                    result.l7_protocol = L7Protocol::TLS;
                    return;
                }

                sni_offset += name_len;
            }

            return; // SNI extension present but no hostname entry found
        }

        offset += ext_length;
    }
}

// Top-Level Orchestration
DissectionResult dissect_packet(const uint8_t *data, std::size_t length)
{
    DissectionResult result;

    if (data == nullptr || length == 0)
    {
        result.truncated = true;
        return result;
    }

    // Layer 2
    if (!parse_ethernet(data, length, result))
    {
        return result;
    }

    const uint8_t *l3_data = data + sizeof(EthernetHeader);
    const std::size_t l3_length = length - sizeof(EthernetHeader);

    std::size_t l3_header_len = 0;

    // Layer 3
    if (result.ether_type == EtherType::IPv4)
    {
        l3_header_len = parse_ipv4(l3_data, l3_length, result);
    }
    else if (result.ether_type == EtherType::IPv6)
    {
        l3_header_len = parse_ipv6(l3_data, l3_length, result);
    }
    else if (result.ether_type == EtherType::ARP)
    {
        result.l3_protocol = L3Protocol::ARP;
        result.valid = true;
        return result; // ARP carries no L4/L7 payload to dissect further
    }
    else
    {
        result.l3_protocol = L3Protocol::OTHER;
        return result;
    }

    if (l3_header_len == 0)
    {
        return result; // L3 parse failed or was truncated
    }

    const uint8_t *l4_data = l3_data + l3_header_len;
    const std::size_t l4_length = l3_length - l3_header_len;

    std::size_t l4_header_len = 0;

    // Layer 4
    if (result.ip_protocol_number == IPProtocol::TCP)
    {
        l4_header_len = parse_tcp(l4_data, l4_length, result);
    }
    else if (result.ip_protocol_number == IPProtocol::UDP)
    {
        l4_header_len = parse_udp(l4_data, l4_length, result);
    }
    else if (result.ip_protocol_number == IPProtocol::ICMP ||
             result.ip_protocol_number == IPProtocol::ICMPv6)
    {
        result.l4_protocol = L4Protocol::ICMP;
        return result; // no port-based L7 dissection for ICMP
    }
    else
    {
        result.l4_protocol = L4Protocol::OTHER;
        return result;
    }

    if (l4_header_len == 0)
    {
        return result; // L4 parse failed or was truncated
    }

    const uint8_t *l7_data = l4_data + l4_header_len;
    const std::size_t l7_length = l4_length - l4_header_len;

    result.l7_payload = l7_data;
    result.l7_payload_length = l7_length;

    if (l7_length == 0)
    {
        return result; // pure ACK / empty-payload segment — nothing to inspect
    }

    // Layer 7 dispatch by well-known port
    const bool is_dns = (result.src_port == 53 || result.dst_port == 53);
    const bool is_http = (result.src_port == 80 || result.dst_port == 80);
    const bool is_tls = (result.src_port == 443 || result.dst_port == 443);

    if (is_dns)
    {
        extract_dns_signature(l7_data, l7_length, result);
    }
    else if (is_http && result.l4_protocol == L4Protocol::TCP)
    {
        extract_http_signature(l7_data, l7_length, result);
    }
    else if (is_tls && result.l4_protocol == L4Protocol::TCP)
    {
        extract_tls_sni(l7_data, l7_length, result);
    }
    else if (result.l4_protocol == L4Protocol::TCP)
    {
        extract_http_signature(l7_data, l7_length, result);
    }
    return result;
}