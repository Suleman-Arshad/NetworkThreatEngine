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

// Layer 3: IP (IPv4)
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