#include "Config.hpp"
#include "PacketInfo.hpp"
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>

namespace nte
{

    // Wire-format structs  (packed - no compiler padding)
#pragma pack(push, 1)

    struct WireEthernet
    {
        uint8_t dst_mac[6];
        uint8_t src_mac[6];
        uint16_t ether_type; // network byte order
    };

    struct WireIPv4
    {
        uint8_t version_ihl;
        uint8_t dscp_ecn;
        uint16_t total_length;
        uint16_t identification;
        uint16_t flags_fragment;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t checksum;
        uint32_t src_addr;
        uint32_t dst_addr;

        [[nodiscard]] uint8_t ihl_bytes() const noexcept
        {
            return static_cast<uint8_t>((version_ihl & 0x0F) * 4);
        }

        [[nodiscard]] uint8_t version() const noexcept
        {
            return static_cast<uint8_t>(version_ihl >> 4);
        }

        [[nodiscard]] bool more_fragments() const noexcept
        {
            return (ntohs(flags_fragment) & 0x2000) != 0;
        }

        [[nodiscard]] uint16_t fragment_offset() const noexcept
        {
            return static_cast<uint16_t>(ntohs(flags_fragment) & 0x1FFF);
        }
    };

    struct WireIPv6
    {
        uint32_t version_class_flow;
        uint16_t payload_length;
        uint8_t next_header;
        uint8_t hop_limit;
        uint8_t src_addr[16];
        uint8_t dst_addr[16];

        [[nodiscard]] uint8_t version() const noexcept
        {
            const auto *b = reinterpret_cast<const uint8_t *>(&version_class_flow);
            return static_cast<uint8_t>(b[0] >> 4);
        }
    };

    struct WireTCP
    {
        uint16_t src_port;
        uint16_t dst_port;
        uint32_t seq_number;
        uint32_t ack_number;
        uint8_t data_offset_reserved;
        uint8_t flags;
        uint16_t window_size;
        uint16_t checksum;
        uint16_t urgent_pointer;

        [[nodiscard]] uint8_t header_bytes() const noexcept
        {
            return static_cast<uint8_t>(((data_offset_reserved & 0xF0) >> 4) * 4);
        }
    };

    struct WireUDP
    {
        uint16_t src_port;
        uint16_t dst_port;
        uint16_t length;
        uint16_t checksum;
    };

#pragma pack(pop)

    // Formatting helpers
    static std::string format_ipv4(uint32_t host_order_addr)
    {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                      (host_order_addr >> 24) & 0xFF,
                      (host_order_addr >> 16) & 0xFF,
                      (host_order_addr >> 8) & 0xFF,
                      (host_order_addr) & 0xFF);
        return std::string(buf);
    }

    static std::string format_ipv6(const uint8_t addr[16])
    {
        // Build 8 groups of uint16_t
        uint16_t groups[8];
        for (int i = 0; i < 8; ++i)
        {
            groups[i] = static_cast<uint16_t>(
                (static_cast<uint16_t>(addr[i * 2]) << 8) | addr[i * 2 + 1]);
        }

        // Find longest run of consecutive zero groups for :: compression
        int best_start = -1, best_len = 0;
        int cur_start = -1, cur_len = 0;

        for (int i = 0; i < 8; ++i)
        {
            if (groups[i] == 0)
            {
                if (cur_start == -1)
                    cur_start = i;
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

        if (best_len < 2)
        {
            best_start = -1;
        }

        std::ostringstream oss;
        oss << std::hex;

        for (int i = 0; i < 8;)
        {
            if (i == best_start)
            {
                oss << "::";
                i += best_len;
                if (i >= 8)
                    break;
                oss << groups[i++];
                continue;
            }
            if (i != 0 && !(i == best_start + best_len && best_start == 0))
                oss << ":";
            oss << groups[i++];
        }

        return oss.str();
    }

    static std::string format_mac(const uint8_t mac[6])
    {
        char buf[18];
        std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                      mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return std::string(buf);
    }

    // Layer 7 extractors (forward declarations)
    static void extract_dns(const uint8_t *payload, std::size_t len, PacketInfo &info);
    static void extract_http(const uint8_t *payload, std::size_t len, PacketInfo &info);
    static void extract_tls(const uint8_t *payload, std::size_t len, PacketInfo &info);

    // Primary entry point
    PacketInfo dissect_packet(const CapturedPacket &raw)
    {
        PacketInfo info;
        info.timestamp_us = raw.timestamp_us;
        info.captured_length = raw.captured_length;
        info.original_length = raw.original_length;

        const uint8_t *data = raw.data.data();
        const std::size_t len = raw.captured_length;

        if (data == nullptr || len == 0)
            return info;

        // Layer 2: Ethernet
        if (len < sizeof(WireEthernet))
        {
            info.truncated = true;
            return info;
        }

        const auto *eth = reinterpret_cast<const WireEthernet *>(data);
        std::memcpy(info.dst_mac.data(), eth->dst_mac, 6);
        std::memcpy(info.src_mac.data(), eth->src_mac, 6);
        info.ether_type = ntohs(eth->ether_type);
        info.has_ethernet = true;

        // Handle 802.1Q VLAN tag - skip the 4-byte tag and re-read EtherType
        std::size_t l3_offset = sizeof(WireEthernet);

        if (info.ether_type == constants::ETHERTYPE_VLAN)
        {
            if (len < l3_offset + 4)
            {
                info.truncated = true;
                return info;
            }
            // VLAN tag: PCP(3) DEI(1) VID(12) EtherType(16)
            info.ether_type = ntohs(
                *reinterpret_cast<const uint16_t *>(data + l3_offset + 2));
            l3_offset += 4;
        }

        // Layer 3: IPv4
        if (info.ether_type == constants::ETHERTYPE_IPV4)
        {
            if (len < l3_offset + sizeof(WireIPv4))
            {
                info.truncated = true;
                return info;
            }

            const auto *ip = reinterpret_cast<const WireIPv4 *>(data + l3_offset);

            if (ip->version() != 4)
            {
                return info;
            }

            const std::size_t ihl = ip->ihl_bytes();

            if (ihl < sizeof(WireIPv4) || len < l3_offset + ihl)
            {
                info.truncated = true;
                return info;
            }

            info.l3_proto = L3Protocol::IPv4;
            info.ip_proto_num = ip->protocol;
            info.ttl_or_hop_limit = ip->ttl;
            info.ip_total_length = ntohs(ip->total_length);
            info.ip_fragmented = ip->more_fragments() || ip->fragment_offset() > 0;
            info.src_ip = format_ipv4(ntohl(ip->src_addr));
            info.dst_ip = format_ipv4(ntohl(ip->dst_addr));
            info.valid = true;

            const std::size_t l4_offset = l3_offset + ihl;
            const std::size_t l4_len = len - l4_offset;

            // Layer 4 dispatch
            if (ip->protocol == constants::IPPROTO_TCP_NUM)
            {
                if (l4_len < sizeof(WireTCP))
                {
                    info.truncated = true;
                    return info;
                }

                const auto *tcp =
                    reinterpret_cast<const WireTCP *>(data + l4_offset);
                const std::size_t tcp_hdr = tcp->header_bytes();

                if (tcp_hdr < sizeof(WireTCP) || l4_len < tcp_hdr)
                {
                    info.truncated = true;
                    return info;
                }

                info.l4_proto = L4Protocol::TCP;
                info.src_port = ntohs(tcp->src_port);
                info.dst_port = ntohs(tcp->dst_port);
                info.tcp_seq = ntohl(tcp->seq_number);
                info.tcp_ack = ntohl(tcp->ack_number);
                info.tcp_flags = tcp->flags;
                info.tcp_window = ntohs(tcp->window_size);

                const std::size_t l7_offset = l4_offset + tcp_hdr;
                const std::size_t l7_len = len - l7_offset;

                if (l7_len > 0)
                {
                    info.l7_payload = data + l7_offset;
                    info.l7_payload_length = l7_len;

                    // Layer 7 dispatch
                    if (info.dst_port == constants::PORT_DNS ||
                        info.src_port == constants::PORT_DNS)
                    {
                        extract_dns(data + l7_offset, l7_len, info);
                    }
                    else if (info.dst_port == constants::PORT_HTTPS ||
                             info.src_port == constants::PORT_HTTPS)
                    {
                        extract_tls(data + l7_offset, l7_len, info);
                    }
                    else if (info.dst_port == constants::PORT_HTTP ||
                             info.src_port == constants::PORT_HTTP)
                    {
                        extract_http(data + l7_offset, l7_len, info);
                    }
                    else
                    {
                        // Opportunistic HTTP detection on non-standard ports
                        extract_http(data + l7_offset, l7_len, info);
                    }
                }
            }
            else if (ip->protocol == constants::IPPROTO_UDP_NUM)
            {
                if (l4_len < sizeof(WireUDP))
                {
                    info.truncated = true;
                    return info;
                }

                const auto *udp =
                    reinterpret_cast<const WireUDP *>(data + l4_offset);

                info.l4_proto = L4Protocol::UDP;
                info.src_port = ntohs(udp->src_port);
                info.dst_port = ntohs(udp->dst_port);

                const std::size_t l7_offset = l4_offset + sizeof(WireUDP);
                const std::size_t l7_len = len - l7_offset;

                if (l7_len > 0)
                {
                    info.l7_payload = data + l7_offset;
                    info.l7_payload_length = l7_len;

                    if (info.dst_port == constants::PORT_DNS ||
                        info.src_port == constants::PORT_DNS)
                    {
                        extract_dns(data + l7_offset, l7_len, info);
                    }
                }
            }
            else if (ip->protocol == constants::IPPROTO_ICMP_V4)
            {
                info.l4_proto = L4Protocol::ICMP;
            }
            else
            {
                info.l4_proto = L4Protocol::OTHER;
            }
        }

        // Layer 3: IPv6
        else if (info.ether_type == constants::ETHERTYPE_IPV6)
        {
            if (len < l3_offset + sizeof(WireIPv6))
            {
                info.truncated = true;
                return info;
            }

            const auto *ip6 =
                reinterpret_cast<const WireIPv6 *>(data + l3_offset);

            if (ip6->version() != 6)
            {
                return info;
            }

            info.l3_proto = L3Protocol::IPv6;
            info.ip_proto_num = ip6->next_header;
            info.ttl_or_hop_limit = ip6->hop_limit;
            info.ip_total_length = static_cast<uint16_t>(
                ntohs(ip6->payload_length) + sizeof(WireIPv6));
            info.src_ip = format_ipv6(ip6->src_addr);
            info.dst_ip = format_ipv6(ip6->dst_addr);
            info.valid = true;

            const std::size_t l4_offset = l3_offset + sizeof(WireIPv6);
            const std::size_t l4_len = len - l4_offset;

            if (ip6->next_header == constants::IPPROTO_TCP_NUM && l4_len >= sizeof(WireTCP))
            {
                const auto *tcp =
                    reinterpret_cast<const WireTCP *>(data + l4_offset);
                const std::size_t tcp_hdr = tcp->header_bytes();

                if (tcp_hdr >= sizeof(WireTCP) && l4_len >= tcp_hdr)
                {
                    info.l4_proto = L4Protocol::TCP;
                    info.src_port = ntohs(tcp->src_port);
                    info.dst_port = ntohs(tcp->dst_port);
                    info.tcp_seq = ntohl(tcp->seq_number);
                    info.tcp_ack = ntohl(tcp->ack_number);
                    info.tcp_flags = tcp->flags;
                    info.tcp_window = ntohs(tcp->window_size);

                    const std::size_t l7_offset = l4_offset + tcp_hdr;
                    const std::size_t l7_len = len - l7_offset;

                    if (l7_len > 0)
                    {
                        info.l7_payload = data + l7_offset;
                        info.l7_payload_length = l7_len;

                        if (info.dst_port == constants::PORT_HTTPS ||
                            info.src_port == constants::PORT_HTTPS)
                        {
                            extract_tls(data + l7_offset, l7_len, info);
                        }
                        else if (info.dst_port == constants::PORT_HTTP ||
                                 info.src_port == constants::PORT_HTTP)
                        {
                            extract_http(data + l7_offset, l7_len, info);
                        }
                    }
                }
            }
            else if (ip6->next_header == constants::IPPROTO_UDP_NUM &&
                     l4_len >= sizeof(WireUDP))
            {
                const auto *udp =
                    reinterpret_cast<const WireUDP *>(data + l4_offset);

                info.l4_proto = L4Protocol::UDP;
                info.src_port = ntohs(udp->src_port);
                info.dst_port = ntohs(udp->dst_port);

                const std::size_t l7_offset = l4_offset + sizeof(WireUDP);
                const std::size_t l7_len = len - l7_offset;

                if (l7_len > 0 &&
                    (info.dst_port == constants::PORT_DNS ||
                     info.src_port == constants::PORT_DNS))
                {
                    info.l7_payload = data + l7_offset;
                    info.l7_payload_length = l7_len;
                    extract_dns(data + l7_offset, l7_len, info);
                }
            }
            else if (ip6->next_header == constants::IPPROTO_ICMPV6)
            {
                info.l4_proto = L4Protocol::ICMP;
            }
        }

        // Layer 3: ARP
        else if (info.ether_type == constants::ETHERTYPE_ARP)
        {
            info.l3_proto = L3Protocol::ARP;
            info.valid = true;
        }

        return info;
    }

    // DNS extractor
    static void extract_dns(const uint8_t *payload,
                            std::size_t len,
                            PacketInfo &info)
    {
        if (len < constants::DNS_HEADER_SIZE + 5)
            return;

        // QR bit: bit 15 of the Flags field (byte offset 2)
        const bool is_response = ((payload[2] & 0x80) != 0);

        // QDCOUNT at bytes 4-5
        const uint16_t qdcount = static_cast<uint16_t>(
            (payload[4] << 8) | payload[5]);

        if (qdcount == 0)
            return;

        std::size_t offset = constants::DNS_HEADER_SIZE;
        std::string name;
        std::size_t hops = 0;

        // Decode QNAME (length-prefixed labels)
        while (offset < len && hops < constants::DNS_MAX_LABEL_HOPS)
        {
            const uint8_t label_len = payload[offset];

            if (label_len == 0)
            {
                ++offset;
                break;
            }

            // Compression pointer: bail out (no pointer following in extractor)
            if ((label_len & 0xC0) == 0xC0)
                return;

            ++offset;
            if (offset + label_len > len)
                return;

            if (!name.empty())
                name += '.';
            name.append(reinterpret_cast<const char *>(payload + offset), label_len);
            offset += label_len;
            ++hops;
        }

        if (name.empty() || offset + 2 > len)
            return;

        const uint16_t qtype = static_cast<uint16_t>(
            (payload[offset] << 8) | payload[offset + 1]);

        DnsInfo dns_info;
        dns_info.query_name = std::move(name);
        dns_info.query_type = qtype;
        dns_info.is_response = is_response;

        info.dns = std::move(dns_info);
        info.l7_proto = L7Protocol::DNS;
    }

    // HTTP extractor (plaintext HTTP/1.x requests)
    static void extract_http(const uint8_t *payload,
                             std::size_t len,
                             PacketInfo &info)
    {
        if (len < 16)
            return;

        static const char *kMethods[] = {
            "GET ", "POST ", "PUT ", "DELETE ",
            "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "};

        std::string method;

        for (const char *m : kMethods)
        {
            const std::size_t ml = std::strlen(m);
            if (len >= ml &&
                std::memcmp(payload, m, ml) == 0)
            {
                method.assign(m, ml - 1); // strip trailing space
                break;
            }
        }

        if (method.empty())
            return;

        // Find end of request line
        const std::size_t method_len = method.size() + 1;
        std::size_t uri_end = method_len;

        while (uri_end < len && payload[uri_end] != ' ')
            ++uri_end;

        std::string uri(
            reinterpret_cast<const char *>(payload + method_len),
            uri_end - method_len);

        // Find Host: header
        std::string host;
        std::size_t pos = 0;

        // Advance past request line
        while (pos + 1 < len &&
               !(payload[pos] == '\r' && payload[pos + 1] == '\n'))
        {
            ++pos;
        }
        pos += 2; // skip \r\n

        while (pos + 1 < len)
        {
            // Empty line = end of headers
            if (payload[pos] == '\r' && payload[pos + 1] == '\n')
                break;

            // Check for "Host:" (case-sensitive per RFC 7230)
            static const char kHost[] = "Host: ";
            constexpr std::size_t kHostLen = sizeof(kHost) - 1;

            if (len - pos >= kHostLen &&
                std::memcmp(payload + pos, kHost, kHostLen) == 0)
            {
                std::size_t val_start = pos + kHostLen;
                std::size_t val_end = val_start;

                while (val_end + 1 < len &&
                       !(payload[val_end] == '\r' && payload[val_end + 1] == '\n'))
                {
                    ++val_end;
                }

                host.assign(
                    reinterpret_cast<const char *>(payload + val_start),
                    val_end - val_start);
                break;
            }

            // Advance to next header line
            while (pos + 1 < len &&
                   !(payload[pos] == '\r' && payload[pos + 1] == '\n'))
            {
                ++pos;
            }
            pos += 2;
        }

        HttpInfo http_info;
        http_info.method = std::move(method);
        http_info.uri = std::move(uri);
        http_info.host = std::move(host);

        info.http = std::move(http_info);
        info.l7_proto = L7Protocol::HTTP;
    }

    // TLS SNI extractor
    static void extract_tls(const uint8_t *payload,
                            std::size_t len,
                            PacketInfo &info)
    {
        // Minimum: TLS record header (5) + handshake header (4) + ClientHello
        if (len < 43)
            return;

        // TLS record header
        if (payload[0] != constants::TLS_CONTENT_HANDSHAKE)
            return;

        const uint16_t record_version = static_cast<uint16_t>(
            (payload[1] << 8) | payload[2]);
        const uint16_t record_len = static_cast<uint16_t>(
            (payload[3] << 8) | payload[4]);

        if (static_cast<std::size_t>(5u + record_len) > len)
            return;

        std::size_t offset = 5;

        // Handshake header
        if (payload[offset] != constants::TLS_HANDSHAKE_CLIENT_HELLO)
            return;

        const uint32_t hs_len =
            (static_cast<uint32_t>(payload[offset + 1]) << 16) |
            (static_cast<uint32_t>(payload[offset + 2]) << 8) |
            static_cast<uint32_t>(payload[offset + 3]);

        offset += 4;

        const std::size_t hs_end = offset + hs_len;
        if (hs_end > len)
            return;

        // ClientHello body: Version(2) + Random(32)
        if (offset + 34 > len)
            return;
        offset += 34;

        // Session ID
        if (offset + 1 > len)
            return;
        const uint8_t session_id_len = payload[offset++];
        if (offset + session_id_len > len)
            return;
        offset += session_id_len;

        // Cipher Suites
        if (offset + 2 > len)
            return;
        const uint16_t cs_len = static_cast<uint16_t>(
            (payload[offset] << 8) | payload[offset + 1]);
        offset += 2;
        if (offset + cs_len > len)
            return;
        offset += cs_len;

        // Compression Methods
        if (offset + 1 > len)
            return;
        const uint8_t comp_len = payload[offset++];
        if (offset + comp_len > len)
            return;
        offset += comp_len;

        // Extensions
        if (offset + 2 > len)
            return;
        const uint16_t ext_total = static_cast<uint16_t>(
            (payload[offset] << 8) | payload[offset + 1]);
        offset += 2;

        const std::size_t ext_end = offset + ext_total;
        if (ext_end > len || ext_end > hs_end)
            return;

        // Walk extensions looking for SNI (type 0x0000)
        while (offset + 4 <= ext_end)
        {
            const uint16_t ext_type = static_cast<uint16_t>(
                (payload[offset] << 8) | payload[offset + 1]);
            const uint16_t ext_len = static_cast<uint16_t>(
                (payload[offset + 2] << 8) | payload[offset + 3]);
            offset += 4;

            if (offset + ext_len > ext_end)
                break;

            if (ext_type == constants::TLS_EXTENSION_SNI)
            {
                if (offset + 2 > ext_end)
                    break;

                const uint16_t sni_list_len = static_cast<uint16_t>(
                    (payload[offset] << 8) | payload[offset + 1]);
                std::size_t sni_offset = offset + 2;

                const std::size_t sni_end = sni_offset + sni_list_len;
                if (sni_end > ext_end)
                    break;

                while (sni_offset + 3 <= sni_end)
                {
                    const uint8_t name_type = payload[sni_offset];
                    const uint16_t name_len = static_cast<uint16_t>(
                        (payload[sni_offset + 1] << 8) | payload[sni_offset + 2]);
                    sni_offset += 3;

                    if (sni_offset + name_len > sni_end)
                        break;

                    if (name_type == 0x00) // host_name
                    {
                        TlsInfo tls_info;
                        tls_info.sni.assign(
                            reinterpret_cast<const char *>(payload + sni_offset),
                            name_len);
                        tls_info.record_version = record_version;

                        info.tls = std::move(tls_info);
                        info.l7_proto = L7Protocol::TLS;
                        return;
                    }

                    sni_offset += name_len;
                }
                break;
            }

            offset += ext_len;
        }
    }

    // Public format helpers (used by dashboard and alert logging)
    std::string format_tcp_flags(uint8_t flags)
    {
        using namespace nte::constants;
        std::string out;

        auto add = [&](const char *name)
        {
            if (!out.empty())
                out += ',';
            out += name;
        };

        if (flags & TCP_FLAG_CWR)
            add("CWR");
        if (flags & TCP_FLAG_ECE)
            add("ECE");
        if (flags & TCP_FLAG_URG)
            add("URG");
        if (flags & TCP_FLAG_ACK)
            add("ACK");
        if (flags & TCP_FLAG_PSH)
            add("PSH");
        if (flags & TCP_FLAG_RST)
            add("RST");
        if (flags & TCP_FLAG_SYN)
            add("SYN");
        if (flags & TCP_FLAG_FIN)
            add("FIN");

        return out.empty() ? std::string("NONE") : out;
    }

} // namespace nte