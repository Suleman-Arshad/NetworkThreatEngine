#pragma once
#ifndef NETWORK_THREAT_ENGINE_FLOW_KEY_HPP
#define NETWORK_THREAT_ENGINE_FLOW_KEY_HPP
#include "Config.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>

namespace nte
{
    // Raw 128-bit address type (IPv4-mapped or native IPv6)
    using Addr128 = std::array<uint8_t, 16>;

    // Convert a 4-byte IPv4 address (in host byte order, most-significant byte first) into IPv4-mapped IPv6 form:  ::ffff:a.b.c.d
    inline Addr128 ipv4_to_addr128(uint32_t host_order_addr) noexcept
    {
        Addr128 out{};
        // Prefix: 10 zero bytes + 0xFF 0xFF
        out[10] = 0xFF;
        out[11] = 0xFF;
        // IPv4 octets in big-endian order in the last 4 bytes
        out[12] = static_cast<uint8_t>((host_order_addr >> 24) & 0xFF);
        out[13] = static_cast<uint8_t>((host_order_addr >> 16) & 0xFF);
        out[14] = static_cast<uint8_t>((host_order_addr >> 8) & 0xFF);
        out[15] = static_cast<uint8_t>(host_order_addr & 0xFF);
        return out;
    }

    // Copy a 16-byte IPv6 address from a raw pointer into an Addr128.
    inline Addr128 ipv6_to_addr128(const uint8_t *raw16) noexcept
    {
        Addr128 out{};
        std::memcpy(out.data(), raw16, 16);
        return out;
    }

    struct FlowKey
    {
        // Normalised addresses (lower endpoint always in lo_addr/lo_port).
        Addr128 lo_addr{}; // lexicographically smaller address
        Addr128 hi_addr{}; // lexicographically larger address
        uint16_t lo_port{0};
        uint16_t hi_port{0};
        uint8_t protocol{0}; // IANA protocol number: 6=TCP, 17=UDP

        // Factory: build a normalised key from a parsed packet

        static FlowKey make(const Addr128 &src_addr,
                            const Addr128 &dst_addr,
                            uint16_t src_port,
                            uint16_t dst_port,
                            uint8_t proto) noexcept
        {
            FlowKey key;
            key.protocol = proto;

            // Normalise: place smaller {addr, port} pair in lo_ fields.
            // Comparison is lexicographic on the 16-byte address first;
            // port is used as a tiebreaker to handle same-IP loopback flows.
            const bool src_is_lo =
                (src_addr < dst_addr) ||
                (src_addr == dst_addr && src_port <= dst_port);

            if (src_is_lo)
            {
                key.lo_addr = src_addr;
                key.lo_port = src_port;
                key.hi_addr = dst_addr;
                key.hi_port = dst_port;
            }
            else
            {
                key.lo_addr = dst_addr;
                key.lo_port = dst_port;
                key.hi_addr = src_addr;
                key.hi_port = src_port;
            }

            return key;
        }

        // Equality (required by std::unordered_map)

        bool operator==(const FlowKey &other) const noexcept
        {
            return lo_addr == other.lo_addr && hi_addr == other.hi_addr && lo_port == other.lo_port && hi_port == other.hi_port && protocol == other.protocol;
        }

        bool operator!=(const FlowKey &other) const noexcept
        {
            return !(*this == other);
        }

        // Human-readable representation (for logging / dashboard)

        [[nodiscard]] std::string to_string() const
        {
            // Produce "lo_addr:lo_port <-> hi_addr:hi_port / proto"
            // We format the Addr128 as hex groups for IPv6, or dotted-decimal for IPv4-mapped addresses.
            auto format_addr = [](const Addr128 &a) -> std::string
            {
                // Detect IPv4-mapped prefix: bytes 0-9 are 0, bytes 10-11 are 0xFF
                bool is_v4 = true;
                for (int i = 0; i < 10; ++i)
                {
                    if (a[i] != 0)
                    {
                        is_v4 = false;
                        break;
                    }
                }
                if (is_v4 && a[10] == 0xFF && a[11] == 0xFF)
                {
                    char buf[16];
                    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                                  a[12], a[13], a[14], a[15]);
                    return std::string(buf);
                }

                // IPv6 - compact hex, no zero-run compression (sufficient for key display)
                char buf[40];
                std::snprintf(buf, sizeof(buf),
                              "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                              "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                              a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
                              a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]);
                return std::string(buf);
            };

            return format_addr(lo_addr) + ":" + std::to_string(lo_port) + " <-> " + format_addr(hi_addr) + ":" + std::to_string(hi_port) + " / proto=" + std::to_string(static_cast<int>(protocol));
        }
    };

    // FlowKeyHash  — FNV-1a 64-bit hash functor for std::unordered_map
    struct FlowKeyHash
    {
        std::size_t operator()(const FlowKey &key) const noexcept
        {
            // FNV-1a 64-bit constants
            static constexpr uint64_t FNV_OFFSET = 14695981039346656037ULL;
            static constexpr uint64_t FNV_PRIME = 1099511628211ULL;

            uint64_t hash = FNV_OFFSET;

            auto mix_bytes = [&](const void *data, std::size_t len) noexcept
            {
                const auto *bytes = static_cast<const uint8_t *>(data);
                for (std::size_t i = 0; i < len; ++i)
                {
                    hash ^= static_cast<uint64_t>(bytes[i]);
                    hash *= FNV_PRIME;
                }
            };

            mix_bytes(key.lo_addr.data(), key.lo_addr.size());
            mix_bytes(key.hi_addr.data(), key.hi_addr.size());
            mix_bytes(&key.lo_port, sizeof(key.lo_port));
            mix_bytes(&key.hi_port, sizeof(key.hi_port));
            mix_bytes(&key.protocol, sizeof(key.protocol));

            return static_cast<std::size_t>(hash);
        }
    };

    // FlowKeyEqual  — equality functor (std::unordered_map requires both)
    struct FlowKeyEqual
    {
        bool operator()(const FlowKey &a, const FlowKey &b) const noexcept
        {
            return a == b;
        }
    };

} // namespace nte

#endif // NETWORK_THREAT_ENGINE_FLOW_KEY_HPP