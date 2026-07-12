#pragma once
#ifndef NETWORK_THREAT_ENGINE_FLOW_RECORD_HPP
#define NETWORK_THREAT_ENGINE_FLOW_RECORD_HPP
#include "Config.hpp"
#include "FlowKey.hpp"
#include "PacketInfo.hpp"
#include <chrono>
#include <cstdint>
#include <unordered_set>

namespace nte
{
    // TCP connection state machine
    enum class TcpState : uint8_t
    {
        INIT = 0,         // No packets seen yet
        SYN_SENT = 1,     // SYN observed (client→server)
        SYN_RECEIVED = 2, // SYN+ACK observed (server→client)
        ESTABLISHED = 3,  // ACK observed after SYN+ACK
        FIN_WAIT = 4,     // FIN observed from either side
        CLOSED = 5        // RST observed, or both FINs exchanged
    };

    [[nodiscard]] inline const char *tcp_state_to_string(TcpState s) noexcept
    {
        switch (s)
        {
        case TcpState::INIT:
            return "INIT";
        case TcpState::SYN_SENT:
            return "SYN_SENT";
        case TcpState::SYN_RECEIVED:
            return "SYN_RECEIVED";
        case TcpState::ESTABLISHED:
            return "ESTABLISHED";
        case TcpState::FIN_WAIT:
            return "FIN_WAIT";
        case TcpState::CLOSED:
            return "CLOSED";
        }
        return "UNKNOWN";
    }

    // FlowDirection - which side of the normalised key sent a given packet
    enum class FlowDirection : uint8_t
    {
        LO_TO_HI = 0, // lo_addr:lo_port -> hi_addr:hi_port
        HI_TO_LO = 1  // hi_addr:hi_port -> lo_addr:lo_port
    };

    // FlowRecord
    struct FlowRecord
    {
        // Identity
        FlowKey key{};

        // Timing
        std::chrono::steady_clock::time_point first_seen{};
        std::chrono::steady_clock::time_point last_seen{};

        // Packet and byte accounting
        uint64_t total_packets{0};
        uint64_t total_bytes{0};

        // Per-direction counters (lo->hi and hi->lo)
        uint64_t lo_to_hi_packets{0};
        uint64_t lo_to_hi_bytes{0};
        uint64_t hi_to_lo_packets{0};
        uint64_t hi_to_lo_bytes{0};

        // TCP state machine
        TcpState tcp_state{TcpState::INIT};

        // Raw TCP flag accumulator - bitwise OR of all flags seen in this flow.
        // Lets the detector ask "has this flow ever seen a RST?" in O(1).
        uint8_t tcp_flags_seen{0};

        // Per-flag packet counts
        uint64_t syn_count{0};     // SYN set, ACK not set
        uint64_t syn_ack_count{0}; // SYN and ACK both set
        uint64_t ack_count{0};     // ACK set, SYN not set
        uint64_t fin_count{0};     // FIN set
        uint64_t rst_count{0};     // RST set
        uint64_t psh_count{0};     // PSH set

        // Number of completed TCP handshakes observed in this flow
        // (incremented on the third ACK that follows a SYN+ACK).
        uint32_t completed_handshakes{0};

        // Port scan tracking
        std::unordered_set<uint16_t> dst_ports_contacted{};

        // Timestamp when dst_ports_contacted was last cleared (for sliding window).
        std::chrono::steady_clock::time_point scan_window_start{};

        // SYN flood tracking
        // Count of SYN-only packets (no ACK) observed in the current window.
        uint64_t syn_window_count{0};
        std::chrono::steady_clock::time_point syn_window_start{};

        // Application layer indicators
        // Populated from PacketInfo by FlowTracker; used by ThreatDetector.
        L7Protocol l7_proto{L7Protocol::NONE};
        std::string last_dns_query{};
        uint16_t last_dns_qtype{0};
        std::string last_http_host{};
        std::string last_http_method{};
        std::string last_tls_sni{};

        // Lifecycle

        explicit FlowRecord(const FlowKey &k)
            : key(k), first_seen(std::chrono::steady_clock::now()), last_seen(first_seen), scan_window_start(first_seen), syn_window_start(first_seen)
        {
        }

        FlowRecord()
            : first_seen(std::chrono::steady_clock::now()), last_seen(first_seen), scan_window_start(first_seen), syn_window_start(first_seen)
        {
        }

        // FlowRecord is not copyable (unordered_set copy is expensive and
        // semantically wrong - we never want a shallow copy of tracking state).
        FlowRecord(const FlowRecord &) = delete;
        FlowRecord &operator=(const FlowRecord &) = delete;

        // Movable - needed for std::unordered_map::emplace internals.
        FlowRecord(FlowRecord &&) = default;
        FlowRecord &operator=(FlowRecord &&) = default;

        // TCP State Machine Transition
        // Apply a TCP flags byte to advance the state machine.
        // Returns true if the state changed.
        bool advance_tcp_state(uint8_t flags, FlowDirection direction) noexcept
        {
            using namespace nte::constants;

            tcp_flags_seen |= flags;

            const bool syn = (flags & TCP_FLAG_SYN) != 0;
            const bool ack = (flags & TCP_FLAG_ACK) != 0;
            const bool fin = (flags & TCP_FLAG_FIN) != 0;
            const bool rst = (flags & TCP_FLAG_RST) != 0;

            // Update per-flag counters
            if (syn && !ack)
            {
                ++syn_count;
            }
            if (syn && ack)
            {
                ++syn_ack_count;
            }
            if (!syn && ack)
            {
                ++ack_count;
            }
            if (fin)
            {
                ++fin_count;
            }
            if (rst)
            {
                ++rst_count;
            }
            if ((flags & TCP_FLAG_PSH) != 0)
            {
                ++psh_count;
            }

            const TcpState prev = tcp_state;

            // RST transitions to CLOSED from any state
            if (rst)
            {
                tcp_state = TcpState::CLOSED;
                return tcp_state != prev;
            }

            switch (tcp_state)
            {
            case TcpState::INIT:
                if (syn && !ack)
                {
                    tcp_state = TcpState::SYN_SENT;
                }
                break;

            case TcpState::SYN_SENT:
                if (syn && ack)
                {
                    tcp_state = TcpState::SYN_RECEIVED;
                }
                else if (syn && !ack)
                {
                    // Simultaneous open or retransmitted SYN - stay in SYN_SENT
                }
                break;

            case TcpState::SYN_RECEIVED:
                if (!syn && ack)
                {
                    tcp_state = TcpState::ESTABLISHED;
                    ++completed_handshakes;
                }
                break;

            case TcpState::ESTABLISHED:
                if (fin)
                {
                    tcp_state = TcpState::FIN_WAIT;
                }
                break;

            case TcpState::FIN_WAIT:
                if (fin && ack)
                {
                    tcp_state = TcpState::CLOSED;
                }
                break;

            case TcpState::CLOSED:
                // New SYN after CLOSED = connection reuse; re-open
                if (syn && !ack)
                {
                    tcp_state = TcpState::SYN_SENT;
                    // Reset handshake-related counters for the new session
                    syn_count = 1;
                    syn_ack_count = 0;
                    ack_count = 0;
                    fin_count = 0;
                    rst_count = 0;
                }
                break;
            }

            (void)direction; // Direction used by caller to set lo/hi counters
            return tcp_state != prev;
        }

        // Idle time helpers

        [[nodiscard]] double idle_seconds() const noexcept
        {
            const auto now = std::chrono::steady_clock::now();
            return std::chrono::duration<double>(now - last_seen).count();
        }

        [[nodiscard]] double age_seconds() const noexcept
        {
            const auto now = std::chrono::steady_clock::now();
            return std::chrono::duration<double>(now - first_seen).count();
        }

        // SYN ratio helper

        // Fraction of all TCP packets that were SYN-only (no ACK).
        // Returns 0.0 when no packets seen to avoid division by zero.
        [[nodiscard]] double syn_only_ratio() const noexcept
        {
            if (total_packets == 0)
                return 0.0;
            return static_cast<double>(syn_count) /
                   static_cast<double>(total_packets);
        }
    };

} // namespace nte

#endif // NETWORK_THREAT_ENGINE_FLOW_RECORD_HPP