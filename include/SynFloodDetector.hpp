#pragma once
#ifndef NETWORK_THREAT_ENGINE_SYN_FLOOD_DETECTOR_HPP
#define NETWORK_THREAT_ENGINE_SYN_FLOOD_DETECTOR_HPP
#include "Config.hpp"
#include "ThreatAlert.hpp"
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

namespace nte
{

    // PerIpSynProfile - per-source-IP SYN flood tracking state
    struct PerIpSynProfile
    {
        // Current window counters
        uint64_t syn_only_count{0};  // SYN set, ACK not set
        uint64_t tcp_total_count{0}; // all TCP packets this window
        uint64_t syn_ack_count{0};   // SYN+ACK (server responses - evidence of completions)
        std::chrono::steady_clock::time_point window_start{};

        // Cumulative lifetime counters
        uint64_t lifetime_syn_count{0};
        uint64_t lifetime_tcp_count{0};
        uint64_t completed_handshakes{0}; // SYN+ACK seen (proxy for completions)

        explicit PerIpSynProfile()
            : window_start(std::chrono::steady_clock::now())
        {
        }
    };

    // SynFloodResult - returned when a flood is detected
    struct SynFloodResult
    {
        Severity severity{Severity::HIGH};
        double syn_rate_pps{0.0}; // observed SYN/s in this window
        double syn_ratio{0.0};    // SYN-only / total TCP fraction
        uint64_t syn_count{0};    // raw SYN count in window
        uint64_t completed_handshakes{0};
    };

    // SynFloodDetector
    class SynFloodDetector
    {
    public:
        explicit SynFloodDetector(const SynFloodConfig &cfg = SynFloodConfig{})
            : cfg_(cfg)
        {
        }

        ~SynFloodDetector() = default;

        SynFloodDetector(const SynFloodDetector &) = delete;
        SynFloodDetector &operator=(const SynFloodDetector &) = delete;
        SynFloodDetector(SynFloodDetector &&) = default;
        SynFloodDetector &operator=(SynFloodDetector &&) = default;

        // Primary entry point
        [[nodiscard]] std::optional<SynFloodResult>
        inspect(const std::string &src_ip,
                uint8_t tcp_flags,
                std::chrono::steady_clock::time_point now)
        {
            PerIpSynProfile &profile = get_or_create(src_ip);

            const bool syn_set = (tcp_flags & constants::TCP_FLAG_SYN) != 0;
            const bool ack_set = (tcp_flags & constants::TCP_FLAG_ACK) != 0;

            // Classify this packet
            ++profile.tcp_total_count;
            ++profile.lifetime_tcp_count;

            if (syn_set && !ack_set)
            {
                ++profile.syn_only_count;
                ++profile.lifetime_syn_count;
            }

            if (syn_set && ack_set)
            {
                ++profile.syn_ack_count;
                ++profile.completed_handshakes;
            }

            // Window evaluation
            const double window_age =
                std::chrono::duration<double>(now - profile.window_start).count();

            if (window_age < cfg_.window_sec)
            {
                return std::nullopt; // Window not yet complete
            }

            // Window has elapsed - evaluate and reset
            const double syn_rate =
                static_cast<double>(profile.syn_only_count) / window_age;

            const double syn_ratio =
                (profile.tcp_total_count > 0)
                    ? static_cast<double>(profile.syn_only_count) /
                          static_cast<double>(profile.tcp_total_count)
                    : 0.0;

            const uint64_t syn_snapshot = profile.syn_only_count;
            const uint64_t handshake_snap = profile.completed_handshakes;

            // Reset window
            profile.syn_only_count = 0;
            profile.tcp_total_count = 0;
            profile.syn_ack_count = 0;
            profile.window_start = now;

            // Threshold evaluation

            if (syn_rate < cfg_.syn_rate_pps)
            {
                return std::nullopt; // Rate condition not met
            }

            if (syn_ratio < cfg_.syn_ratio)
            {
                return std::nullopt; // Ratio condition not met
            }

            // Build result
            SynFloodResult result;
            result.syn_rate_pps = syn_rate;
            result.syn_ratio = syn_ratio;
            result.syn_count = syn_snapshot;
            result.completed_handshakes = handshake_snap;

            // CRITICAL if rate is 5× or more above the configured threshold
            result.severity =
                (syn_rate >= cfg_.syn_rate_pps * 5.0)
                    ? Severity::CRITICAL
                    : Severity::HIGH;

            return result;
        }

        // Diagnostics

        [[nodiscard]] std::size_t tracked_ip_count() const noexcept
        {
            return profiles_.size();
        }

        // Returns the lifetime SYN-only ratio for a source IP.
        // Used by the dashboard to display per-IP threat indicators.
        [[nodiscard]] double lifetime_syn_ratio(const std::string &src_ip) const
        {
            const auto it = profiles_.find(src_ip);
            if (it == profiles_.end())
                return 0.0;
            const auto &p = it->second;
            if (p.lifetime_tcp_count == 0)
                return 0.0;
            return static_cast<double>(p.lifetime_syn_count) /
                   static_cast<double>(p.lifetime_tcp_count);
        }

        // Evict profiles for IPs not seen in the last 2 x window_sec.
        void evict_stale(std::chrono::steady_clock::time_point now)
        {
            for (auto it = profiles_.begin(); it != profiles_.end();)
            {
                const double idle =
                    std::chrono::duration<double>(now - it->second.window_start).count();

                if (idle > cfg_.window_sec * 10.0)
                {
                    it = profiles_.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }

        [[nodiscard]] const SynFloodConfig &config() const noexcept { return cfg_; }

    private:
        SynFloodConfig cfg_;
        std::unordered_map<std::string, PerIpSynProfile> profiles_;

        PerIpSynProfile &get_or_create(const std::string &src_ip)
        {
            auto it = profiles_.find(src_ip);
            if (it != profiles_.end())
                return it->second;

            auto [ins, ok] = profiles_.emplace(
                std::piecewise_construct,
                std::forward_as_tuple(src_ip),
                std::forward_as_tuple());
            (void)ok;
            return ins->second;
        }
    };

} // namespace nte

#endif // NETWORK_THREAT_ENGINE_SYN_FLOOD_DETECTOR_HPP