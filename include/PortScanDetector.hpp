#pragma once
#ifndef NETWORK_THREAT_ENGINE_PORT_SCAN_DETECTOR_HPP
#define NETWORK_THREAT_ENGINE_PORT_SCAN_DETECTOR_HPP
#include "Config.hpp"
#include "ThreatAlert.hpp"
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace nte
{
    // PerIpScanProfile - per-source-IP sliding window state
    struct PerIpScanProfile
    {
        // Distinct destination ports contacted in the current window.
        std::unordered_set<uint16_t> dst_ports{};

        // Total TCP packets seen from this source in the current window.
        uint64_t tcp_packet_count{0};

        // SYN-only packets (SYN set, ACK not set) in the current window.
        uint64_t syn_only_count{0};

        // Start of the current measurement window.
        std::chrono::steady_clock::time_point window_start{};

        explicit PerIpScanProfile()
            : window_start(std::chrono::steady_clock::now())
        {
        }
    };

    // PortScanResult - returned when a scan is detected
    struct PortScanResult
    {
        Severity severity{Severity::MEDIUM};
        uint32_t distinct_ports{0};
        double syn_ratio{0.0};
        double window_sec{0.0};
    };

    // PortScanDetector
    class PortScanDetector
    {
    public:
        explicit PortScanDetector(const PortScanConfig &cfg = PortScanConfig{})
            : cfg_(cfg)
        {
        }

        ~PortScanDetector() = default;

        PortScanDetector(const PortScanDetector &) = delete;
        PortScanDetector &operator=(const PortScanDetector &) = delete;
        PortScanDetector(PortScanDetector &&) = default;
        PortScanDetector &operator=(PortScanDetector &&) = default;

        // Primary entry point
        [[nodiscard]] std::optional<PortScanResult>
        inspect(const std::string &src_ip,
                uint16_t dst_port,
                uint8_t tcp_flags,
                std::chrono::steady_clock::time_point now)
        {
            PerIpScanProfile &profile = get_or_create(src_ip);

            // Window management
            const double window_age =
                std::chrono::duration<double>(now - profile.window_start).count();

            if (window_age >= cfg_.window_sec)
            {
                // Window expired - reset without generating an alert (alert was already generated when threshold was first breached, or was never breached and we simply roll forward).
                profile.dst_ports.clear();
                profile.tcp_packet_count = 0;
                profile.syn_only_count = 0;
                profile.window_start = now;
            }

            // Accumulate
            profile.dst_ports.insert(dst_port);
            ++profile.tcp_packet_count;

            const bool syn_set = (tcp_flags & constants::TCP_FLAG_SYN) != 0;
            const bool ack_set = (tcp_flags & constants::TCP_FLAG_ACK) != 0;

            if (syn_set && !ack_set)
            {
                ++profile.syn_only_count;
            }

            // Threshold evaluation
            const auto port_count =
                static_cast<uint32_t>(profile.dst_ports.size());

            if (port_count < cfg_.distinct_port_threshold)
            {
                return std::nullopt;
            }

            // SYN ratio gate
            if (cfg_.syn_only_ratio > 0.0 && profile.tcp_packet_count > 0)
            {
                const double syn_ratio =
                    static_cast<double>(profile.syn_only_count) /
                    static_cast<double>(profile.tcp_packet_count);

                if (syn_ratio < cfg_.syn_only_ratio)
                {
                    return std::nullopt; // Ratio gate not met; likely legitimate
                }
            }

            // Build result
            PortScanResult result;
            result.distinct_ports = port_count;
            result.window_sec = std::min(window_age, cfg_.window_sec);

            if (profile.tcp_packet_count > 0)
            {
                result.syn_ratio =
                    static_cast<double>(profile.syn_only_count) /
                    static_cast<double>(profile.tcp_packet_count);
            }

            // Severity escalation: double the threshold -> HIGH
            result.severity =
                (port_count >= cfg_.distinct_port_threshold * 2)
                    ? Severity::HIGH
                    : Severity::MEDIUM;

            return result;
        }

        // Diagnostics

        [[nodiscard]] std::size_t tracked_ip_count() const noexcept
        {
            return profiles_.size();
        }

        // Evict stale profiles (IPs not seen for > 2 x window_sec).
        void evict_stale(std::chrono::steady_clock::time_point now)
        {
            for (auto it = profiles_.begin(); it != profiles_.end();)
            {
                const double idle =
                    std::chrono::duration<double>(now - it->second.window_start).count();

                if (idle > cfg_.window_sec * 2.0)
                {
                    it = profiles_.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }

        [[nodiscard]] const PortScanConfig &config() const noexcept { return cfg_; }

    private:
        PortScanConfig cfg_;
        std::unordered_map<std::string, PerIpScanProfile> profiles_;

        PerIpScanProfile &get_or_create(const std::string &src_ip)
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

#endif // NETWORK_THREAT_ENGINE_PORT_SCAN_DETECTOR_HPP