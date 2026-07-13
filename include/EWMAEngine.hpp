#pragma once
#ifndef NETWORK_THREAT_ENGINE_EWMA_ENGINE_HPP
#define NETWORK_THREAT_ENGINE_EWMA_ENGINE_HPP
#include "Config.hpp"
#include "ThreatAlert.hpp"
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

namespace nte
{

    // PerIpEwmaProfile
    struct PerIpEwmaProfile
    {
        // EWMA baselines
        double ewma_pps{0.0}; // packets-per-second baseline
        double ewma_bps{0.0}; // bytes-per-second baseline

        // Sliding window accumulators
        uint64_t window_packets{0};
        uint64_t window_bytes{0};
        std::chrono::steady_clock::time_point window_start{};

        // Lifecycle
        bool cold_start{true}; // true until first full window has elapsed

        // Last-seen timestamp for stale detection
        std::chrono::steady_clock::time_point last_update{};

        explicit PerIpEwmaProfile()
            : window_start(std::chrono::steady_clock::now()), last_update(window_start)
        {
        }
    };

    // EWMAResult - returned by update(); non-empty when an anomaly is detected
    struct EWMAResult
    {
        Severity severity{Severity::LOW};
        double observed_pps{0.0};
        double baseline_pps{0.0};
        double ratio{0.0};
        double observed_bps{0.0};
    };

    // EWMAEngine
    class EWMAEngine
    {
    public:
        explicit EWMAEngine(const EWMAConfig &cfg = EWMAConfig{})
            : cfg_(cfg)
        {
        }

        ~EWMAEngine() = default;

        // Non-copyable - owns a large hash map of per-IP state
        EWMAEngine(const EWMAEngine &) = delete;
        EWMAEngine &operator=(const EWMAEngine &) = delete;

        // Movable - allows ThreatDetector to construct it in place
        EWMAEngine(EWMAEngine &&) = default;
        EWMAEngine &operator=(EWMAEngine &&) = default;

        // Primary entry point

        [[nodiscard]] std::optional<EWMAResult>
        update(const std::string &src_ip,
               uint32_t packet_bytes,
               std::chrono::steady_clock::time_point now)
        {
            PerIpEwmaProfile &profile = get_or_create(src_ip);

            // Stale check
            const double since_last =
                std::chrono::duration<double>(now - profile.last_update).count();

            if (!profile.cold_start && since_last > cfg_.stale_reset_sec)
            {
                // Reset to cold-start: don't generate an alert on the next burst
                profile.ewma_pps = 0.0;
                profile.ewma_bps = 0.0;
                profile.window_packets = 0;
                profile.window_bytes = 0;
                profile.window_start = now;
                profile.cold_start = true;
            }

            profile.last_update = now;

            // Accumulate into current window
            ++profile.window_packets;
            profile.window_bytes += static_cast<uint64_t>(packet_bytes);

            // Check if the measurement window has elapsed
            const double window_age =
                std::chrono::duration<double>(now - profile.window_start).count();

            if (window_age < cfg_.min_window_sec)
            {
                return std::nullopt; // Window not yet complete
            }

            // Compute instantaneous rates
            const double inst_pps =
                static_cast<double>(profile.window_packets) / window_age;
            const double inst_bps =
                static_cast<double>(profile.window_bytes) / window_age;

            // EWMA update
            std::optional<EWMAResult> result = std::nullopt;

            if (profile.cold_start)
            {
                // Seed baseline from first observation - no anomaly scoring yet
                profile.ewma_pps = inst_pps;
                profile.ewma_bps = inst_bps;
                profile.cold_start = false;
            }
            else
            {
                // Standard EWMA: alpha x current + (1-alpha) x previous
                const double alpha = cfg_.alpha;
                const double one_minus_a = 1.0 - alpha;

                const double prev_pps = profile.ewma_pps;

                profile.ewma_pps =
                    (alpha * inst_pps) + (one_minus_a * profile.ewma_pps);
                profile.ewma_bps =
                    (alpha * inst_bps) + (one_minus_a * profile.ewma_bps);

                // Anomaly scoring
                const double baseline = std::max(prev_pps, cfg_.pps_floor);
                const double ratio = inst_pps / baseline;

                if (ratio >= cfg_.high_multiplier)
                {
                    EWMAResult r;
                    r.severity = Severity::HIGH;
                    r.observed_pps = inst_pps;
                    r.baseline_pps = prev_pps;
                    r.ratio = ratio;
                    r.observed_bps = inst_bps;
                    result = r;
                }
                else if (ratio >= cfg_.medium_multiplier)
                {
                    EWMAResult r;
                    r.severity = Severity::MEDIUM;
                    r.observed_pps = inst_pps;
                    r.baseline_pps = prev_pps;
                    r.ratio = ratio;
                    r.observed_bps = inst_bps;
                    result = r;
                }
            }

            // Reset window accumulators for next interval
            profile.window_packets = 0;
            profile.window_bytes = 0;
            profile.window_start = now;

            return result;
        }

        // Query helpers
        [[nodiscard]] double baseline_pps(const std::string &src_ip) const
        {
            const auto it = profiles_.find(src_ip);
            if (it == profiles_.end())
                return 0.0;
            return it->second.ewma_pps;
        }

        [[nodiscard]] double baseline_bps(const std::string &src_ip) const
        {
            const auto it = profiles_.find(src_ip);
            if (it == profiles_.end())
                return 0.0;
            return it->second.ewma_bps;
        }

        // Number of unique source IPs currently profiled.
        [[nodiscard]] std::size_t profile_count() const noexcept
        {
            return profiles_.size();
        }

        // Evict profiles that have been idle for longer than stale_reset_sec.
        void evict_stale_profiles()
        {
            const auto now = std::chrono::steady_clock::now();

            for (auto it = profiles_.begin(); it != profiles_.end();)
            {
                const double idle =
                    std::chrono::duration<double>(now - it->second.last_update).count();

                if (idle > cfg_.stale_reset_sec * 2.0)
                {
                    it = profiles_.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }

        // Configuration access

        [[nodiscard]] const EWMAConfig &config() const noexcept { return cfg_; }

    private:
        EWMAConfig cfg_;

        std::unordered_map<std::string, PerIpEwmaProfile> profiles_;

        // Internal helpers
        PerIpEwmaProfile &get_or_create(const std::string &src_ip)
        {
            auto it = profiles_.find(src_ip);
            if (it != profiles_.end())
            {
                return it->second;
            }

            auto [inserted, ok] = profiles_.emplace(
                std::piecewise_construct,
                std::forward_as_tuple(src_ip),
                std::forward_as_tuple());
            (void)ok;
            return inserted->second;
        }
    };

} // namespace nte

#endif // NETWORK_THREAT_ENGINE_EWMA_ENGINE_HPP