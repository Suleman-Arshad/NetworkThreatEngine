#pragma once
#ifndef NTE_THREAT_DETECTOR_HPP
#define NTE_THREAT_DETECTOR_HPP

#include "Config.hpp"
#include "EWMAEngine.hpp"
#include "FlowRecord.hpp"
#include "PacketInfo.hpp"
#include "PortScanDetector.hpp"
#include "SynFloodDetector.hpp"
#include "ThreatAlert.hpp"
#include <atomic>
#include <chrono>
#include <unordered_map>
#include <utility>

namespace nte
{
    struct PerIpSuppressionState
    {
        std::unordered_map<uint8_t, std::chrono::steady_clock::time_point> last_fired{};
        [[nodiscard]] bool is_suppressed(AttackType type, double suppression_sec,
                                         std::chrono::steady_clock::time_point now) const;
        void record(AttackType type, std::chrono::steady_clock::time_point now);
    };

    struct PortWindow
    {
        uint64_t count{0};
        std::chrono::steady_clock::time_point window_start{std::chrono::steady_clock::now()};
    };

    struct PerIpBruteForceState
    {
        std::unordered_map<uint16_t, PortWindow> port_windows{};
    };

    class ThreatDetector
    {
    public:
        explicit ThreatDetector(const Config &config);
        ~ThreatDetector();
        ThreatDetector(const ThreatDetector &) = delete;
        ThreatDetector &operator=(const ThreatDetector &) = delete;
        ThreatDetector(ThreatDetector &&) = delete;
        ThreatDetector &operator=(ThreatDetector &&) = delete;

        void inspect(const PacketInfo &info, const FlowRecord *flow,
                     std::chrono::steady_clock::time_point now);
        [[nodiscard]] uint64_t total_alerts_fired() const noexcept;
        void evict_stale_state(std::chrono::steady_clock::time_point now);

    private:
        Config config_;
        EWMAEngine ewma_;
        PortScanDetector port_scan_;
        SynFloodDetector syn_flood_;

        std::unordered_map<std::string, PerIpSuppressionState> suppression_;
        std::unordered_map<std::string, PerIpBruteForceState> brute_force_state_;
        std::unordered_map<std::string,
                           std::pair<std::chrono::steady_clock::time_point, uint64_t>>
            exfil_state_;
        std::unordered_map<std::string,
                           std::pair<std::chrono::steady_clock::time_point, uint64_t>>
            dns_txt_state_;

        std::atomic<uint64_t> total_alerts_fired_;

        [[nodiscard]] bool is_suppressed(const std::string &src_ip, AttackType type,
                                         std::chrono::steady_clock::time_point now) const;
        void record_suppression(const std::string &src_ip, AttackType type,
                                std::chrono::steady_clock::time_point now);
        void fire(ThreatAlert alert, std::chrono::steady_clock::time_point now);
        [[nodiscard]] bool is_sensitive_port(uint16_t port) const noexcept;

        void handle_ewma_anomaly(const PacketInfo &info, const EWMAResult &result,
                                 std::chrono::steady_clock::time_point now);
        void handle_syn_flood(const PacketInfo &info, const SynFloodResult &result,
                              std::chrono::steady_clock::time_point now);
        void handle_port_scan(const PacketInfo &info, const PortScanResult &result,
                              std::chrono::steady_clock::time_point now);
        void check_brute_force(const PacketInfo &info,
                               std::chrono::steady_clock::time_point now);
        void check_dns_tunneling(const PacketInfo &info,
                                 std::chrono::steady_clock::time_point now);
        void check_data_exfiltration(const PacketInfo &info,
                                     std::chrono::steady_clock::time_point now);
        [[nodiscard]] static const char *port_to_service_name(uint16_t port) noexcept;
    };

    ThreatDetector *get_threat_detector() noexcept;
    void set_threat_detector(ThreatDetector *td) noexcept;
}
#endif // NTE_THREAT_DETECTOR_HPP