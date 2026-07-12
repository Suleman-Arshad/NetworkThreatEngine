#pragma once
#ifndef NETWORK_THREAT_ENGINE_THREAT_ALERT_HPP
#define NETWORK_THREAT_ENGINE_THREAT_ALERT_HPP
#include <chrono>
#include <cstdint>
#include <string>

namespace nte
{
    // Severity - ordered so numeric comparison is meaningful
    enum class Severity : uint8_t
    {
        LOW = 0,
        MEDIUM = 1,
        HIGH = 2,
        CRITICAL = 3
    };

    [[nodiscard]] inline const char *severity_to_string(Severity s) noexcept
    {
        switch (s)
        {
        case Severity::LOW:
            return "LOW";
        case Severity::MEDIUM:
            return "MEDIUM";
        case Severity::HIGH:
            return "HIGH";
        case Severity::CRITICAL:
            return "CRITICAL";
        }
        return "UNKNOWN";
    }

    [[nodiscard]] inline Severity severity_from_string(const std::string &s) noexcept
    {
        if (s == "CRITICAL")
            return Severity::CRITICAL;
        if (s == "HIGH")
            return Severity::HIGH;
        if (s == "MEDIUM")
            return Severity::MEDIUM;
        return Severity::LOW;
    }

    // AttackType - enumerated threat categories

    enum class AttackType : uint8_t
    {
        UNKNOWN = 0,
        VOLUME_ANOMALY = 1,   // EWMA pps/bps spike
        SYN_FLOOD = 2,        // High SYN rate, low handshake completion
        PORT_SCAN = 3,        // Many distinct dst-ports from one src
        BRUTE_FORCE = 4,      // High rate toward a single sensitive port
        DNS_TUNNELING = 5,    // Abnormal DNS query length or TXT rate
        DATA_EXFILTRATION = 6 // Anomalous outbound byte volume
    };

    [[nodiscard]] inline const char *attack_type_to_string(AttackType t) noexcept
    {
        switch (t)
        {
        case AttackType::UNKNOWN:
            return "UNKNOWN";
        case AttackType::VOLUME_ANOMALY:
            return "VOLUME_ANOMALY";
        case AttackType::SYN_FLOOD:
            return "SYN_FLOOD";
        case AttackType::PORT_SCAN:
            return "PORT_SCAN";
        case AttackType::BRUTE_FORCE:
            return "BRUTE_FORCE";
        case AttackType::DNS_TUNNELING:
            return "DNS_TUNNELING";
        case AttackType::DATA_EXFILTRATION:
            return "DATA_EXFILTRATION";
        }
        return "UNKNOWN";
    }

    // ThreatAlert

    struct ThreatAlert
    {
        // Classification
        AttackType attack_type{AttackType::UNKNOWN};
        Severity severity{Severity::LOW};

        // Timestamp
        std::string timestamp_iso{};

        // Steady-clock time point for internal suppression calculations.
        std::chrono::steady_clock::time_point generated_at{};

        // Network context
        std::string src_ip{};
        std::string dst_ip{};
        uint16_t src_port{0};
        uint16_t dst_port{0};

        // Evidence
        std::string evidence_summary{};

        // Optional: raw numeric metrics for structured consumers (SIEM/dashboards).
        double observed_value{0.0};  // e.g. current pps or port count
        double baseline_value{0.0};  // e.g. EWMA pps at time of alert
        double threshold_value{0.0}; // e.g. configured multiplier x baseline

        // Convenience constructors

        ThreatAlert() = default;

        ThreatAlert(AttackType type,
                    Severity sev,
                    std::string src,
                    std::string dst,
                    uint16_t sport,
                    uint16_t dport,
                    std::string evidence)
            : attack_type(type), severity(sev), generated_at(std::chrono::steady_clock::now()), src_ip(std::move(src)), dst_ip(std::move(dst)), src_port(sport), dst_port(dport), evidence_summary(std::move(evidence))
        {
            timestamp_iso = make_iso8601_now();
        }

        // Copyable and movable - DeliveryLayer queues these by value.
        ThreatAlert(const ThreatAlert &) = default;
        ThreatAlert &operator=(const ThreatAlert &) = default;
        ThreatAlert(ThreatAlert &&) = default;
        ThreatAlert &operator=(ThreatAlert &&) = default;

        // Helpers

        [[nodiscard]] const char *type_str() const noexcept
        {
            return attack_type_to_string(attack_type);
        }

        [[nodiscard]] const char *severity_str() const noexcept
        {
            return severity_to_string(severity);
        }

        // Generate current wall-clock time as ISO-8601 UTC string.
        [[nodiscard]] static std::string make_iso8601_now()
        {
            const auto now = std::chrono::system_clock::now();
            const auto tt = std::chrono::system_clock::to_time_t(now);
            struct tm utc{};
            gmtime_r(&tt, &utc);
            char buf[32];
            std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &utc);
            return std::string(buf);
        }

        // ncurses colour pair index based on severity (defined in DeliveryLayer).
        [[nodiscard]] int ncurses_color_pair() const noexcept
        {
            switch (severity)
            {
            case Severity::LOW:
                return 1; // white
            case Severity::MEDIUM:
                return 2; // yellow
            case Severity::HIGH:
                return 3; // red
            case Severity::CRITICAL:
                return 4; // magenta / bright red
            }
            return 1;
        }
    };

} // namespace nte

#endif // NETWORK_THREAT_ENGINE_THREAT_ALERT_HPP