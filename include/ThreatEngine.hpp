#pragma once
#ifndef NETWORK_THREAT_ENGINE_THREAT_ENGINE_HPP
#define NETWORK_THREAT_ENGINE_THREAT_ENGINE_HPP

#include "ProtocolDissector.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
struct sqlite3;
struct sqlite3_stmt;

// Severity levels - ordered so that numeric comparison is meaningful
enum class Severity : uint8_t
{
    LOW = 0,
    MEDIUM = 1,
    HIGH = 2,
    CRITICAL = 3
};
[[nodiscard]] const char *severity_to_string(Severity s) noexcept;

// ThreatAlert - the output type of the detection engine
struct ThreatAlert
{
    std::string timestamp;   // ISO-8601 wall-clock string
    std::string threat_type; // e.g. "SYN_FLOOD", "PORT_SCAN"
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port{0};
    uint16_t dst_port{0};
    Severity severity{Severity::LOW};
    std::string description; // human-readable evidence summary
};

// EWMA Configuration
struct EwmaConfig
{
    double alpha{0.125};
    double stale_seconds{60.0};
    double medium_multiplier{4.0};
    // Multiplier for HIGH severity.
    double high_multiplier{8.0};
};

// Detection thresholds for various threat types
struct DetectionConfig
{
    EwmaConfig ewma{};

    // SYN Flood
    // Minimum SYN packets per second from one source to trigger the rule.
    double syn_flood_rate_pps{50.0};
    // Minimum ratio of SYN-only packets to total TCP packets to confirm flood.
    double syn_flood_ratio{0.85};

    // Port Scan
    // Sliding window length in seconds for port scan counting.
    double port_scan_window_sec{10.0};
    // How many distinct destination ports within the window = port scan.
    uint32_t port_scan_distinct_ports{20};

    // Brute Force
    // Packets per second toward a single sensitive port = brute force.
    double brute_force_rate_pps{20.0};
    // Well-known sensitive ports monitored for brute-force attempts.
    std::vector<uint16_t> sensitive_ports{22, 23, 3389, 5900, 21, 25, 110, 143};

    // DNS Tunneling
    // Domain label length that is considered suspiciously long.
    std::size_t dns_suspicious_label_length{40};
    // Total DNS query name length threshold.
    std::size_t dns_suspicious_total_length{100};
    double dns_txt_rate_threshold{5.0};

    // Data Exfiltration
    // Bytes per second outbound from one src IP that triggers MEDIUM alert.
    double exfil_bytes_per_sec_medium{5'000'000.0}; // ~5 MB/s Bytes per second outbound for HIGH alert.
    double exfil_bytes_per_sec_high{20'000'000.0};  // ~20 MB/s

    // Alert suppression
    double alert_suppression_sec{5.0};
};

// PerIpProfile - all mutable per-source-IP state
struct PerIpProfile
{
    mutable std::mutex profile_mutex;

    // EWMA state
    double ewma_pps{0.0}; // packets/second baseline
    double ewma_bps{0.0}; // bytes/second baseline

    // Sliding-window counters reset every ~1 second
    uint64_t window_packet_count{0};
    uint64_t window_byte_count{0};
    std::chrono::steady_clock::time_point window_start{};

    // TCP / SYN flood tracking
    uint64_t tcp_total_count{0};
    uint64_t syn_only_count{0};       // SYN set, ACK not set
    uint64_t completed_handshakes{0}; // SYN+ACK seen (approximation)

    std::chrono::steady_clock::time_point syn_window_start{};
    uint64_t syn_window_count{0};

    // Port scan tracking
    std::chrono::steady_clock::time_point scan_window_start{};
    std::unordered_set<uint16_t> scanned_ports{};

    // Brute-force tracking (per sensitive port)
    std::unordered_map<uint16_t,
                       std::pair<std::chrono::steady_clock::time_point, uint64_t>>
        brute_force_state{};

    // DNS tunneling tracking
    std::chrono::steady_clock::time_point dns_txt_window_start{};
    uint64_t dns_txt_window_count{0};

    // Data exfiltration tracking
    // Alert suppression — last-fired timestamps per threat type
    std::unordered_map<std::string,
                       std::chrono::steady_clock::time_point>
        last_alert_time{};

    // Lifecycle
    PerIpProfile();
    // Non-copyable - mutex members cannot be copied
    PerIpProfile(const PerIpProfile &) = delete;
    PerIpProfile &operator=(const PerIpProfile &) = delete;
    PerIpProfile(PerIpProfile &&) = delete;
    PerIpProfile &operator=(PerIpProfile &&) = delete;
};

// ThreatEngine - the main detection engine
class ThreatEngine
{
public:
    explicit ThreatEngine(const std::string &db_path = "alerts.db", DetectionConfig config = DetectionConfig{});

    // Destructor
    ~ThreatEngine();

    // Non-copyable, non-movable - owns a mutex and a raw database handle.
    ThreatEngine(const ThreatEngine &) = delete;
    ThreatEngine &operator=(const ThreatEngine &) = delete;
    ThreatEngine(ThreatEngine &&) = delete;
    ThreatEngine &operator=(ThreatEngine &&) = delete;

    // Primary entry point.  Call once per packet from the Consumer thread.
    // Thread-safe — may be called concurrently from multiple threads.
    void inspect_packet(const DissectionResult &diss);

    // Return the total number of alerts fired since construction.
    [[nodiscard]] uint64_t total_alerts() const noexcept;

private:
    // Configuration (immutable after construction)
    DetectionConfig config_;

    // Per-IP profile map
    mutable std::mutex map_mutex_;
    std::unordered_map<std::string, PerIpProfile> profiles_;

    // SQLite state
    mutable std::mutex db_mutex_;
    sqlite3 *db_{nullptr};
    sqlite3_stmt *insert_stmt_{nullptr}; // pre-compiled INSERT prepared stmt

    // Alert counter
    std::atomic<uint64_t> alert_count_{0}; //

    // Private helpers
    PerIpProfile &get_or_create_profile(const std::string &src_ip);

    // EWMA update and anomaly detection
    [[nodiscard]] std::unique_ptr<ThreatAlert>
    update_ewma_and_detect(PerIpProfile &profile,
                           const std::string &src_ip,
                           const std::string &dst_ip,
                           uint32_t packet_bytes,
                           std::chrono::steady_clock::time_point now);

    // Individual rule detectors
    [[nodiscard]] std::unique_ptr<ThreatAlert>
    detect_syn_flood(PerIpProfile &profile,
                     const DissectionResult &diss,
                     std::chrono::steady_clock::time_point now);

    [[nodiscard]] std::unique_ptr<ThreatAlert>
    detect_port_scan(PerIpProfile &profile,
                     const DissectionResult &diss,
                     std::chrono::steady_clock::time_point now);

    [[nodiscard]] std::unique_ptr<ThreatAlert>
    detect_brute_force(PerIpProfile &profile,
                       const DissectionResult &diss,
                       std::chrono::steady_clock::time_point now);

    [[nodiscard]] std::unique_ptr<ThreatAlert>
    detect_dns_tunneling(PerIpProfile &profile,
                         const DissectionResult &diss,
                         std::chrono::steady_clock::time_point now);

    [[nodiscard]] std::unique_ptr<ThreatAlert>
    detect_data_exfiltration(PerIpProfile &profile,
                             const DissectionResult &diss,
                             std::chrono::steady_clock::time_point now);

    // Suppression check
    [[nodiscard]] bool is_suppressed(PerIpProfile &profile,
                                     const std::string &threat_type,
                                     std::chrono::steady_clock::time_point now) const;

    // Record the fire time of a threat type.  Called with profile lock held.
    void record_alert_time(PerIpProfile &profile,
                           const std::string &threat_type,
                           std::chrono::steady_clock::time_point now);

    // Persist alert to SQLite and print to stdout.
    void fire_alert(ThreatAlert alert);

    // SQLite helpers
    void init_database(const std::string &db_path);
    void prepare_insert_statement();

    // Format current wall-clock time as ISO-8601 string.
    [[nodiscard]] static std::string now_iso8601();

    // Check whether a port is in the configured sensitive_ports list.
    [[nodiscard]] bool is_sensitive_port(uint16_t port) const noexcept;
};
#endif // NETWORK_THREAT_ENGINE_THREAT_ENGINE_HPP