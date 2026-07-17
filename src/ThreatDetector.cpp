#include "Config.hpp"
#include "EWMAEngine.hpp"
#include "FlowRecord.hpp"
#include "PacketInfo.hpp"
#include "PortScanDetector.hpp"
#include "SynFloodDetector.hpp"
#include "ThreatAlert.hpp"
#include <chrono>
#include <cmath>
#include <atomic>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <cstring>
#include <cstdio>
#include <arpa/inet.h>
#include <sys/socket.h>

namespace nte
{

    // Forward declaration of DeliveryLayer alert sink
    void delivery_fire_alert(const ThreatAlert &alert);

    struct PerIpSuppressionState
    {
        std::unordered_map<uint8_t,
                           std::chrono::steady_clock::time_point>
            last_fired{};

        // Returns true if the given attack type is currently suppressed.
        [[nodiscard]] bool is_suppressed(
            AttackType type,
            double suppression_sec,
            std::chrono::steady_clock::time_point now) const
        {
            const auto it = last_fired.find(static_cast<uint8_t>(type));
            if (it == last_fired.end())
                return false;

            const double elapsed =
                std::chrono::duration<double>(now - it->second).count();

            return elapsed < suppression_sec;
        }

        // Record that an alert of the given type just fired.
        void record(AttackType type,
                    std::chrono::steady_clock::time_point now)
        {
            last_fired[static_cast<uint8_t>(type)] = now;
        }
    };

    // PerIpBruteForceState

    struct PortWindow
    {
        uint64_t count{0};
        std::chrono::steady_clock::time_point window_start{};

        PortWindow()
            : window_start(std::chrono::steady_clock::now())
        {
        }
    };

    struct PerIpBruteForceState
    {
        // Key: destination port, Value: sliding window state
        std::unordered_map<uint16_t, PortWindow> port_windows{};
    };

    // ThreatDetector

    class ThreatDetector
    {
    public:
        explicit ThreatDetector(const Config &config)
            : config_(config), ewma_(config.ewma), port_scan_(config.port_scan), syn_flood_(config.syn_flood), total_alerts_fired_(0)
        {
        }

        ~ThreatDetector() = default;

        ThreatDetector(const ThreatDetector &) = delete;
        ThreatDetector &operator=(const ThreatDetector &) = delete;
        ThreatDetector(ThreatDetector &&) = delete;
        ThreatDetector &operator=(ThreatDetector &&) = delete;

        // Primary entry point

        void inspect(const PacketInfo &info,
                     const FlowRecord *flow,
                     std::chrono::steady_clock::time_point now)
        {
            if (!info.valid || info.src_ip.empty())
                return;

            // 1. EWMA volume anomaly
            auto ewma_result = ewma_.update(
                info.src_ip,
                static_cast<uint32_t>(info.ip_total_length),
                now);

            if (ewma_result.has_value())
            {
                handle_ewma_anomaly(info, *ewma_result, now);
            }

            // 2. SYN Flood
            if (info.l4_proto == L4Protocol::TCP)
            {
                auto syn_result = syn_flood_.inspect(
                    info.src_ip, info.tcp_flags, now);

                if (syn_result.has_value())
                {
                    handle_syn_flood(info, *syn_result, now);
                }
            }

            // 3. Port Scan
            if (info.dst_port != 0)
            {
                auto scan_result = port_scan_.inspect(
                    info.src_ip,
                    info.dst_port,
                    (info.l4_proto == L4Protocol::TCP) ? info.tcp_flags : uint8_t{0},
                    now);

                if (scan_result.has_value())
                {
                    handle_port_scan(info, *scan_result, now);
                }
            }

            // 4. Brute Force
            if (info.dst_port != 0 && is_sensitive_port(info.dst_port))
            {
                check_brute_force(info, now);
            }

            // 5. DNS Tunneling
            if (info.dns.has_value())
            {
                check_dns_tunneling(info, now);
            }

            // 6. Data Exfiltration
            if (info.l7_payload_length > 0)
            {
                check_data_exfiltration(info, now);
            }
        }

        // Diagnostics

        [[nodiscard]] uint64_t total_alerts_fired() const noexcept
        {
            return total_alerts_fired_.load(std::memory_order_relaxed);
        }

        void evict_stale_state(std::chrono::steady_clock::time_point now)
        {
            ewma_.evict_stale_profiles();
            port_scan_.evict_stale(now);
            syn_flood_.evict_stale(now);
        }

    private:
        // Configuration and detector instances
        Config config_;
        EWMAEngine ewma_;
        PortScanDetector port_scan_;
        SynFloodDetector syn_flood_;

        // Per-IP state maps (Consumer-thread-exclusive  no locking needed)
        std::unordered_map<std::string, PerIpSuppressionState> suppression_;
        std::unordered_map<std::string, PerIpBruteForceState> brute_force_state_;

        // Exfiltration byte volume tracking: src_ip -> {window_start, byte_count}
        std::unordered_map<std::string,
                           std::pair<std::chrono::steady_clock::time_point, uint64_t>>
            exfil_state_;

        std::atomic<uint64_t> total_alerts_fired_;

        // Suppression helpers

        [[nodiscard]] bool is_suppressed(
            const std::string &src_ip,
            AttackType type,
            std::chrono::steady_clock::time_point now) const
        {
            const auto it = suppression_.find(src_ip);
            if (it == suppression_.end())
                return false;
            return it->second.is_suppressed(
                type, config_.delivery.alert_suppression_sec, now);
        }

        void record_suppression(
            const std::string &src_ip,
            AttackType type,
            std::chrono::steady_clock::time_point now)
        {
            suppression_[src_ip].record(type, now);
        }

        // Alert firing

        void fire(ThreatAlert alert,
                  std::chrono::steady_clock::time_point now)
        {
            record_suppression(alert.src_ip, alert.attack_type, now);
            ++total_alerts_fired_;
            delivery_fire_alert(alert);
        }

        // Sensitive port check

        [[nodiscard]] bool is_sensitive_port(uint16_t port) const noexcept
        {
            for (const uint16_t p : config_.brute_force.sensitive_ports)
            {
                if (p == port)
                    return true;
            }
            return false;
        }

        // Handler: EWMA volume anomaly

        void handle_ewma_anomaly(
            const PacketInfo &info,
            const EWMAResult &result,
            std::chrono::steady_clock::time_point now)
        {
            if (is_suppressed(info.src_ip, AttackType::VOLUME_ANOMALY, now))
                return;

            std::ostringstream desc;
            desc << std::fixed << std::setprecision(1)
                 << "Traffic spike: "
                 << result.observed_pps << " pps vs EWMA baseline "
                 << result.baseline_pps << " pps ("
                 << std::setprecision(1) << result.ratio << "x deviation); "
                 << "inst_bps=" << std::setprecision(0) << result.observed_bps
                 << " B/s";

            ThreatAlert alert(
                AttackType::VOLUME_ANOMALY,
                result.severity,
                info.src_ip,
                info.dst_ip,
                info.src_port,
                info.dst_port,
                desc.str());

            alert.observed_value = result.observed_pps;
            alert.baseline_value = result.baseline_pps;
            alert.threshold_value =
                result.baseline_pps * config_.ewma.medium_multiplier;

            fire(std::move(alert), now);
        }

        // Handler: SYN Flood

        void handle_syn_flood(
            const PacketInfo &info,
            const SynFloodResult &result,
            std::chrono::steady_clock::time_point now)
        {
            if (is_suppressed(info.src_ip, AttackType::SYN_FLOOD, now))
                return;

            std::ostringstream desc;
            desc << std::fixed << std::setprecision(1)
                 << "SYN flood: rate=" << result.syn_rate_pps
                 << " pps (threshold=" << config_.syn_flood.syn_rate_pps << "); "
                 << "SYN-only ratio="
                 << std::setprecision(1) << (result.syn_ratio * 100.0)
                 << "% (threshold="
                 << (config_.syn_flood.syn_ratio * 100.0) << "%);"
                 << " completed_handshakes=" << result.completed_handshakes
                 << "; target=" << info.dst_ip
                 << ":" << info.dst_port;

            ThreatAlert alert(
                AttackType::SYN_FLOOD,
                result.severity,
                info.src_ip,
                info.dst_ip,
                info.src_port,
                info.dst_port,
                desc.str());

            alert.observed_value = result.syn_rate_pps;
            alert.baseline_value = 0.0;
            alert.threshold_value = config_.syn_flood.syn_rate_pps;

            fire(std::move(alert), now);
        }

        // Handler: Port Scan

        void handle_port_scan(
            const PacketInfo &info,
            const PortScanResult &result,
            std::chrono::steady_clock::time_point now)
        {
            if (is_suppressed(info.src_ip, AttackType::PORT_SCAN, now))
                return;

            std::ostringstream desc;
            desc << "Port scan: "
                 << result.distinct_ports << " distinct dst ports in "
                 << std::fixed << std::setprecision(1)
                 << result.window_sec << "s "
                 << "(threshold=" << config_.port_scan.distinct_port_threshold << "); "
                 << "SYN-only ratio="
                 << std::setprecision(1) << (result.syn_ratio * 100.0)
                 << "%; target=" << info.dst_ip
                 << "; proto=" << (info.l4_proto == L4Protocol::TCP ? "TCP" : "UDP");

            ThreatAlert alert(
                AttackType::PORT_SCAN,
                result.severity,
                info.src_ip,
                info.dst_ip,
                info.src_port,
                info.dst_port,
                desc.str());

            alert.observed_value =
                static_cast<double>(result.distinct_ports);
            alert.baseline_value = 0.0;
            alert.threshold_value =
                static_cast<double>(config_.port_scan.distinct_port_threshold);

            fire(std::move(alert), now);
        }

        // Brute Force detection

        void check_brute_force(
            const PacketInfo &info,
            std::chrono::steady_clock::time_point now)
        {
            PerIpBruteForceState &state = brute_force_state_[info.src_ip];
            PortWindow &win = state.port_windows[info.dst_port];

            if (win.count == 0)
            {
                win.window_start = now;
            }

            ++win.count;

            const double window_age =
                std::chrono::duration<double>(now - win.window_start).count();

            bool trigger_alert = false;
            double current_rate = 0.0;

            if (window_age >= 1.0)
            {
                current_rate = static_cast<double>(win.count) / window_age;
                if (current_rate >= config_.brute_force.rate_pps)
                {
                    trigger_alert = true;
                }

                win.count = 0;
                win.window_start = now;
            }
            else if (win.count >= config_.brute_force.rate_pps)
            {
                current_rate = static_cast<double>(win.count) / std::max(0.001, window_age);
                trigger_alert = true;

                win.count = 0;
                win.window_start = now;
            }

            if (trigger_alert)
            {
                if (is_suppressed(info.src_ip, AttackType::BRUTE_FORCE, now))
                    return;

                const char *service = port_to_service_name(info.dst_port);

                const Severity sev =
                    (current_rate >= config_.brute_force.rate_pps * 3.0)
                        ? Severity::CRITICAL
                        : Severity::HIGH;

                std::ostringstream desc;
                desc << std::fixed << std::setprecision(1)
                     << "Brute force on " << service
                     << " (port " << info.dst_port << "): "
                     << current_rate << " pps "
                     << "(threshold=" << config_.brute_force.rate_pps << ");"
                     << " target=" << info.dst_ip;

                ThreatAlert alert(
                    AttackType::BRUTE_FORCE,
                    sev,
                    info.src_ip,
                    info.dst_ip,
                    info.src_port,
                    info.dst_port,
                    desc.str());

                alert.observed_value = current_rate;
                alert.threshold_value = config_.brute_force.rate_pps;

                fire(std::move(alert), now);
            }
        }

        // DNS Tunneling detection

        void check_dns_tunneling(
            const PacketInfo &info,
            std::chrono::steady_clock::time_point now)
        {
            const DnsInfo &dns = *info.dns;
            const std::string &qname = dns.query_name;

            // Heuristic A: abnormal query name length
            bool length_trigger = false;
            std::size_t max_label = 0;

            {
                std::size_t label_start = 0;

                for (std::size_t i = 0; i <= qname.size(); ++i)
                {
                    if (i == qname.size() || qname[i] == '.')
                    {
                        const std::size_t label_len = i - label_start;
                        if (label_len > max_label)
                            max_label = label_len;
                        label_start = i + 1;
                    }
                }

                if (qname.size() >= config_.dns_tunneling.max_fqdn_length ||
                    max_label >= config_.dns_tunneling.max_label_length)
                {
                    length_trigger = true;
                }
            }

            if (length_trigger)
            {
                if (!is_suppressed(info.src_ip, AttackType::DNS_TUNNELING, now))
                {
                    std::ostringstream desc;
                    desc << "Suspicious DNS query: "
                         << "name_len=" << qname.size()
                         << " (threshold=" << config_.dns_tunneling.max_fqdn_length << "); "
                         << "max_label=" << max_label
                         << " (threshold=" << config_.dns_tunneling.max_label_length << "); "
                         << "query=" << qname
                         << "; qtype=" << dns.query_type;

                    ThreatAlert alert(
                        AttackType::DNS_TUNNELING,
                        Severity::HIGH,
                        info.src_ip,
                        info.dst_ip,
                        info.src_port,
                        info.dst_port,
                        desc.str());

                    alert.observed_value = static_cast<double>(qname.size());
                    alert.threshold_value =
                        static_cast<double>(config_.dns_tunneling.max_fqdn_length);

                    fire(std::move(alert), now);
                    return;
                }
            }

            // Heuristic B: high TXT record query rate
            if (dns.query_type == constants::DNS_QTYPE_TXT)
            {
                auto &[win_start, txt_count] = dns_txt_state_[info.src_ip];

                const double age =
                    std::chrono::duration<double>(now - win_start).count();

                if (age >= 1.0)
                {
                    const double rate =
                        static_cast<double>(txt_count) / age;

                    txt_count = 1;
                    win_start = now;

                    if (rate >= config_.dns_tunneling.txt_rate_pps)
                    {
                        if (!is_suppressed(
                                info.src_ip, AttackType::DNS_TUNNELING, now))
                        {
                            std::ostringstream desc;
                            desc << std::fixed << std::setprecision(1)
                                 << "High DNS TXT rate: " << rate
                                 << " TXT/s (threshold="
                                 << config_.dns_tunneling.txt_rate_pps << ");"
                                 << " last_query=" << qname;

                            ThreatAlert alert(
                                AttackType::DNS_TUNNELING,
                                Severity::HIGH,
                                info.src_ip,
                                info.dst_ip,
                                info.src_port,
                                info.dst_port,
                                desc.str());

                            alert.observed_value = rate;
                            alert.threshold_value =
                                config_.dns_tunneling.txt_rate_pps;

                            fire(std::move(alert), now);
                        }
                    }
                }
                else
                {
                    ++txt_count;
                }
            }
        }

        // Data Exfiltration detection

        void check_data_exfiltration(
            const PacketInfo &info,
            std::chrono::steady_clock::time_point now)
        {
            auto &[win_start, byte_count] = exfil_state_[info.src_ip];

            if (win_start == std::chrono::steady_clock::time_point{})
            {
                win_start = now;
            }

            byte_count += static_cast<uint64_t>(info.l7_payload_length);

            const double age =
                std::chrono::duration<double>(now - win_start).count();

            // Threshold constants
            constexpr double EXFIL_MEDIUM_BPS = 5'000'000.0; // 5 MB/s
            constexpr double EXFIL_HIGH_BPS = 20'000'000.0;  // 20 MB/s

            bool trigger_alert = false;
            double bps = 0.0;

            if (age >= 1.0)
            {
                bps = static_cast<double>(byte_count) / age;
                if (bps >= EXFIL_MEDIUM_BPS)
                {
                    trigger_alert = true;
                }

                byte_count = 0;
                win_start = now;
            }
            else if (byte_count >= EXFIL_MEDIUM_BPS)
            {
                bps = static_cast<double>(byte_count) / std::max(0.001, age);
                trigger_alert = true;

                byte_count = 0;
                win_start = now;
            }

            if (trigger_alert)
            {
                Severity sev = Severity::LOW;

                if (bps >= EXFIL_HIGH_BPS)
                {
                    sev = Severity::HIGH;
                }
                else if (bps >= EXFIL_MEDIUM_BPS)
                {
                    sev = Severity::MEDIUM;
                }

                if (is_suppressed(info.src_ip, AttackType::DATA_EXFILTRATION, now))
                    return;

                std::ostringstream desc;
                desc << std::fixed << std::setprecision(2)
                     << "Outbound data volume: "
                     << (bps / 1'000'000.0) << " MB/s "
                     << "(medium threshold=" << (EXFIL_MEDIUM_BPS / 1'000'000.0)
                     << " MB/s, high=" << (EXFIL_HIGH_BPS / 1'000'000.0) << " MB/s);"
                     << " dst=" << info.dst_ip << ":" << info.dst_port;

                ThreatAlert alert(
                    AttackType::DATA_EXFILTRATION,
                    sev,
                    info.src_ip,
                    info.dst_ip,
                    info.src_port,
                    info.dst_port,
                    desc.str());

                alert.observed_value = bps;
                alert.threshold_value = EXFIL_MEDIUM_BPS;

                fire(std::move(alert), now);
            }
        }

        // Additional per-IP state maps

        // DNS TXT rate tracking: src_ip -> {window_start, count}
        std::unordered_map<std::string,
                           std::pair<std::chrono::steady_clock::time_point, uint64_t>>
            dns_txt_state_;

        // Port -> service name mapping

        [[nodiscard]] static const char *
        port_to_service_name(uint16_t port) noexcept
        {
            switch (port)
            {
            case 21:
                return "FTP";
            case 22:
                return "SSH";
            case 23:
                return "Telnet";
            case 25:
                return "SMTP";
            case 110:
                return "POP3";
            case 143:
                return "IMAP";
            case 3389:
                return "RDP";
            case 5900:
                return "VNC";
            default:
                return "SENSITIVE_PORT";
            }
        }
    };

    static ThreatDetector *g_threat_detector = nullptr;

    ThreatDetector *get_threat_detector() noexcept { return g_threat_detector; }
    void set_threat_detector(ThreatDetector *td) noexcept { g_threat_detector = td; }

} // namespace nte