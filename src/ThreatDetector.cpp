#include "Threatdetector.hpp"
#include "Deliverylayer.hpp"
#include <cmath>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace nte
{
    // PerIpSuppressionState
    bool PerIpSuppressionState::is_suppressed(AttackType type, double sec,
                                              std::chrono::steady_clock::time_point now) const
    {
        auto it = last_fired.find(static_cast<uint8_t>(type));
        if (it == last_fired.end())
            return false;
        return std::chrono::duration<double>(now - it->second).count() < sec;
    }
    void PerIpSuppressionState::record(AttackType type, std::chrono::steady_clock::time_point now)
    {
        last_fired[static_cast<uint8_t>(type)] = now;
    }

    ThreatDetector::ThreatDetector(const Config &config)
        : config_(config), ewma_(config.ewma), port_scan_(config.port_scan),
          syn_flood_(config.syn_flood), total_alerts_fired_(0) {}
    ThreatDetector::~ThreatDetector() = default;
    uint64_t ThreatDetector::total_alerts_fired() const noexcept { return total_alerts_fired_.load(std::memory_order_relaxed); }

    bool ThreatDetector::is_suppressed(const std::string &src, AttackType type,
                                       std::chrono::steady_clock::time_point now) const
    {
        auto it = suppression_.find(src);
        if (it == suppression_.end())
            return false;
        return it->second.is_suppressed(type, config_.delivery.alert_suppression_sec, now);
    }
    void ThreatDetector::record_suppression(const std::string &src, AttackType type,
                                            std::chrono::steady_clock::time_point now)
    {
        suppression_[src].record(type, now);
    }

    bool ThreatDetector::is_sensitive_port(uint16_t port) const noexcept
    {
        for (auto p : config_.brute_force.sensitive_ports)
            if (p == port)
                return true;
        return false;
    }

    const char *ThreatDetector::port_to_service_name(uint16_t port) noexcept
    {
        switch (port)
        {
        case 22:
            return "SSH";
        case 23:
            return "Telnet";
        case 21:
            return "FTP";
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
            return "PORT";
        }
    }

    void ThreatDetector::fire(ThreatAlert alert, std::chrono::steady_clock::time_point now)
    {
        record_suppression(alert.src_ip, alert.attack_type, now);
        ++total_alerts_fired_;
        delivery_fire_alert(alert);
    }

    void ThreatDetector::evict_stale_state(std::chrono::steady_clock::time_point now)
    {
        ewma_.evict_stale_profiles();
        port_scan_.evict_stale(now);
        syn_flood_.evict_stale(now);
    }

    void ThreatDetector::handle_ewma_anomaly(const PacketInfo &info, const EWMAResult &r,
                                             std::chrono::steady_clock::time_point now)
    {
        if (is_suppressed(info.src_ip, AttackType::VOLUME_ANOMALY, now))
            return;
        std::ostringstream d;
        d << std::fixed << std::setprecision(1) << "Traffic spike: " << r.observed_pps
          << " pps vs baseline " << r.baseline_pps << " pps (" << r.ratio << "x)";
        ThreatAlert a(AttackType::VOLUME_ANOMALY, r.severity, info.src_ip, info.dst_ip,
                      info.src_port, info.dst_port, d.str());
        a.observed_value = r.observed_pps;
        a.baseline_value = r.baseline_pps;
        a.threshold_value = r.baseline_pps * config_.ewma.medium_multiplier;
        fire(std::move(a), now);
    }

    void ThreatDetector::handle_syn_flood(const PacketInfo &info, const SynFloodResult &r,
                                          std::chrono::steady_clock::time_point now)
    {
        if (is_suppressed(info.src_ip, AttackType::SYN_FLOOD, now))
            return;
        std::ostringstream d;
        d << std::fixed << std::setprecision(1) << "SYN flood: " << r.syn_rate_pps
          << " pps, ratio=" << (r.syn_ratio * 100.0) << "%, handshakes=" << r.completed_handshakes;
        ThreatAlert a(AttackType::SYN_FLOOD, r.severity, info.src_ip, info.dst_ip,
                      info.src_port, info.dst_port, d.str());
        a.observed_value = r.syn_rate_pps;
        a.threshold_value = config_.syn_flood.syn_rate_pps;
        fire(std::move(a), now);
    }

    void ThreatDetector::handle_port_scan(const PacketInfo &info, const PortScanResult &r,
                                          std::chrono::steady_clock::time_point now)
    {
        if (is_suppressed(info.src_ip, AttackType::PORT_SCAN, now))
            return;
        std::ostringstream d;
        d << "Port scan: " << r.distinct_ports << " ports in "
          << std::fixed << std::setprecision(1) << r.window_sec << "s, SYN ratio="
          << (r.syn_ratio * 100.0) << "%";
        ThreatAlert a(AttackType::PORT_SCAN, r.severity, info.src_ip, info.dst_ip,
                      info.src_port, info.dst_port, d.str());
        a.observed_value = static_cast<double>(r.distinct_ports);
        a.threshold_value = static_cast<double>(config_.port_scan.distinct_port_threshold);
        fire(std::move(a), now);
    }

    void ThreatDetector::check_brute_force(const PacketInfo &info,
                                           std::chrono::steady_clock::time_point now)
    {
        auto &win = brute_force_state_[info.src_ip].port_windows[info.dst_port];
        const double age = std::chrono::duration<double>(now - win.window_start).count();
        if (age >= 1.0)
        {
            const double rate = static_cast<double>(win.count) / age;
            win.count = 1;
            win.window_start = now;
            if (rate >= config_.brute_force.rate_pps && !is_suppressed(info.src_ip, AttackType::BRUTE_FORCE, now))
            {
                const Severity sev = (rate >= config_.brute_force.rate_pps * 3.0) ? Severity::CRITICAL : Severity::HIGH;
                std::ostringstream d;
                d << std::fixed << std::setprecision(1) << "Brute force on "
                  << port_to_service_name(info.dst_port) << " port=" << info.dst_port
                  << " rate=" << rate << " pps";
                ThreatAlert a(AttackType::BRUTE_FORCE, sev, info.src_ip, info.dst_ip,
                              info.src_port, info.dst_port, d.str());
                a.observed_value = rate;
                a.threshold_value = config_.brute_force.rate_pps;
                fire(std::move(a), now);
            }
        }
        else
            ++win.count;
    }

    void ThreatDetector::check_dns_tunneling(const PacketInfo &info,
                                             std::chrono::steady_clock::time_point now)
    {
        const std::string &qname = info.dns->query_name;
        std::size_t max_label = 0, ls = 0;
        for (std::size_t i = 0; i <= qname.size(); ++i)
        {
            if (i == qname.size() || qname[i] == '.')
            {
                max_label = std::max(max_label, i - ls);
                ls = i + 1;
            }
        }
        if ((qname.size() >= config_.dns_tunneling.max_fqdn_length ||
             max_label >= config_.dns_tunneling.max_label_length) &&
            !is_suppressed(info.src_ip, AttackType::DNS_TUNNELING, now))
        {
            std::ostringstream d;
            d << "Suspicious DNS: len=" << qname.size() << " max_label=" << max_label << " q=" << qname;
            ThreatAlert a(AttackType::DNS_TUNNELING, Severity::HIGH, info.src_ip, info.dst_ip,
                          info.src_port, info.dst_port, d.str());
            a.observed_value = static_cast<double>(qname.size());
            fire(std::move(a), now);
            return;
        }
        if (info.dns->query_type == constants::DNS_QTYPE_TXT)
        {
            auto &[ws, cnt] = dns_txt_state_[info.src_ip];
            const double age = std::chrono::duration<double>(now - ws).count();
            if (age >= 1.0)
            {
                const double rate = static_cast<double>(cnt) / age;
                cnt = 1;
                ws = now;
                if (rate >= config_.dns_tunneling.txt_rate_pps &&
                    !is_suppressed(info.src_ip, AttackType::DNS_TUNNELING, now))
                {
                    std::ostringstream d;
                    d << std::fixed << std::setprecision(1) << "High DNS TXT rate: " << rate << " TXT/s";
                    ThreatAlert a(AttackType::DNS_TUNNELING, Severity::HIGH, info.src_ip, info.dst_ip,
                                  info.src_port, info.dst_port, d.str());
                    a.observed_value = rate;
                    a.threshold_value = config_.dns_tunneling.txt_rate_pps;
                    fire(std::move(a), now);
                }
            }
            else
                ++cnt;
        }
    }

    void ThreatDetector::check_data_exfiltration(const PacketInfo &info,
                                                 std::chrono::steady_clock::time_point now)
    {
        auto &[ws, bytes] = exfil_state_[info.src_ip];
        bytes += static_cast<uint64_t>(info.l7_payload_length);
        const double age = std::chrono::duration<double>(now - ws).count();
        if (age < 1.0)
            return;
        const double bps = static_cast<double>(bytes) / age;
        bytes = 0;
        ws = now;
        constexpr double MED = 5'000'000.0, HI = 20'000'000.0;
        Severity sev = Severity::LOW;
        if (bps >= HI)
            sev = Severity::HIGH;
        else if (bps >= MED)
            sev = Severity::MEDIUM;
        else
            return;
        if (is_suppressed(info.src_ip, AttackType::DATA_EXFILTRATION, now))
            return;
        std::ostringstream d;
        d << std::fixed << std::setprecision(2) << "Outbound " << (bps / 1e6) << " MB/s";
        ThreatAlert a(AttackType::DATA_EXFILTRATION, sev, info.src_ip, info.dst_ip,
                      info.src_port, info.dst_port, d.str());
        a.observed_value = bps;
        a.threshold_value = MED;
        fire(std::move(a), now);
    }

    void ThreatDetector::inspect(const PacketInfo &info, const FlowRecord *flow,
                                 std::chrono::steady_clock::time_point now)
    {
        if (!info.valid || info.src_ip.empty())
            return;
        auto ewma_r = ewma_.update(info.src_ip, static_cast<uint32_t>(info.ip_total_length), now);
        if (ewma_r)
            handle_ewma_anomaly(info, *ewma_r, now);
        if (info.l4_proto == L4Protocol::TCP)
        {
            auto syn_r = syn_flood_.inspect(info.src_ip, info.tcp_flags, now);
            if (syn_r)
                handle_syn_flood(info, *syn_r, now);
        }
        if (info.dst_port != 0)
        {
            auto scan_r = port_scan_.inspect(info.src_ip, info.dst_port,
                                             (info.l4_proto == L4Protocol::TCP) ? info.tcp_flags : uint8_t{0}, now);
            if (scan_r)
                handle_port_scan(info, *scan_r, now);
        }
        if (info.dst_port != 0 && is_sensitive_port(info.dst_port))
            check_brute_force(info, now);
        if (info.dns.has_value())
            check_dns_tunneling(info, now);
        if (info.l7_payload_length > 0)
            check_data_exfiltration(info, now);
        (void)flow;
    }

    static ThreatDetector *g_threat_detector = nullptr;
    ThreatDetector *get_threat_detector() noexcept { return g_threat_detector; }
    void set_threat_detector(ThreatDetector *td) noexcept { g_threat_detector = td; }
}