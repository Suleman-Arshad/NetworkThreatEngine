#include "ThreatEngine.hpp"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sqlite3.h>

// Utility free functions
const char *severity_to_string(Severity s) noexcept
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

// Returns elapsed seconds between two steady_clock time points.
static double elapsed_seconds(std::chrono::steady_clock::time_point start,
                              std::chrono::steady_clock::time_point end) noexcept
{
    return std::chrono::duration<double>(end - start).count();
}

// PerIpProfile
PerIpProfile::PerIpProfile()
    : window_start(std::chrono::steady_clock::now()), syn_window_start(std::chrono::steady_clock::now()), scan_window_start(std::chrono::steady_clock::now()), dns_txt_window_start(std::chrono::steady_clock::now())
{
}

// ThreatEngine — constructor / destructor
ThreatEngine::ThreatEngine(const std::string &db_path, DetectionConfig config)
    : config_(std::move(config))
{
    init_database(db_path);
    prepare_insert_statement();

    std::cout
        << "[ThreatEngine] Initialised.\n"
        << "[ThreatEngine]   Database    : " << db_path << "\n"
        << "[ThreatEngine]   EWMA alpha  : " << config_.ewma.alpha << "\n"
        << "[ThreatEngine]   SYN flood   : >" << config_.syn_flood_rate_pps << " pps\n"
        << "[ThreatEngine]   Port scan   : >" << config_.port_scan_distinct_ports
        << " ports / "
        << config_.port_scan_window_sec << "s\n"
        << "[ThreatEngine]   Brute force : >" << config_.brute_force_rate_pps << " pps\n"
        << "[ThreatEngine]   Suppression : " << config_.alert_suppression_sec << "s\n";
    std::cout.flush();
}

ThreatEngine::~ThreatEngine()
{
    std::lock_guard<std::mutex> db_lock(db_mutex_);

    if (insert_stmt_ != nullptr)
    {
        sqlite3_finalize(insert_stmt_);
        insert_stmt_ = nullptr;
    }

    if (db_ != nullptr)
    {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

// ThreatEngine - SQLite initialisation
void ThreatEngine::init_database(const std::string &db_path)
{
    if (sqlite3_open(db_path.c_str(), &db_) != SQLITE_OK)
    {
        const std::string err = sqlite3_errmsg(db_);
        sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error("[ThreatEngine] Cannot open SQLite database '" + db_path + "': " + err);
    }

    // Enable WAL mode for better concurrent read performance and durability
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA synchronous=NORMAL;", nullptr, nullptr, nullptr);

    // Create the alerts table — schema matches the spec exactly
    const char *create_sql =
        "CREATE TABLE IF NOT EXISTS alerts ("
        "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  timestamp   TEXT    NOT NULL,"
        "  threat_type TEXT    NOT NULL,"
        "  src_ip      TEXT    NOT NULL,"
        "  dst_ip      TEXT    NOT NULL,"
        "  src_port    INTEGER NOT NULL,"
        "  dst_port    INTEGER NOT NULL,"
        "  severity    TEXT    NOT NULL,"
        "  description TEXT    NOT NULL"
        ");";

    char *errmsg = nullptr;
    if (sqlite3_exec(db_, create_sql, nullptr, nullptr, &errmsg) != SQLITE_OK)
    {
        std::string err = errmsg;
        sqlite3_free(errmsg);
        throw std::runtime_error("[ThreatEngine] Failed to create alerts table: " + err);
    }

    // Index on (src_ip, threat_type) for fast forensic queries
    const char *index_sql =
        "CREATE INDEX IF NOT EXISTS idx_alerts_src_type "
        "ON alerts (src_ip, threat_type);";
    sqlite3_exec(db_, index_sql, nullptr, nullptr, nullptr);

    const char *index_ts_sql =
        "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp "
        "ON alerts (timestamp);";
    sqlite3_exec(db_, index_ts_sql, nullptr, nullptr, nullptr);
}

void ThreatEngine::prepare_insert_statement()
{
    const char *insert_sql =
        "INSERT INTO alerts "
        "(timestamp, threat_type, src_ip, dst_ip, src_port, dst_port, severity, description) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";

    if (sqlite3_prepare_v2(db_, insert_sql, -1, &insert_stmt_, nullptr) != SQLITE_OK)
    {
        throw std::runtime_error(
            std::string("[ThreatEngine] Failed to prepare INSERT statement: ") + sqlite3_errmsg(db_));
    }
}

// ThreatEngine - profile map
PerIpProfile &ThreatEngine::get_or_create_profile(const std::string &src_ip)
{
    std::lock_guard<std::mutex> map_lock(map_mutex_);

    auto it = profiles_.find(src_ip);
    if (it != profiles_.end())
    {
        return it->second;
    }

    // Emplace constructs the PerIpProfile in-place - avoids any move/copy of the mutex-containing struct.
    auto [inserted_it, ok] = profiles_.emplace(
        std::piecewise_construct,
        std::forward_as_tuple(src_ip),
        std::forward_as_tuple());
    (void)ok;
    return inserted_it->second;
}

// ThreatEngine - primary entry point
void ThreatEngine::inspect_packet(const DissectionResult &diss)
{
    // Skip frames that failed L3 parsing - no usable src/dst IP
    if (!diss.valid || diss.src_ip.empty())
    {
        return;
    }

    const auto now = std::chrono::steady_clock::now();

    // Obtain the per-IP profile without holding the map lock beyond this call
    PerIpProfile &profile = get_or_create_profile(diss.src_ip);
    std::vector<ThreatAlert> pending_alerts;

    {
        std::lock_guard<std::mutex> profile_lock(profile.profile_mutex);

        // EWMA update & volume anomaly
        auto ewma_alert = update_ewma_and_detect(
            profile, diss.src_ip, diss.dst_ip,
            static_cast<uint32_t>(diss.ip_total_length), now);
        if (ewma_alert)
        {
            pending_alerts.push_back(std::move(*ewma_alert));
        }

        // SYN Flood
        if (diss.l4_protocol == L4Protocol::TCP)
        {
            auto syn_alert = detect_syn_flood(profile, diss, now);
            if (syn_alert)
            {
                pending_alerts.push_back(std::move(*syn_alert));
            }
        }

        // Port Scan
        if (diss.dst_port != 0)
        {
            auto scan_alert = detect_port_scan(profile, diss, now);
            if (scan_alert)
            {
                pending_alerts.push_back(std::move(*scan_alert));
            }
        }

        // Brute Force
        if (diss.dst_port != 0 && is_sensitive_port(diss.dst_port))
        {
            auto bf_alert = detect_brute_force(profile, diss, now);
            if (bf_alert)
            {
                pending_alerts.push_back(std::move(*bf_alert));
            }
        }

        // DNS Tunneling
        if (diss.dns.has_value())
        {
            auto dns_alert = detect_dns_tunneling(profile, diss, now);
            if (dns_alert)
            {
                pending_alerts.push_back(std::move(*dns_alert));
            }
        }

        // Data Exfiltration
        if (diss.l7_payload_length > 0)
        {
            auto exfil_alert = detect_data_exfiltration(profile, diss, now);
            if (exfil_alert)
            {
                pending_alerts.push_back(std::move(*exfil_alert));
            }
        }

    } // profile lock released here

    // Fire alerts outside the profile lock to avoid holding it during I/O
    for (auto &alert : pending_alerts)
    {
        fire_alert(std::move(alert));
    }
}

std::unique_ptr<ThreatAlert>
ThreatEngine::update_ewma_and_detect(PerIpProfile &profile,
                                     const std::string &src_ip,
                                     const std::string &dst_ip,
                                     uint32_t packet_bytes,
                                     std::chrono::steady_clock::time_point now)
{
    ++profile.window_packet_count;
    profile.window_byte_count += packet_bytes;

    const double window_age = elapsed_seconds(profile.window_start, now);

    // Only update EWMA after at least 1 second of observation; this prevents the very first burst of packets from poisoning the baseline.
    if (window_age < 1.0)
    {
        return nullptr;
    }

    // Compute instantaneous rates over the completed window
    const double inst_pps = static_cast<double>(profile.window_packet_count) / window_age;
    const double inst_bps = static_cast<double>(profile.window_byte_count) / window_age;

    const double alpha = config_.ewma.alpha;
    const double one_minus_a = 1.0 - alpha;

    // Cold-start check: if the baseline is still zero (very first window), seed it directly without anomaly scoring.
    const bool cold_start = (profile.ewma_pps < 1e-9 && profile.ewma_bps < 1e-9);

    if (cold_start)
    {
        profile.ewma_pps = inst_pps;
        profile.ewma_bps = inst_bps;
    }
    else
    {
        if (window_age > config_.ewma.stale_seconds)
        {
            profile.ewma_pps = inst_pps;
            profile.ewma_bps = inst_bps;
            profile.window_packet_count = 0;
            profile.window_byte_count = 0;
            profile.window_start = now;
            return nullptr;
        }
        profile.ewma_pps = (alpha * inst_pps) + (one_minus_a * profile.ewma_pps);
        profile.ewma_bps = (alpha * inst_bps) + (one_minus_a * profile.ewma_bps);
    }

    // Reset sliding window counters for the next interval
    profile.window_packet_count = 0;
    profile.window_byte_count = 0;
    profile.window_start = now;

    if (cold_start)
    {
        return nullptr; // No anomaly on first window
    }

    // Anomaly scoring
    const double baseline_pps = std::max(profile.ewma_pps, 1.0);
    const double ratio_pps = inst_pps / baseline_pps;

    Severity sev = Severity::LOW;

    if (ratio_pps >= config_.ewma.high_multiplier)
    {
        sev = Severity::HIGH;
    }
    else if (ratio_pps >= config_.ewma.medium_multiplier)
    {
        sev = Severity::MEDIUM;
    }
    else
    {
        return nullptr;
    }

    const std::string threat = "VOLUME_ANOMALY";

    if (is_suppressed(profile, threat, now))
    {
        return nullptr;
    }

    record_alert_time(profile, threat, now);

    std::ostringstream desc;
    desc << std::fixed << std::setprecision(1)
         << "Traffic spike: " << inst_pps << " pps vs EWMA baseline "
         << profile.ewma_pps << " pps (ratio " << ratio_pps << "x); "
         << "inst_bps=" << inst_bps << " B/s";

    auto alert = std::make_unique<ThreatAlert>();
    alert->timestamp = now_iso8601();
    alert->threat_type = threat;
    alert->src_ip = src_ip;
    alert->dst_ip = dst_ip;
    alert->src_port = 0;
    alert->dst_port = 0;
    alert->severity = sev;
    alert->description = desc.str();
    return alert;
}
std::unique_ptr<ThreatAlert>
ThreatEngine::detect_syn_flood(PerIpProfile &profile,
                               const DissectionResult &diss,
                               std::chrono::steady_clock::time_point now)
{
    ++profile.tcp_total_count;

    const bool syn_set = (diss.tcp_flags & TCPFlag::SYN) != 0;
    const bool ack_set = (diss.tcp_flags & TCPFlag::ACK) != 0;

    // Count SYN+ACK as evidence of a completed handshake (server response)
    if (syn_set && ack_set)
    {
        ++profile.completed_handshakes;
        return nullptr;
    }

    // Pure SYN - the pattern a flood attacker sends
    if (!syn_set)
    {
        return nullptr;
    }

    ++profile.syn_only_count;
    ++profile.syn_window_count;

    const double window_age = elapsed_seconds(profile.syn_window_start, now);

    if (window_age < 1.0)
    {
        return nullptr; // Window not yet complete
    }

    // Compute SYN rate for the completed window
    const double syn_rate = static_cast<double>(profile.syn_window_count) / window_age;

    // Reset the SYN window
    profile.syn_window_count = 0;
    profile.syn_window_start = now;

    // Rate threshold check
    if (syn_rate < config_.syn_flood_rate_pps)
    {
        return nullptr;
    }

    // Ratio check — what fraction of total TCP traffic is SYN-only?
    const double syn_ratio = (profile.tcp_total_count > 0)
                                 ? static_cast<double>(profile.syn_only_count) /
                                       static_cast<double>(profile.tcp_total_count)
                                 : 0.0;

    if (syn_ratio < config_.syn_flood_ratio)
    {
        return nullptr;
    }

    const std::string threat = "SYN_FLOOD";

    if (is_suppressed(profile, threat, now))
    {
        return nullptr;
    }

    record_alert_time(profile, threat, now);

    std::ostringstream desc;
    desc << std::fixed << std::setprecision(2)
         << "SYN flood detected: rate=" << syn_rate
         << " pps (threshold=" << config_.syn_flood_rate_pps
         << "); SYN-only ratio=" << (syn_ratio * 100.0)
         << "% (threshold=" << (config_.syn_flood_ratio * 100.0)
         << "%); completed_handshakes=" << profile.completed_handshakes
         << "; dst=" << diss.dst_ip << ":" << diss.dst_port;

    auto alert = std::make_unique<ThreatAlert>();
    alert->timestamp = now_iso8601();
    alert->threat_type = threat;
    alert->src_ip = diss.src_ip;
    alert->dst_ip = diss.dst_ip;
    alert->src_port = diss.src_port;
    alert->dst_port = diss.dst_port;
    alert->severity = Severity::HIGH;
    alert->description = desc.str();
    return alert;
}

// Port Scan detection
std::unique_ptr<ThreatAlert>
ThreatEngine::detect_port_scan(PerIpProfile &profile,
                               const DissectionResult &diss,
                               std::chrono::steady_clock::time_point now)
{
    const double window_age = elapsed_seconds(profile.scan_window_start, now);

    // Roll the window when it expires
    if (window_age >= config_.port_scan_window_sec)
    {
        profile.scanned_ports.clear();
        profile.scan_window_start = now;
    }

    profile.scanned_ports.insert(diss.dst_port);

    const auto port_count = static_cast<uint32_t>(profile.scanned_ports.size());

    if (port_count < config_.port_scan_distinct_ports)
    {
        return nullptr;
    }

    const std::string threat = "PORT_SCAN";

    if (is_suppressed(profile, threat, now))
    {
        return nullptr;
    }

    record_alert_time(profile, threat, now);

    // Determine severity: approaching twice the threshold = HIGH
    const Severity sev = (port_count >= config_.port_scan_distinct_ports * 2)
                             ? Severity::HIGH
                             : Severity::MEDIUM;

    std::ostringstream desc;
    desc << "Port scan detected: " << port_count
         << " distinct dst ports in " << std::fixed << std::setprecision(1)
         << std::min(window_age, config_.port_scan_window_sec)
         << "s (threshold=" << config_.port_scan_distinct_ports
         << "); target=" << diss.dst_ip
         << "; proto=" << (diss.l4_protocol == L4Protocol::TCP ? "TCP" : "UDP");

    auto alert = std::make_unique<ThreatAlert>();
    alert->timestamp = now_iso8601();
    alert->threat_type = threat;
    alert->src_ip = diss.src_ip;
    alert->dst_ip = diss.dst_ip;
    alert->src_port = diss.src_port;
    alert->dst_port = diss.dst_port;
    alert->severity = sev;
    alert->description = desc.str();
    return alert;
}

// Brute Force detection
std::unique_ptr<ThreatAlert>
ThreatEngine::detect_brute_force(PerIpProfile &profile,
                                 const DissectionResult &diss,
                                 std::chrono::steady_clock::time_point now)
{
    const uint16_t port = diss.dst_port;

    auto &[window_start, window_count] = profile.brute_force_state[port];

    // Initialise on first access
    if (window_count == 0 &&
        window_start == std::chrono::steady_clock::time_point{})
    {
        window_start = now;
    }

    const double window_age = elapsed_seconds(window_start, now);

    if (window_age >= 1.0)
    {
        // Evaluate this completed window
        const double rate = static_cast<double>(window_count) / window_age;

        // Reset for next window
        window_count = 1;
        window_start = now;

        if (rate >= config_.brute_force_rate_pps)
        {
            const std::string threat = "BRUTE_FORCE";

            if (is_suppressed(profile, threat, now))
            {
                return nullptr;
            }

            record_alert_time(profile, threat, now);

            const Severity sev = (rate >= config_.brute_force_rate_pps * 3.0)
                                     ? Severity::CRITICAL
                                     : Severity::HIGH;

            // Map well-known port numbers to service names for the description
            const char *service = "UNKNOWN";
            switch (port)
            {
            case 22:
                service = "SSH";
                break;
            case 23:
                service = "Telnet";
                break;
            case 21:
                service = "FTP";
                break;
            case 25:
                service = "SMTP";
                break;
            case 110:
                service = "POP3";
                break;
            case 143:
                service = "IMAP";
                break;
            case 3389:
                service = "RDP";
                break;
            case 5900:
                service = "VNC";
                break;
            default:
                service = "SENSITIVE_PORT";
                break;
            }

            std::ostringstream desc;
            desc << std::fixed << std::setprecision(1)
                 << "Brute force attempt on " << service
                 << " (port " << port << "): rate=" << rate
                 << " pps (threshold=" << config_.brute_force_rate_pps
                 << "); target=" << diss.dst_ip;

            auto alert = std::make_unique<ThreatAlert>();
            alert->timestamp = now_iso8601();
            alert->threat_type = threat;
            alert->src_ip = diss.src_ip;
            alert->dst_ip = diss.dst_ip;
            alert->src_port = diss.src_port;
            alert->dst_port = port;
            alert->severity = sev;
            alert->description = desc.str();
            return alert;
        }
    }
    else
    {
        ++window_count;
    }

    return nullptr;
}

// DNS Tunneling detection
std::unique_ptr<ThreatAlert>
ThreatEngine::detect_dns_tunneling(PerIpProfile &profile,
                                   const DissectionResult &diss,
                                   std::chrono::steady_clock::time_point now)
{
    const DnsSignature &dns = *diss.dns;

    // Heuristic A: Anomalously long query name
    const std::size_t name_len = dns.query_name.size();
    std::size_t max_label_len = 0;
    {
        std::size_t label_start = 0;
        const std::string &qname = dns.query_name;

        for (std::size_t i = 0; i <= qname.size(); ++i)
        {
            if (i == qname.size() || qname[i] == '.')
            {
                const std::size_t label_len = i - label_start;
                if (label_len > max_label_len)
                {
                    max_label_len = label_len;
                }
                label_start = i + 1;
            }
        }
    }

    const bool long_name = (name_len >= config_.dns_suspicious_total_length);
    const bool long_label = (max_label_len >= config_.dns_suspicious_label_length);

    if (long_name || long_label)
    {
        const std::string threat = "DNS_TUNNELING";

        if (!is_suppressed(profile, threat, now))
        {
            record_alert_time(profile, threat, now);

            std::ostringstream desc;
            desc << "Suspicious DNS query: name_len=" << name_len
                 << " (threshold=" << config_.dns_suspicious_total_length
                 << "); max_label_len=" << max_label_len
                 << " (threshold=" << config_.dns_suspicious_label_length
                 << "); query=" << dns.query_name
                 << "; qtype=" << dns.query_type;

            auto alert = std::make_unique<ThreatAlert>();
            alert->timestamp = now_iso8601();
            alert->threat_type = threat;
            alert->src_ip = diss.src_ip;
            alert->dst_ip = diss.dst_ip;
            alert->src_port = diss.src_port;
            alert->dst_port = diss.dst_port;
            alert->severity = Severity::HIGH;
            alert->description = desc.str();
            return alert;
        }
    }

    // Heuristic B: High TXT record query rate DNS QTYPE 16 = TXT
    constexpr uint16_t QTYPE_TXT = 16;

    if (dns.query_type == QTYPE_TXT)
    {
        ++profile.dns_txt_window_count;

        const double window_age = elapsed_seconds(profile.dns_txt_window_start, now);

        if (window_age >= 1.0)
        {
            const double txt_rate = static_cast<double>(profile.dns_txt_window_count) / window_age;

            profile.dns_txt_window_count = 0;
            profile.dns_txt_window_start = now;

            if (txt_rate >= config_.dns_txt_rate_threshold)
            {
                const std::string threat = "DNS_TUNNELING";

                if (!is_suppressed(profile, threat, now))
                {
                    record_alert_time(profile, threat, now);

                    std::ostringstream desc;
                    desc << std::fixed << std::setprecision(1)
                         << "High DNS TXT query rate: " << txt_rate
                         << " TXT/s (threshold=" << config_.dns_txt_rate_threshold
                         << "); likely data exfiltration via DNS TXT records"
                         << "; last_query=" << dns.query_name;

                    auto alert = std::make_unique<ThreatAlert>();
                    alert->timestamp = now_iso8601();
                    alert->threat_type = threat;
                    alert->src_ip = diss.src_ip;
                    alert->dst_ip = diss.dst_ip;
                    alert->src_port = diss.src_port;
                    alert->dst_port = diss.dst_port;
                    alert->severity = Severity::HIGH;
                    alert->description = desc.str();
                    return alert;
                }
            }
        }
    }

    return nullptr;
}

// Data Exfiltration detection
std::unique_ptr<ThreatAlert>
ThreatEngine::detect_data_exfiltration(PerIpProfile &profile,
                                       const DissectionResult &diss,
                                       std::chrono::steady_clock::time_point now)
{
    // The EWMA byte rate was already updated in update_ewma_and_detect().
    // We read it here for comparison against absolute thresholds.
    const double bps = profile.ewma_bps;

    Severity sev = Severity::LOW;
    const char *level_str = nullptr;

    if (bps >= config_.exfil_bytes_per_sec_high)
    {
        sev = Severity::HIGH;
        level_str = "HIGH";
    }
    else if (bps >= config_.exfil_bytes_per_sec_medium)
    {
        sev = Severity::MEDIUM;
        level_str = "MEDIUM";
    }
    else
    {
        return nullptr;
    }

    const std::string threat = "DATA_EXFILTRATION";

    if (is_suppressed(profile, threat, now))
    {
        return nullptr;
    }

    record_alert_time(profile, threat, now);

    const double mbps = bps / 1'000'000.0;

    std::ostringstream desc;
    desc << std::fixed << std::setprecision(2)
         << level_str << " outbound data volume: EWMA=" << mbps
         << " MB/s (medium threshold="
         << (config_.exfil_bytes_per_sec_medium / 1'000'000.0)
         << " MB/s, high threshold="
         << (config_.exfil_bytes_per_sec_high / 1'000'000.0)
         << " MB/s); dst=" << diss.dst_ip
         << ":" << diss.dst_port;

    auto alert = std::make_unique<ThreatAlert>();
    alert->timestamp = now_iso8601();
    alert->threat_type = threat;
    alert->src_ip = diss.src_ip;
    alert->dst_ip = diss.dst_ip;
    alert->src_port = diss.src_port;
    alert->dst_port = diss.dst_port;
    alert->severity = sev;
    alert->description = desc.str();
    return alert;
}

// Alert suppression helpers
bool ThreatEngine::is_suppressed(PerIpProfile &profile,
                                 const std::string &threat_type,
                                 std::chrono::steady_clock::time_point now) const
{
    const auto it = profile.last_alert_time.find(threat_type);

    if (it == profile.last_alert_time.end())
    {
        return false;
    }

    const double since_last = elapsed_seconds(it->second, now);
    return (since_last < config_.alert_suppression_sec);
}

void ThreatEngine::record_alert_time(PerIpProfile &profile,
                                     const std::string &threat_type,
                                     std::chrono::steady_clock::time_point now)
{
    profile.last_alert_time[threat_type] = now;
}

// fire_alert - persist to SQLite + print to stdout
void ThreatEngine::fire_alert(ThreatAlert alert)
{
    ++alert_count_;

    // Terminal output
    std::cout
        << "\n"
        << "╔══════════════════════════════════════════════════════════════╗\n"
        << "║  THREAT ALERT  #" << std::setw(8) << std::left << alert_count_.load()
        << "                           ║\n"
        << "╠══════════════════════════════════════════════════════════════╣\n"
        << "║  Type      : " << std::setw(49) << std::left << alert.threat_type << "║\n"
        << "║  Severity  : " << std::setw(49) << std::left << severity_to_string(alert.severity) << "║\n"
        << "║  Timestamp : " << std::setw(49) << std::left << alert.timestamp << "║\n"
        << "║  Src IP    : " << std::setw(49) << std::left << alert.src_ip << "║\n"
        << "║  Dst IP    : " << std::setw(49) << std::left << alert.dst_ip << "║\n"
        << "║  Src Port  : " << std::setw(49) << std::left << alert.src_port << "║\n"
        << "║  Dst Port  : " << std::setw(49) << std::left << alert.dst_port << "║\n"
        << "║  Evidence  : " << std::left;

    // Wrap the description at 49 chars per line inside the box
    const std::string &desc = alert.description;
    constexpr std::size_t LINE_WIDTH = 49;
    std::size_t pos = 0;

    while (pos < desc.size())
    {
        const std::size_t chunk = std::min(LINE_WIDTH, desc.size() - pos);

        if (pos == 0)
        {
            std::cout << std::setw(static_cast<int>(LINE_WIDTH)) << desc.substr(pos, chunk) << "║\n";
        }
        else
        {
            std::cout << "║              "
                      << std::setw(static_cast<int>(LINE_WIDTH)) << desc.substr(pos, chunk) << "║\n";
        }

        pos += chunk;
    }

    std::cout
        << "╚══════════════════════════════════════════════════════════════╝\n";
    std::cout.flush();

    // SQLite persistence
    {
        std::lock_guard<std::mutex> db_lock(db_mutex_);

        if (insert_stmt_ == nullptr || db_ == nullptr)
        {
            return;
        }

        // Reset the prepared statement for re-use
        sqlite3_reset(insert_stmt_);
        sqlite3_clear_bindings(insert_stmt_);

        // Bind all parameters by index (1-based in SQLite)
        sqlite3_bind_text(insert_stmt_, 1,
                          alert.timestamp.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(insert_stmt_, 2,
                          alert.threat_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(insert_stmt_, 3,
                          alert.src_ip.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(insert_stmt_, 4,
                          alert.dst_ip.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(insert_stmt_, 5,
                         static_cast<int>(alert.src_port));
        sqlite3_bind_int(insert_stmt_, 6,
                         static_cast<int>(alert.dst_port));
        sqlite3_bind_text(insert_stmt_, 7,
                          severity_to_string(alert.severity), -1, SQLITE_STATIC);
        sqlite3_bind_text(insert_stmt_, 8,
                          alert.description.c_str(), -1, SQLITE_TRANSIENT);

        const int rc = sqlite3_step(insert_stmt_);

        if (rc != SQLITE_DONE)
        {
            std::cerr << "[ThreatEngine] SQLite INSERT failed (rc=" << rc
                      << "): " << sqlite3_errmsg(db_) << "\n";
        }
    }
}

// Miscellaneous helpers
uint64_t ThreatEngine::total_alerts() const noexcept
{
    return alert_count_.load(std::memory_order_relaxed);
}

bool ThreatEngine::is_sensitive_port(uint16_t port) const noexcept
{
    for (const uint16_t p : config_.sensitive_ports)
    {
        if (p == port)
        {
            return true;
        }
    }
    return false;
}

std::string ThreatEngine::now_iso8601()
{
    // Use wall-clock time for the human-readable timestamp stored in the DB
    const auto wall_now = std::chrono::system_clock::now();
    const std::time_t t = std::chrono::system_clock::to_time_t(wall_now);

    struct tm tm_buf{};
    gmtime_r(&t, &tm_buf);

    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
    return std::string(buf);
}