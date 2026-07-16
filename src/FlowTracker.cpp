#include "Config.hpp"
#include "FlowKey.hpp"
#include "FlowRecord.hpp"
#include "PacketInfo.hpp"
#include "ThreatAlert.hpp"
#include <atomic>
#include <chrono>
#include <functional>
#include <iostream>
#include <memory>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <condition_variable>
#include <cstring>
#include <cstdio>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

namespace nte
{

    // FlowTable type alias
    using FlowTable =
        std::unordered_map<FlowKey, FlowRecord, FlowKeyHash, FlowKeyEqual>;

    // FlowTracker
    class FlowTracker
    {
    public:
        // Construction

        explicit FlowTracker(const Config &config)
            : config_(config.flow_tracker), total_flows_created_(0), total_flows_evicted_(0), active_flow_count_(0), running_(false)
        {
            // Pre-allocate bucket capacity to reduce rehashing under load
            table_.reserve(65536);
        }

        ~FlowTracker()
        {
            stop_reaper();
        }

        FlowTracker(const FlowTracker &) = delete;
        FlowTracker &operator=(const FlowTracker &) = delete;
        FlowTracker(FlowTracker &&) = delete;
        FlowTracker &operator=(FlowTracker &&) = delete;

        // Lifecycle

        // Start the background reaper thread.
        void start_reaper()
        {
            running_.store(true, std::memory_order_release);
            reaper_thread_ = std::thread([this]()
                                         { reaper_loop(); });
        }

        // Signal the reaper thread to stop and join it.
        void stop_reaper() noexcept
        {
            running_.store(false, std::memory_order_release);
            reaper_cv_.notify_all();

            if (reaper_thread_.joinable())
            {
                reaper_thread_.join();
            }
        }

        // Primary entry point
        FlowRecord *update(const PacketInfo &info)
        {
            if (!info.valid)
                return nullptr;

            // Build the flow key
            Addr128 src_addr{}, dst_addr{};

            if (info.l3_proto == L3Protocol::IPv4)
            {
                src_addr = make_addr128_from_ipv4_string(info.src_ip);
                dst_addr = make_addr128_from_ipv4_string(info.dst_ip);
            }
            else if (info.l3_proto == L3Protocol::IPv6)
            {
                src_addr = make_addr128_from_ipv6_string(info.src_ip);
                dst_addr = make_addr128_from_ipv6_string(info.dst_ip);
            }
            else
            {
                return nullptr; // ARP/OTHER - no flow tracking
            }

            const uint8_t proto = info.ip_proto_num;

            FlowKey key = FlowKey::make(
                src_addr, dst_addr,
                info.src_port, info.dst_port,
                proto);

            // Determine direction relative to the normalised key
            const FlowDirection direction =
                (src_addr <= dst_addr) ? FlowDirection::LO_TO_HI
                                       : FlowDirection::HI_TO_LO;

            const auto now = std::chrono::steady_clock::now();

            // Try shared (read) lock for existing flow
            {
                std::shared_lock<std::shared_mutex> read_lock(table_mutex_);

                auto it = table_.find(key);
                if (it != table_.end())
                {
                    update_record(it->second, info, direction, now);
                    return &it->second;
                }
            }

            // Flow not found - take exclusive lock to insert
            {
                std::unique_lock<std::shared_mutex> write_lock(table_mutex_);

                auto it = table_.find(key);
                if (it != table_.end())
                {
                    update_record(it->second, info, direction, now);
                    return &it->second;
                }

                // Capacity check
                if (table_.size() >= config_.max_flows)
                {
                    std::cerr
                        << "[FlowTracker] Max flow capacity ("
                        << config_.max_flows
                        << ") reached — dropping new flow: "
                        << key.to_string() << "\n";
                    return nullptr;
                }

                // Insert new flow record
                auto [new_it, ok] = table_.emplace(
                    std::piecewise_construct,
                    std::forward_as_tuple(key),
                    std::forward_as_tuple(key));
                (void)ok;

                ++total_flows_created_;
                active_flow_count_.fetch_add(1, std::memory_order_relaxed);

                update_record(new_it->second, info, direction, now);
                return &new_it->second;
            }
        }

        // Diagnostics

        [[nodiscard]] std::size_t active_flow_count() const noexcept
        {
            return active_flow_count_.load(std::memory_order_relaxed);
        }

        [[nodiscard]] uint64_t total_flows_created() const noexcept
        {
            return total_flows_created_.load(std::memory_order_relaxed);
        }

        [[nodiscard]] uint64_t total_flows_evicted() const noexcept
        {
            return total_flows_evicted_.load(std::memory_order_relaxed);
        }

        // Collect a snapshot of current flow records for dashboard display.
        // Returns up to max_count records ordered by most-recently-seen.
        [[nodiscard]] std::vector<FlowRecord *>
        snapshot_active_flows(std::size_t max_count)
        {
            std::shared_lock<std::shared_mutex> read_lock(table_mutex_);

            std::vector<FlowRecord *> result;
            result.reserve(std::min(max_count, table_.size()));

            for (auto &[key, record] : table_)
            {
                if (result.size() >= max_count)
                    break;
                result.push_back(&record);
            }

            return result;
        }

    private:
        // Configuration
        FlowTrackerConfig config_;

        // Flow table
        FlowTable table_;
        mutable std::shared_mutex table_mutex_;

        // Telemetry
        std::atomic<uint64_t> total_flows_created_;
        std::atomic<uint64_t> total_flows_evicted_;
        std::atomic<std::size_t> active_flow_count_;

        // Reaper thread
        std::thread reaper_thread_;
        std::mutex reaper_mutex_;
        std::condition_variable reaper_cv_;
        std::atomic<bool> running_;

        void update_record(FlowRecord &record,
                           const PacketInfo &info,
                           FlowDirection direction,
                           std::chrono::steady_clock::time_point now) noexcept
        {
            record.last_seen = now;
            ++record.total_packets;
            record.total_bytes += info.captured_length;

            if (direction == FlowDirection::LO_TO_HI)
            {
                ++record.lo_to_hi_packets;
                record.lo_to_hi_bytes += info.captured_length;
            }
            else
            {
                ++record.hi_to_lo_packets;
                record.hi_to_lo_bytes += info.captured_length;
            }

            // TCP state machine
            if (info.l4_proto == L4Protocol::TCP)
            {
                record.advance_tcp_state(info.tcp_flags, direction);

                if (direction == FlowDirection::LO_TO_HI && info.dst_port != 0)
                {
                    const double scan_window_age =
                        std::chrono::duration<double>(
                            now - record.scan_window_start)
                            .count();

                    // Use a 10-second window (matches PortScanConfig default)
                    constexpr double SCAN_WINDOW_SEC = 10.0;

                    if (scan_window_age >= SCAN_WINDOW_SEC)
                    {
                        record.dst_ports_contacted.clear();
                        record.scan_window_start = now;
                    }

                    record.dst_ports_contacted.insert(info.dst_port);
                }

                // SYN flood window tracking
                const bool syn_set =
                    (info.tcp_flags & constants::TCP_FLAG_SYN) != 0;
                const bool ack_set =
                    (info.tcp_flags & constants::TCP_FLAG_ACK) != 0;

                if (syn_set && !ack_set)
                {
                    const double syn_window_age =
                        std::chrono::duration<double>(
                            now - record.syn_window_start)
                            .count();

                    constexpr double SYN_WINDOW_SEC = 1.0;

                    if (syn_window_age >= SYN_WINDOW_SEC)
                    {
                        record.syn_window_count = 0;
                        record.syn_window_start = now;
                    }

                    ++record.syn_window_count;
                }
            }

            // Application layer indicators
            if (info.l7_proto != L7Protocol::NONE)
            {
                record.l7_proto = info.l7_proto;
            }

            if (info.dns.has_value())
            {
                record.last_dns_query = info.dns->query_name;
                record.last_dns_qtype = info.dns->query_type;
            }

            if (info.http.has_value())
            {
                record.last_http_host = info.http->host;
                record.last_http_method = info.http->method;
            }

            if (info.tls.has_value())
            {
                record.last_tls_sni = info.tls->sni;
            }
        }

        // Address parsing helpers

        // Parse a dotted-decimal IPv4 string into an IPv4-mapped Addr128.
        static Addr128 make_addr128_from_ipv4_string(const std::string &ip) noexcept
        {
            unsigned int a = 0, b = 0, c = 0, d = 0;
            std::sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d);

            const uint32_t host_order =
                (static_cast<uint32_t>(a) << 24) |
                (static_cast<uint32_t>(b) << 16) |
                (static_cast<uint32_t>(c) << 8) |
                static_cast<uint32_t>(d);

            return ipv4_to_addr128(host_order);
        }

        // Parse a colon-hex IPv6 string into an Addr128.
        // Uses inet_pton for correctness and RFC 5952 compatibility.
        static Addr128 make_addr128_from_ipv6_string(const std::string &ip) noexcept
        {
            Addr128 addr{};
            struct in6_addr in6{};

            if (inet_pton(AF_INET6, ip.c_str(), &in6) == 1)
            {
                std::memcpy(addr.data(), in6.s6_addr, 16);
            }

            return addr;
        }

        // Reaper thread

        void reaper_loop()
        {
            std::cout << "[FlowTracker] Reaper thread started. "
                         "Interval: "
                      << config_.reaper_interval_sec << "s\n";
            std::cout.flush();

            while (running_.load(std::memory_order_acquire))
            {
                // Sleep for the configured interval using condition_variable so stop_reaper() can wake us immediately.
                {
                    std::unique_lock<std::mutex> lock(reaper_mutex_);
                    reaper_cv_.wait_for(
                        lock,
                        std::chrono::duration<double>(config_.reaper_interval_sec),
                        [this]()
                        {
                            return !running_.load(std::memory_order_acquire);
                        });
                }

                if (!running_.load(std::memory_order_acquire))
                    break;

                evict_expired_flows();
            }

            std::cout << "[FlowTracker] Reaper thread exiting.\n";
            std::cout.flush();
        }

        void evict_expired_flows()
        {
            const auto now = std::chrono::steady_clock::now();
            std::size_t evicted = 0;

            std::unique_lock<std::shared_mutex> write_lock(table_mutex_);

            for (auto it = table_.begin(); it != table_.end();)
            {
                const FlowRecord &rec = it->second;
                const double idle =
                    std::chrono::duration<double>(now - rec.last_seen).count();

                bool should_evict = false;

                if (rec.key.protocol == constants::IPPROTO_TCP_NUM)
                {
                    // Evict closed TCP flows immediately after a grace period
                    if (rec.tcp_state == TcpState::CLOSED && idle > 5.0)
                    {
                        should_evict = true;
                    }
                    else if (idle > config_.tcp_flow_timeout_sec)
                    {
                        should_evict = true;
                    }
                }
                else
                {
                    // UDP and other protocols - evict on idle timeout
                    if (idle > config_.udp_flow_timeout_sec)
                    {
                        should_evict = true;
                    }
                }

                if (should_evict)
                {
                    it = table_.erase(it);
                    ++evicted;
                    active_flow_count_.fetch_sub(1, std::memory_order_relaxed);
                }
                else
                {
                    ++it;
                }
            }

            if (evicted > 0)
            {
                total_flows_evicted_.fetch_add(
                    static_cast<uint64_t>(evicted), std::memory_order_relaxed);

                std::cout << "[FlowTracker] Evicted " << evicted
                          << " expired flows. Active: "
                          << active_flow_count_.load(std::memory_order_relaxed)
                          << "\n";
                std::cout.flush();
            }
        }
    };

    static FlowTracker *g_flow_tracker = nullptr;

    FlowTracker *get_flow_tracker() noexcept { return g_flow_tracker; }
    void set_flow_tracker(FlowTracker *ft) noexcept { g_flow_tracker = ft; }

} // namespace nte