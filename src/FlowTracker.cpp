#include "Flowtracker.hpp"
#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>

namespace nte
{
    FlowTracker::FlowTracker(const Config &config)
        : config_(config.flow_tracker), total_flows_created_(0),
          total_flows_evicted_(0), active_flow_count_(0), running_(false)
    {
        table_.reserve(65536);
    }

    FlowTracker::~FlowTracker() { stop_reaper(); }

    std::size_t FlowTracker::active_flow_count() const noexcept { return active_flow_count_.load(std::memory_order_relaxed); }
    uint64_t FlowTracker::total_flows_created() const noexcept { return total_flows_created_.load(std::memory_order_relaxed); }
    uint64_t FlowTracker::total_flows_evicted() const noexcept { return total_flows_evicted_.load(std::memory_order_relaxed); }

    void FlowTracker::start_reaper()
    {
        running_.store(true, std::memory_order_release);
        reaper_thread_ = std::thread([this]()
                                     { reaper_loop(); });
    }

    void FlowTracker::stop_reaper() noexcept
    {
        running_.store(false, std::memory_order_release);
        reaper_cv_.notify_all();
        if (reaper_thread_.joinable())
            reaper_thread_.join();
    }

    Addr128 FlowTracker::make_addr128_from_ipv4_string(const std::string &ip) noexcept
    {
        unsigned int a = 0, b = 0, c = 0, d = 0;
        std::sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d);
        const uint32_t h = (static_cast<uint32_t>(a) << 24) | (static_cast<uint32_t>(b) << 16) | (static_cast<uint32_t>(c) << 8) | static_cast<uint32_t>(d);
        return ipv4_to_addr128(h);
    }

    Addr128 FlowTracker::make_addr128_from_ipv6_string(const std::string &ip) noexcept
    {
        Addr128 addr{};
        struct in6_addr in6{};
        if (inet_pton(AF_INET6, ip.c_str(), &in6) == 1)
            std::memcpy(addr.data(), in6.s6_addr, 16);
        return addr;
    }

    FlowRecord *FlowTracker::update(const PacketInfo &info)
    {
        if (!info.valid)
            return nullptr;
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
            return nullptr;

        FlowKey key = FlowKey::make(src_addr, dst_addr, info.src_port, info.dst_port, info.ip_proto_num);
        const FlowDirection direction = (src_addr <= dst_addr) ? FlowDirection::LO_TO_HI : FlowDirection::HI_TO_LO;
        const auto now = std::chrono::steady_clock::now();

        {
            std::shared_lock<std::shared_mutex> rl(table_mutex_);
            auto it = table_.find(key);
            if (it != table_.end())
            {
                update_record(it->second, info, direction, now);
                return &it->second;
            }
        }

        {
            std::unique_lock<std::shared_mutex> wl(table_mutex_);
            auto it = table_.find(key);
            if (it != table_.end())
            {
                update_record(it->second, info, direction, now);
                return &it->second;
            }
            if (table_.size() >= config_.max_flows)
                return nullptr;
            auto [ni, ok] = table_.emplace(std::piecewise_construct,
                                           std::forward_as_tuple(key), std::forward_as_tuple(key));
            (void)ok;
            ++total_flows_created_;
            active_flow_count_.fetch_add(1, std::memory_order_relaxed);
            update_record(ni->second, info, direction, now);
            return &ni->second;
        }
    }

    void FlowTracker::update_record(FlowRecord &rec, const PacketInfo &info,
                                    FlowDirection direction,
                                    std::chrono::steady_clock::time_point now) noexcept
    {
        rec.last_seen = now;
        ++rec.total_packets;
        rec.total_bytes += info.captured_length;
        if (direction == FlowDirection::LO_TO_HI)
        {
            ++rec.lo_to_hi_packets;
            rec.lo_to_hi_bytes += info.captured_length;
        }
        else
        {
            ++rec.hi_to_lo_packets;
            rec.hi_to_lo_bytes += info.captured_length;
        }

        if (info.l4_proto == L4Protocol::TCP)
        {
            rec.advance_tcp_state(info.tcp_flags, direction);
            if (direction == FlowDirection::LO_TO_HI && info.dst_port != 0)
            {
                constexpr double SCAN_W = 10.0;
                if (std::chrono::duration<double>(now - rec.scan_window_start).count() >= SCAN_W)
                {
                    rec.dst_ports_contacted.clear();
                    rec.scan_window_start = now;
                }
                rec.dst_ports_contacted.insert(info.dst_port);
            }
            if ((info.tcp_flags & constants::TCP_FLAG_SYN) != 0 && (info.tcp_flags & constants::TCP_FLAG_ACK) == 0)
            {
                constexpr double SYN_W = 1.0;
                if (std::chrono::duration<double>(now - rec.syn_window_start).count() >= SYN_W)
                {
                    rec.syn_window_count = 0;
                    rec.syn_window_start = now;
                }
                ++rec.syn_window_count;
            }
        }
        if (info.l7_proto != L7Protocol::NONE)
            rec.l7_proto = info.l7_proto;
        if (info.dns.has_value())
        {
            rec.last_dns_query = info.dns->query_name;
            rec.last_dns_qtype = info.dns->query_type;
        }
        if (info.http.has_value())
        {
            rec.last_http_host = info.http->host;
            rec.last_http_method = info.http->method;
        }
        if (info.tls.has_value())
        {
            rec.last_tls_sni = info.tls->sni;
        }
    }

    std::vector<FlowRecord *> FlowTracker::snapshot_active_flows(std::size_t max_count)
    {
        std::shared_lock<std::shared_mutex> rl(table_mutex_);
        std::vector<FlowRecord *> result;
        result.reserve(std::min(max_count, table_.size()));
        for (auto &[k, r] : table_)
        {
            if (result.size() >= max_count)
                break;
            result.push_back(&r);
        }
        return result;
    }

    void FlowTracker::reaper_loop()
    {
        std::cout << "[FlowTracker] Reaper started. Interval: " << config_.reaper_interval_sec << "s\n";
        while (running_.load(std::memory_order_acquire))
        {
            {
                std::unique_lock<std::mutex> lk(reaper_mutex_);
                reaper_cv_.wait_for(lk, std::chrono::duration<double>(config_.reaper_interval_sec),
                                    [this]
                                    { return !running_.load(std::memory_order_acquire); });
            }
            if (!running_.load(std::memory_order_acquire))
                break;
            evict_expired_flows();
        }
        std::cout << "[FlowTracker] Reaper exiting.\n";
    }

    void FlowTracker::evict_expired_flows()
    {
        const auto now = std::chrono::steady_clock::now();
        std::size_t evicted = 0;
        std::unique_lock<std::shared_mutex> wl(table_mutex_);
        for (auto it = table_.begin(); it != table_.end();)
        {
            const double idle = std::chrono::duration<double>(now - it->second.last_seen).count();
            bool evict = false;
            if (it->second.key.protocol == constants::IPPROTO_TCP_NUM)
                evict = (it->second.tcp_state == TcpState::CLOSED && idle > 5.0) || idle > config_.tcp_flow_timeout_sec;
            else
                evict = idle > config_.udp_flow_timeout_sec;
            if (evict)
            {
                it = table_.erase(it);
                ++evicted;
                active_flow_count_.fetch_sub(1, std::memory_order_relaxed);
            }
            else
                ++it;
        }
        if (evicted > 0)
        {
            total_flows_evicted_.fetch_add(static_cast<uint64_t>(evicted), std::memory_order_relaxed);
            std::cout << "[FlowTracker] Evicted " << evicted << " flows. Active: " << active_flow_count_.load() << "\n";
        }
    }

    static FlowTracker *g_flow_tracker = nullptr;
    FlowTracker *get_flow_tracker() noexcept { return g_flow_tracker; }
    void set_flow_tracker(FlowTracker *ft) noexcept { g_flow_tracker = ft; }
}