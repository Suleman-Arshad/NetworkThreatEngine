#pragma once
#ifndef NTE_FLOW_TRACKER_HPP
#define NTE_FLOW_TRACKER_HPP

#include "Config.hpp"
#include "FlowKey.hpp"
#include "FlowRecord.hpp"
#include "PacketInfo.hpp"
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <unordered_map>
#include <vector>

namespace nte
{
    using FlowTable = std::unordered_map<FlowKey, FlowRecord, FlowKeyHash, FlowKeyEqual>;

    class FlowTracker
    {
    public:
        explicit FlowTracker(const Config &config);
        ~FlowTracker();
        FlowTracker(const FlowTracker &) = delete;
        FlowTracker &operator=(const FlowTracker &) = delete;
        FlowTracker(FlowTracker &&) = delete;
        FlowTracker &operator=(FlowTracker &&) = delete;

        void start_reaper();
        void stop_reaper() noexcept;
        FlowRecord *update(const PacketInfo &info);

        [[nodiscard]] std::size_t active_flow_count() const noexcept;
        [[nodiscard]] uint64_t total_flows_created() const noexcept;
        [[nodiscard]] uint64_t total_flows_evicted() const noexcept;
        [[nodiscard]] std::vector<FlowRecord *> snapshot_active_flows(std::size_t max_count);

    private:
        FlowTrackerConfig config_;
        FlowTable table_;
        mutable std::shared_mutex table_mutex_;
        std::atomic<uint64_t> total_flows_created_;
        std::atomic<uint64_t> total_flows_evicted_;
        std::atomic<std::size_t> active_flow_count_;
        std::thread reaper_thread_;
        std::mutex reaper_mutex_;
        std::condition_variable reaper_cv_;
        std::atomic<bool> running_;

        void update_record(FlowRecord &record, const PacketInfo &info,
                           FlowDirection direction,
                           std::chrono::steady_clock::time_point now) noexcept;
        static Addr128 make_addr128_from_ipv4_string(const std::string &ip) noexcept;
        static Addr128 make_addr128_from_ipv6_string(const std::string &ip) noexcept;
        void reaper_loop();
        void evict_expired_flows();
    };

    FlowTracker *get_flow_tracker() noexcept;
    void set_flow_tracker(FlowTracker *ft) noexcept;
}
#endif // NTE_FLOW_TRACKER_HPP