#pragma once
#ifndef NTE_DELIVERY_LAYER_HPP
#define NTE_DELIVERY_LAYER_HPP

#include "Config.hpp"
#include "ThreatAlert.hpp"
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <queue>
#include <string>
#include <thread>

struct sqlite3;
struct sqlite3_stmt;

// Forward-declare WINDOW so callers don't need ncurses.h
typedef struct _win_st WINDOW;

namespace nte
{
    struct EngineStats
    {
        uint64_t packets_captured{0};
        uint64_t packets_dropped_ring{0};
        uint64_t packets_dropped_kernel{0};
        std::size_t ring_queue_depth{0};
        std::size_t active_flows{0};
        uint64_t total_alerts{0};
        double capture_pps{0.0};
        double drop_rate_pct{0.0};
    };

    using StatsProvider = std::function<EngineStats()>;

    class DeliveryLayer
    {
    public:
        explicit DeliveryLayer(const Config &config, StatsProvider stats_fn);
        ~DeliveryLayer();
        DeliveryLayer(const DeliveryLayer &) = delete;
        DeliveryLayer &operator=(const DeliveryLayer &) = delete;
        DeliveryLayer(DeliveryLayer &&) = delete;
        DeliveryLayer &operator=(DeliveryLayer &&) = delete;

        void start();
        void stop() noexcept;
        void enqueue_alert(const ThreatAlert &alert);
        [[nodiscard]] uint64_t total_persisted() const noexcept;

    private:
        static constexpr std::size_t DISPLAY_RING_SIZE = 50;

        DeliveryConfig config_;
        StatsProvider stats_fn_;
        sqlite3 *db_;
        sqlite3_stmt *insert_stmt_;
        std::mutex db_mutex_;

        std::queue<ThreatAlert> alert_queue_;
        std::mutex queue_mutex_;
        std::condition_variable queue_cv_;

        std::deque<ThreatAlert> display_ring_;
        std::mutex display_ring_mutex_;

        std::thread writer_thread_;
        std::thread dashboard_thread_;
        std::atomic<bool> running_;
        std::atomic<uint64_t> total_persisted_;

        bool ncurses_active_;
        WINDOW *win_header_;
        WINDOW *win_stats_;
        WINDOW *win_alerts_;
        WINDOW *win_footer_;
        std::mutex ncurses_mutex_;

        void init_database();
        void close_database() noexcept;
        void persist_alert(const ThreatAlert &alert);
        void writer_loop();
        void dashboard_loop();
        void init_ncurses();
        void teardown_ncurses() noexcept;
        void redraw_dashboard();
        void print_stats_to_stdout() const;
        void print_alert_to_stdout(const ThreatAlert &alert) const;
        [[nodiscard]] static int severity_to_color_pair(Severity s) noexcept;
        [[nodiscard]] static std::string format_double(double val, int precision);
        [[nodiscard]] static std::string truncate(const std::string &s, std::size_t max_len);
    };

    DeliveryLayer *get_delivery_layer() noexcept;
    void set_delivery_layer(DeliveryLayer *dl) noexcept;
    void delivery_fire_alert(const ThreatAlert &alert);
}
#endif // NTE_DELIVERY_LAYER_HPP