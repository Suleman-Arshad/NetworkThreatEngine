#include "Config.hpp"
#include "ThreatAlert.hpp"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <ctime>
#include <deque>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <queue>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <sqlite3.h>
#include <ncurses.h>
#include <unistd.h>
#include <functional>

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

    // Function pointer set by main() so DeliveryLayer can pull stats without depending on a specific global instance.
    using StatsProvider = std::function<EngineStats()>;

    // ncurses colour pair constants
    namespace color
    {
        constexpr int NORMAL = 1;   // white on black
        constexpr int HEADER = 2;   // cyan on black
        constexpr int LOW = 3;      // green on black
        constexpr int MEDIUM = 4;   // yellow on black
        constexpr int HIGH = 5;     // red on black
        constexpr int CRITICAL = 6; // magenta on black
        constexpr int STAT_VAL = 7; // bright white on black
    }

    // DeliveryLayer
    class DeliveryLayer
    {
    public:
        // Construction

        explicit DeliveryLayer(const Config &config,
                               StatsProvider stats_fn)
            : config_(config.delivery), stats_fn_(std::move(stats_fn)), db_(nullptr), insert_stmt_(nullptr), running_(false), total_persisted_(0), ncurses_active_(false)
        {
        }

        ~DeliveryLayer()
        {
            stop();
        }

        DeliveryLayer(const DeliveryLayer &) = delete;
        DeliveryLayer &operator=(const DeliveryLayer &) = delete;
        DeliveryLayer(DeliveryLayer &&) = delete;
        DeliveryLayer &operator=(DeliveryLayer &&) = delete;

        // Lifecycle

        void start()
        {
            if (running_.load(std::memory_order_acquire))
                return;

            init_database();
            init_ncurses();

            running_.store(true, std::memory_order_release);

            writer_thread_ = std::thread([this]()
                                         { writer_loop(); });
            dashboard_thread_ = std::thread([this]()
                                            { dashboard_loop(); });

            std::cout << "[DeliveryLayer] Started. DB: "
                      << config_.db_path << "\n";
            std::cout.flush();
        }

        void stop() noexcept
        {
            if (!running_.load(std::memory_order_acquire))
                return;

            running_.store(false, std::memory_order_release);
            queue_cv_.notify_all();

            if (writer_thread_.joinable())
                writer_thread_.join();
            if (dashboard_thread_.joinable())
                dashboard_thread_.join();

            teardown_ncurses();
            close_database();

            std::cout << "[DeliveryLayer] Stopped. Total persisted: "
                      << total_persisted_.load(std::memory_order_relaxed)
                      << " alerts.\n";
        }

        // Alert intake (called from Consumer thread)

        void enqueue_alert(const ThreatAlert &alert)
        {
            {
                std::lock_guard<std::mutex> lock(queue_mutex_);
                alert_queue_.push(alert);
            }
            queue_cv_.notify_one();
        }

        // Diagnostics

        [[nodiscard]] uint64_t total_persisted() const noexcept
        {
            return total_persisted_.load(std::memory_order_relaxed);
        }

    private:
        // Configuration
        DeliveryConfig config_;
        StatsProvider stats_fn_;

        // SQLite state
        sqlite3 *db_;
        sqlite3_stmt *insert_stmt_;
        std::mutex db_mutex_;

        // Alert queue (Consumer thread -> Writer thread)
        std::queue<ThreatAlert> alert_queue_;
        std::mutex queue_mutex_;
        std::condition_variable queue_cv_;

        // Alert display ring (Writer thread -> Dashboard thread)
        // Bounded ring of the most recent alerts for dashboard display.
        static constexpr std::size_t DISPLAY_RING_SIZE = 50;
        std::deque<ThreatAlert> display_ring_;
        std::mutex display_ring_mutex_;

        // Threads
        std::thread writer_thread_;
        std::thread dashboard_thread_;
        std::atomic<bool> running_;
        std::atomic<uint64_t> total_persisted_;

        // ncurses state
        bool ncurses_active_;
        WINDOW *win_header_{nullptr};
        WINDOW *win_stats_{nullptr};
        WINDOW *win_alerts_{nullptr};
        WINDOW *win_footer_{nullptr};
        std::mutex ncurses_mutex_;

        // SQLite initialisation

        void init_database()
        {
            std::lock_guard<std::mutex> lock(db_mutex_);

            if (sqlite3_open(config_.db_path.c_str(), &db_) != SQLITE_OK)
            {
                const std::string err = (db_ != nullptr)
                                            ? sqlite3_errmsg(db_)
                                            : "unknown error";
                if (db_)
                    sqlite3_close(db_);
                db_ = nullptr;
                throw std::runtime_error(
                    "[DeliveryLayer] Cannot open SQLite DB '" + config_.db_path + "': " + err);
            }

            // Performance pragmas
            sqlite3_exec(db_, "PRAGMA journal_mode=WAL;",
                         nullptr, nullptr, nullptr);
            sqlite3_exec(db_, "PRAGMA synchronous=NORMAL;",
                         nullptr, nullptr, nullptr);

            // Create alerts table
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
                "  description TEXT    NOT NULL,"
                "  observed    REAL    DEFAULT 0.0,"
                "  baseline    REAL    DEFAULT 0.0,"
                "  threshold   REAL    DEFAULT 0.0"
                ");";

            char *errmsg = nullptr;
            if (sqlite3_exec(db_, create_sql,
                             nullptr, nullptr, &errmsg) != SQLITE_OK)
            {
                std::string err = errmsg ? errmsg : "unknown";
                sqlite3_free(errmsg);
                throw std::runtime_error(
                    "[DeliveryLayer] Failed to create alerts table: " + err);
            }

            // Indexes for common query patterns
            sqlite3_exec(db_,
                         "CREATE INDEX IF NOT EXISTS idx_alerts_src "
                         "ON alerts(src_ip);",
                         nullptr, nullptr, nullptr);

            sqlite3_exec(db_,
                         "CREATE INDEX IF NOT EXISTS idx_alerts_ts "
                         "ON alerts(timestamp);",
                         nullptr, nullptr, nullptr);

            sqlite3_exec(db_,
                         "CREATE INDEX IF NOT EXISTS idx_alerts_type "
                         "ON alerts(threat_type);",
                         nullptr, nullptr, nullptr);

            // Prepare INSERT statement - parameterised to prevent SQL injection
            const char *insert_sql =
                "INSERT INTO alerts "
                "(timestamp, threat_type, src_ip, dst_ip, "
                " src_port, dst_port, severity, description,"
                " observed, baseline, threshold) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?);";

            if (sqlite3_prepare_v2(db_, insert_sql, -1,
                                   &insert_stmt_, nullptr) != SQLITE_OK)
            {
                throw std::runtime_error(
                    std::string("[DeliveryLayer] Failed to prepare INSERT: ") + sqlite3_errmsg(db_));
            }
        }

        void close_database() noexcept
        {
            std::lock_guard<std::mutex> lock(db_mutex_);

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

        // SQLite alert persistence

        void persist_alert(const ThreatAlert &alert)
        {
            std::lock_guard<std::mutex> lock(db_mutex_);

            if (db_ == nullptr || insert_stmt_ == nullptr)
                return;

            sqlite3_reset(insert_stmt_);
            sqlite3_clear_bindings(insert_stmt_);

            // Bind all 11 parameters by position (1-indexed)
            sqlite3_bind_text(insert_stmt_, 1,
                              alert.timestamp_iso.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(insert_stmt_, 2,
                              alert.type_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(insert_stmt_, 3,
                              alert.src_ip.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(insert_stmt_, 4,
                              alert.dst_ip.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(insert_stmt_, 5,
                             static_cast<int>(alert.src_port));
            sqlite3_bind_int(insert_stmt_, 6,
                             static_cast<int>(alert.dst_port));
            sqlite3_bind_text(insert_stmt_, 7,
                              alert.severity_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(insert_stmt_, 8,
                              alert.evidence_summary.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_double(insert_stmt_, 9, alert.observed_value);
            sqlite3_bind_double(insert_stmt_, 10, alert.baseline_value);
            sqlite3_bind_double(insert_stmt_, 11, alert.threshold_value);

            const int rc = sqlite3_step(insert_stmt_);

            if (rc != SQLITE_DONE)
            {
                std::cerr << "[DeliveryLayer] SQLite INSERT failed (rc="
                          << rc << "): " << sqlite3_errmsg(db_) << "\n";
            }
            else
            {
                total_persisted_.fetch_add(1, std::memory_order_relaxed);
            }
        }

        // Writer thread

        void writer_loop()
        {
            while (running_.load(std::memory_order_acquire))
            {
                ThreatAlert alert;
                bool has_alert = false;

                {
                    std::unique_lock<std::mutex> lock(queue_mutex_);
                    queue_cv_.wait(lock, [this]()
                                   { return !alert_queue_.empty() || !running_.load(std::memory_order_acquire); });

                    if (!alert_queue_.empty())
                    {
                        alert = alert_queue_.front();
                        alert_queue_.pop();
                        has_alert = true;
                    }
                }

                if (!has_alert)
                    continue;

                // Persist to SQLite
                persist_alert(alert);

                // Print to terminal (only when ncurses is not active)
                if (!ncurses_active_)
                {
                    print_alert_to_stdout(alert);
                }

                // Add to display ring for dashboard
                {
                    std::lock_guard<std::mutex> ring_lock(display_ring_mutex_);
                    display_ring_.push_back(alert);

                    while (display_ring_.size() > DISPLAY_RING_SIZE)
                    {
                        display_ring_.pop_front();
                    }
                }
            }

            // Drain remaining alerts on shutdown
            std::unique_lock<std::mutex> lock(queue_mutex_);
            while (!alert_queue_.empty())
            {
                persist_alert(alert_queue_.front());
                alert_queue_.pop();
            }
        }

        // Terminal output (no-ncurses fallback)

        void print_alert_to_stdout(const ThreatAlert &alert) const
        {
            std::ostringstream oss;
            oss << "\n"
                << "╔══════════════════════════════════════════════════════════════╗\n"
                << "║  THREAT ALERT                                                ║\n"
                << "╠══════════════════════════════════════════════════════════════╣\n"
                << "║  Type      : " << std::left << std::setw(49)
                << alert.type_str() << "║\n"
                << "║  Severity  : " << std::setw(49)
                << alert.severity_str() << "║\n"
                << "║  Time      : " << std::setw(49)
                << alert.timestamp_iso << "║\n"
                << "║  Src       : " << std::setw(49)
                << (alert.src_ip + ":" + std::to_string(alert.src_port)) << "║\n"
                << "║  Dst       : " << std::setw(49)
                << (alert.dst_ip + ":" + std::to_string(alert.dst_port)) << "║\n";

            // Wrap evidence at 49 chars per line
            const std::string &ev = alert.evidence_summary;
            constexpr int WIDTH = 49;
            std::size_t pos = 0;
            bool first = true;

            while (pos < ev.size())
            {
                const std::size_t chunk =
                    std::min(static_cast<std::size_t>(WIDTH), ev.size() - pos);

                if (first)
                {
                    oss << "║  Evidence  : " << std::setw(WIDTH)
                        << ev.substr(pos, chunk) << "║\n";
                    first = false;
                }
                else
                {
                    oss << "║              " << std::setw(WIDTH)
                        << ev.substr(pos, chunk) << "║\n";
                }

                pos += chunk;
            }

            oss << "╚══════════════════════════════════════════════════════════════╝\n";

            std::cout << oss.str();
            std::cout.flush();
        }

        // ncurses initialisation

        void init_ncurses()
        {
            // Only initialise ncurses if we are attached to a terminal.
            // When piped or redirected, fall back to plain stdout.
            if (!isatty(STDOUT_FILENO))
            {
                ncurses_active_ = false;
                return;
            }

            initscr();
            cbreak();
            noecho();
            curs_set(0); // hide cursor
            keypad(stdscr, TRUE);
            nodelay(stdscr, TRUE); // non-blocking getch()
            timeout(0);

            if (has_colors())
            {
                start_color();
                init_pair(color::NORMAL, COLOR_WHITE, COLOR_BLACK);
                init_pair(color::HEADER, COLOR_CYAN, COLOR_BLACK);
                init_pair(color::LOW, COLOR_GREEN, COLOR_BLACK);
                init_pair(color::MEDIUM, COLOR_YELLOW, COLOR_BLACK);
                init_pair(color::HIGH, COLOR_RED, COLOR_BLACK);
                init_pair(color::CRITICAL, COLOR_MAGENTA, COLOR_BLACK);
                init_pair(color::STAT_VAL, COLOR_WHITE, COLOR_BLACK);
            }

            // Compute window geometry
            int rows = 0, cols = 0;
            getmaxyx(stdscr, rows, cols);

            const int header_rows = 3;
            const int stats_rows = 6;
            const int footer_rows = 2;
            const int alerts_rows = rows - header_rows - stats_rows - footer_rows;

            win_header_ = newwin(header_rows, cols, 0, 0);
            win_stats_ = newwin(stats_rows, cols, header_rows, 0);
            win_alerts_ = newwin(std::max(alerts_rows, 4), cols, header_rows + stats_rows, 0);
            win_footer_ = newwin(footer_rows, cols, rows - footer_rows, 0);

            scrollok(win_alerts_, TRUE);
            ncurses_active_ = true;
        }

        void teardown_ncurses() noexcept
        {
            if (!ncurses_active_)
                return;

            std::lock_guard<std::mutex> lock(ncurses_mutex_);

            if (win_header_)
            {
                delwin(win_header_);
                win_header_ = nullptr;
            }
            if (win_stats_)
            {
                delwin(win_stats_);
                win_stats_ = nullptr;
            }
            if (win_alerts_)
            {
                delwin(win_alerts_);
                win_alerts_ = nullptr;
            }
            if (win_footer_)
            {
                delwin(win_footer_);
                win_footer_ = nullptr;
            }

            endwin();
            ncurses_active_ = false;
        }

        // Dashboard thread

        void dashboard_loop()
        {
            if (!ncurses_active_)
            {
                // No terminal - print periodic stats to stdout instead
                while (running_.load(std::memory_order_acquire))
                {
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(
                            config_.dashboard_refresh_ms * 10));

                    if (!running_.load(std::memory_order_acquire))
                        break;

                    print_stats_to_stdout();
                }
                return;
            }

            while (running_.load(std::memory_order_acquire))
            {
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(config_.dashboard_refresh_ms));

                if (!running_.load(std::memory_order_acquire))
                    break;

                redraw_dashboard();
            }
        }

        void print_stats_to_stdout() const
        {
            if (!stats_fn_)
                return;

            const EngineStats stats = stats_fn_();

            std::cout
                << "[STATS] "
                << "cap=" << stats.packets_captured
                << " pps=" << std::fixed << std::setprecision(0)
                << stats.capture_pps
                << " flows=" << stats.active_flows
                << " alerts=" << stats.total_alerts
                << " q_depth=" << stats.ring_queue_depth
                << " drop=" << std::setprecision(3)
                << stats.drop_rate_pct << "%\n";
            std::cout.flush();
        }

        void redraw_dashboard()
        {
            std::lock_guard<std::mutex> lock(ncurses_mutex_);

            if (!ncurses_active_)
                return;

            int rows = 0, cols = 0;
            getmaxyx(stdscr, rows, cols);
            (void)rows;

            // Header panel
            werase(win_header_);
            wbkgd(win_header_, COLOR_PAIR(color::HEADER));
            wattron(win_header_, COLOR_PAIR(color::HEADER) | A_BOLD);

            const std::string title =
                "  Network Threat Engine  v" + std::string("2.0.0") +
                "  —  Real-Time NIDS Dashboard";
            mvwprintw(win_header_, 0, 0, "%s", title.c_str());
            mvwhline(win_header_, 1, 0, ACS_HLINE, cols);

            const std::string ts = ThreatAlert::make_iso8601_now();
            mvwprintw(win_header_, 2, 0, "  %s", ts.c_str());
            wattroff(win_header_, COLOR_PAIR(color::HEADER) | A_BOLD);
            wrefresh(win_header_);

            // Stats panel
            werase(win_stats_);

            EngineStats stats{};
            if (stats_fn_)
                stats = stats_fn_();

            wattron(win_stats_, COLOR_PAIR(color::HEADER) | A_BOLD);
            mvwprintw(win_stats_, 0, 2, "[ Engine Statistics ]");
            wattroff(win_stats_, COLOR_PAIR(color::HEADER) | A_BOLD);

            auto stat_line = [&](int row, int col,
                                 const char *label, const std::string &val,
                                 int pair)
            {
                wattron(win_stats_, COLOR_PAIR(color::NORMAL));
                mvwprintw(win_stats_, row, col, "%-22s", label);
                wattroff(win_stats_, COLOR_PAIR(color::NORMAL));
                wattron(win_stats_, COLOR_PAIR(pair) | A_BOLD);
                wprintw(win_stats_, "%s", val.c_str());
                wattroff(win_stats_, COLOR_PAIR(pair) | A_BOLD);
            };

            const int half = cols / 2;

            stat_line(1, 2, "Packets Captured:",
                      std::to_string(stats.packets_captured), color::STAT_VAL);
            stat_line(1, half, "Active Flows:",
                      std::to_string(stats.active_flows), color::STAT_VAL);

            stat_line(2, 2, "Capture Rate (pps):",
                      format_double(stats.capture_pps, 0), color::STAT_VAL);
            stat_line(2, half, "Queue Depth:",
                      std::to_string(stats.ring_queue_depth), color::STAT_VAL);

            stat_line(3, 2, "Ring Buffer Drops:",
                      std::to_string(stats.packets_dropped_ring), color::HIGH);
            stat_line(3, half, "Kernel Drops:",
                      std::to_string(stats.packets_dropped_kernel), color::HIGH);

            stat_line(4, 2, "Total Alerts:",
                      std::to_string(stats.total_alerts),
                      stats.total_alerts > 0 ? color::MEDIUM : color::STAT_VAL);
            stat_line(4, half, "Drop Rate:",
                      format_double(stats.drop_rate_pct, 4) + "%", color::STAT_VAL);

            mvwhline(win_stats_, 5, 0, ACS_HLINE, cols);
            wrefresh(win_stats_);

            // Alerts panel
            werase(win_alerts_);

            wattron(win_alerts_, COLOR_PAIR(color::HEADER) | A_BOLD);
            mvwprintw(win_alerts_, 0, 2, "[ Recent Alerts ]");
            wattroff(win_alerts_, COLOR_PAIR(color::HEADER) | A_BOLD);

            // Column header
            wattron(win_alerts_, COLOR_PAIR(color::NORMAL) | A_UNDERLINE);
            mvwprintw(win_alerts_, 1, 2,
                      "%-20s %-18s %-18s %-8s %-12s %s",
                      "TIMESTAMP", "SRC_IP", "DST_IP",
                      "DPORT", "TYPE", "SEVERITY");
            wattroff(win_alerts_, COLOR_PAIR(color::NORMAL) | A_UNDERLINE);

            // Copy display ring snapshot
            std::vector<ThreatAlert> ring_snapshot;
            {
                std::lock_guard<std::mutex> ring_lock(display_ring_mutex_);
                ring_snapshot.assign(display_ring_.begin(), display_ring_.end());
            }

            int win_rows = 0, win_cols = 0;
            getmaxyx(win_alerts_, win_rows, win_cols);
            (void)win_cols;

            const int max_rows = win_rows - 3;
            int row = 2;

            // Display most recent first
            for (auto it = ring_snapshot.rbegin();
                 it != ring_snapshot.rend() && row < max_rows + 2;
                 ++it, ++row)
            {
                const ThreatAlert &a = *it;

                const int pair = severity_to_color_pair(a.severity);
                wattron(win_alerts_, COLOR_PAIR(pair));

                // Truncate timestamp to HH:MM:SS for width
                std::string ts_short = a.timestamp_iso;
                if (ts_short.size() >= 19)
                    ts_short = ts_short.substr(11, 8);

                mvwprintw(win_alerts_, row, 2,
                          "%-20s %-18s %-18s %-8u %-12s %s",
                          ts_short.c_str(),
                          truncate(a.src_ip, 17).c_str(),
                          truncate(a.dst_ip, 17).c_str(),
                          static_cast<unsigned>(a.dst_port),
                          truncate(std::string(a.type_str()), 11).c_str(),
                          a.severity_str());

                wattroff(win_alerts_, COLOR_PAIR(pair));
            }

            wrefresh(win_alerts_);

            // Footer panel
            werase(win_footer_);
            wattron(win_footer_, COLOR_PAIR(color::NORMAL));
            mvwhline(win_footer_, 0, 0, ACS_HLINE, cols);
            mvwprintw(win_footer_, 1, 2,
                      "Press Ctrl-C to stop  |  "
                      "DB: %s  |  "
                      "Alerts persisted: %lu",
                      config_.db_path.c_str(),
                      total_persisted_.load(std::memory_order_relaxed));
            wattroff(win_footer_, COLOR_PAIR(color::NORMAL));
            wrefresh(win_footer_);

            // Commit all window updates to the physical screen in one shot
            doupdate();
        }

        // Utility helpers

        [[nodiscard]] static int
        severity_to_color_pair(Severity s) noexcept
        {
            switch (s)
            {
            case Severity::LOW:
                return color::LOW;
            case Severity::MEDIUM:
                return color::MEDIUM;
            case Severity::HIGH:
                return color::HIGH;
            case Severity::CRITICAL:
                return color::CRITICAL;
            }
            return color::NORMAL;
        }

        [[nodiscard]] static std::string
        format_double(double val, int precision)
        {
            std::ostringstream oss;
            oss << std::fixed << std::setprecision(precision) << val;
            return oss.str();
        }

        [[nodiscard]] static std::string
        truncate(const std::string &s, std::size_t max_len)
        {
            if (s.size() <= max_len)
                return s;
            return s.substr(0, max_len - 2) + "..";
        }
    };

    // Global instance and accessor
    static DeliveryLayer *g_delivery_layer = nullptr;

    DeliveryLayer *get_delivery_layer() noexcept { return g_delivery_layer; }
    void set_delivery_layer(DeliveryLayer *dl) noexcept { g_delivery_layer = dl; }

    void delivery_fire_alert(const ThreatAlert &alert)
    {
        if (g_delivery_layer != nullptr)
        {
            g_delivery_layer->enqueue_alert(alert);
        }
        else
        {
            // Fallback: print directly if DeliveryLayer not yet initialised
            std::cout
                << "[ALERT] " << alert.type_str()
                << " | " << alert.severity_str()
                << " | " << alert.src_ip << " -> " << alert.dst_ip
                << " | " << alert.evidence_summary << "\n";
            std::cout.flush();
        }
    }

} // namespace nte