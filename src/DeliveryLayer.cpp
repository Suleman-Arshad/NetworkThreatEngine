#include "Deliverylayer.hpp"
#include <atomic>
#include <chrono>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <unistd.h>
#include <sqlite3.h>
#include <ncurses.h>

namespace nte
{
    namespace color { constexpr int NORMAL=1,HEADER=2,LOW=3,MEDIUM=4,HIGH=5,CRITICAL=6,STAT_VAL=7; }

    DeliveryLayer::DeliveryLayer(const Config& config, StatsProvider stats_fn)
        : config_(config.delivery), stats_fn_(std::move(stats_fn)),
          db_(nullptr), insert_stmt_(nullptr), running_(false), total_persisted_(0),
          ncurses_active_(false), win_header_(nullptr), win_stats_(nullptr),
          win_alerts_(nullptr), win_footer_(nullptr) {}

    DeliveryLayer::~DeliveryLayer() { stop(); }
    uint64_t DeliveryLayer::total_persisted() const noexcept { return total_persisted_.load(std::memory_order_relaxed); }

    void DeliveryLayer::init_database()
    {
        std::lock_guard<std::mutex> lk(db_mutex_);
        if (sqlite3_open(config_.db_path.c_str(), &db_) != SQLITE_OK)
            throw std::runtime_error("[DeliveryLayer] Cannot open DB: " + std::string(sqlite3_errmsg(db_)));
        sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
        sqlite3_exec(db_, "PRAGMA synchronous=NORMAL;", nullptr, nullptr, nullptr);
        const char* ddl =
            "CREATE TABLE IF NOT EXISTS alerts("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "timestamp TEXT NOT NULL, threat_type TEXT NOT NULL,"
            "src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL,"
            "src_port INTEGER NOT NULL, dst_port INTEGER NOT NULL,"
            "severity TEXT NOT NULL, description TEXT NOT NULL,"
            "observed REAL DEFAULT 0, baseline REAL DEFAULT 0, threshold REAL DEFAULT 0);";
        char* err = nullptr;
        if (sqlite3_exec(db_, ddl, nullptr, nullptr, &err) != SQLITE_OK)
        { std::string e=err; sqlite3_free(err); throw std::runtime_error("[DeliveryLayer] DDL failed: "+e); }
        sqlite3_exec(db_, "CREATE INDEX IF NOT EXISTS idx_src ON alerts(src_ip);", nullptr, nullptr, nullptr);
        sqlite3_exec(db_, "CREATE INDEX IF NOT EXISTS idx_ts  ON alerts(timestamp);", nullptr, nullptr, nullptr);
        const char* ins = "INSERT INTO alerts(timestamp,threat_type,src_ip,dst_ip,src_port,dst_port,severity,description,observed,baseline,threshold) VALUES(?,?,?,?,?,?,?,?,?,?,?);";
        if (sqlite3_prepare_v2(db_, ins, -1, &insert_stmt_, nullptr) != SQLITE_OK)
            throw std::runtime_error("[DeliveryLayer] prepare failed: " + std::string(sqlite3_errmsg(db_)));
    }

    void DeliveryLayer::close_database() noexcept
    {
        std::lock_guard<std::mutex> lk(db_mutex_);
        if (insert_stmt_) { sqlite3_finalize(insert_stmt_); insert_stmt_ = nullptr; }
        if (db_)          { sqlite3_close(db_); db_ = nullptr; }
    }

    void DeliveryLayer::persist_alert(const ThreatAlert& a)
    {
        std::lock_guard<std::mutex> lk(db_mutex_);
        if (!db_ || !insert_stmt_) return;
        sqlite3_reset(insert_stmt_); sqlite3_clear_bindings(insert_stmt_);
        sqlite3_bind_text(insert_stmt_,1,a.timestamp_iso.c_str(),-1,SQLITE_TRANSIENT);
        sqlite3_bind_text(insert_stmt_,2,a.type_str(),-1,SQLITE_STATIC);
        sqlite3_bind_text(insert_stmt_,3,a.src_ip.c_str(),-1,SQLITE_TRANSIENT);
        sqlite3_bind_text(insert_stmt_,4,a.dst_ip.c_str(),-1,SQLITE_TRANSIENT);
        sqlite3_bind_int (insert_stmt_,5,static_cast<int>(a.src_port));
        sqlite3_bind_int (insert_stmt_,6,static_cast<int>(a.dst_port));
        sqlite3_bind_text(insert_stmt_,7,a.severity_str(),-1,SQLITE_STATIC);
        sqlite3_bind_text(insert_stmt_,8,a.evidence_summary.c_str(),-1,SQLITE_TRANSIENT);
        sqlite3_bind_double(insert_stmt_,9, a.observed_value);
        sqlite3_bind_double(insert_stmt_,10,a.baseline_value);
        sqlite3_bind_double(insert_stmt_,11,a.threshold_value);
        if (sqlite3_step(insert_stmt_) == SQLITE_DONE) total_persisted_.fetch_add(1, std::memory_order_relaxed);
        else std::cerr << "[DeliveryLayer] INSERT failed: " << sqlite3_errmsg(db_) << "\n";
    }

    void DeliveryLayer::print_alert_to_stdout(const ThreatAlert& a) const
    {
        std::cout << "\n╔══════════════════════════════════════════════╗\n"
                  << "║ ALERT: " << std::left << std::setw(38) << a.type_str()    << "║\n"
                  << "║ Sev:   " << std::setw(38) << a.severity_str()             << "║\n"
                  << "║ Time:  " << std::setw(38) << a.timestamp_iso              << "║\n"
                  << "║ Src:   " << std::setw(38) << (a.src_ip+":"+std::to_string(a.src_port)) << "║\n"
                  << "║ Dst:   " << std::setw(38) << (a.dst_ip+":"+std::to_string(a.dst_port)) << "║\n"
                  << "║ Info:  " << std::setw(38) << a.evidence_summary.substr(0, 37) << "║\n"
                  << "╚══════════════════════════════════════════════╝\n";
        std::cout.flush();
    }

    void DeliveryLayer::writer_loop()
    {
        while (running_.load(std::memory_order_acquire))
        {
            ThreatAlert alert; bool has = false;
            { std::unique_lock<std::mutex> lk(queue_mutex_);
              queue_cv_.wait(lk, [this]{ return !alert_queue_.empty() || !running_.load(std::memory_order_acquire); });
              if (!alert_queue_.empty()) { alert = alert_queue_.front(); alert_queue_.pop(); has = true; } }
            if (!has) continue;
            persist_alert(alert);
            if (!ncurses_active_) print_alert_to_stdout(alert);
            { std::lock_guard<std::mutex> rl(display_ring_mutex_);
              display_ring_.push_back(alert);
              while (display_ring_.size() > DISPLAY_RING_SIZE) display_ring_.pop_front(); }
        }
        std::unique_lock<std::mutex> lk(queue_mutex_);
        while (!alert_queue_.empty()) { persist_alert(alert_queue_.front()); alert_queue_.pop(); }
    }

    void DeliveryLayer::init_ncurses()
    {
        if (!isatty(STDOUT_FILENO)) { ncurses_active_ = false; return; }
        initscr(); cbreak(); noecho(); curs_set(0); keypad(stdscr,TRUE); nodelay(stdscr,TRUE);
        if (has_colors())
        {
            start_color();
            init_pair(color::NORMAL,   COLOR_WHITE,   COLOR_BLACK);
            init_pair(color::HEADER,   COLOR_CYAN,    COLOR_BLACK);
            init_pair(color::LOW,      COLOR_GREEN,   COLOR_BLACK);
            init_pair(color::MEDIUM,   COLOR_YELLOW,  COLOR_BLACK);
            init_pair(color::HIGH,     COLOR_RED,     COLOR_BLACK);
            init_pair(color::CRITICAL, COLOR_MAGENTA, COLOR_BLACK);
            init_pair(color::STAT_VAL, COLOR_WHITE,   COLOR_BLACK);
        }
        int rows=0, cols=0; getmaxyx(stdscr, rows, cols);
        const int hr=3, sr=6, fr=2, ar=std::max(rows-hr-sr-fr,4);
        win_header_ = newwin(hr, cols, 0,        0);
        win_stats_  = newwin(sr, cols, hr,       0);
        win_alerts_ = newwin(ar, cols, hr+sr,    0);
        win_footer_ = newwin(fr, cols, rows-fr,  0);
        scrollok(win_alerts_, TRUE);
        ncurses_active_ = true;
    }

    void DeliveryLayer::teardown_ncurses() noexcept
    {
        if (!ncurses_active_) return;
        std::lock_guard<std::mutex> lk(ncurses_mutex_);
        if (win_header_) { delwin(win_header_); win_header_=nullptr; }
        if (win_stats_)  { delwin(win_stats_);  win_stats_=nullptr;  }
        if (win_alerts_) { delwin(win_alerts_); win_alerts_=nullptr; }
        if (win_footer_) { delwin(win_footer_); win_footer_=nullptr; }
        endwin(); ncurses_active_ = false;
    }

    int DeliveryLayer::severity_to_color_pair(Severity s) noexcept
    {
        switch(s) { case Severity::LOW:return color::LOW; case Severity::MEDIUM:return color::MEDIUM;
                    case Severity::HIGH:return color::HIGH; case Severity::CRITICAL:return color::CRITICAL; }
        return color::NORMAL;
    }

    std::string DeliveryLayer::format_double(double v, int p)
    { std::ostringstream o; o<<std::fixed<<std::setprecision(p)<<v; return o.str(); }

    std::string DeliveryLayer::truncate(const std::string& s, std::size_t n)
    { return s.size()<=n ? s : s.substr(0,n-2)+".."; }

    void DeliveryLayer::print_stats_to_stdout() const
    {
        if (!stats_fn_) return;
        auto s = stats_fn_();
        std::cout << "[STATS] cap=" << s.packets_captured << " pps=" << std::fixed
                  << std::setprecision(0) << s.capture_pps << " flows=" << s.active_flows
                  << " alerts=" << s.total_alerts << " drop=" << std::setprecision(3)
                  << s.drop_rate_pct << "%\n";
        std::cout.flush();
    }

    void DeliveryLayer::redraw_dashboard()
    {
        std::lock_guard<std::mutex> lk(ncurses_mutex_);
        if (!ncurses_active_) return;
        int rows=0, cols=0; getmaxyx(stdscr, rows, cols); (void)rows;

        werase(win_header_); wbkgd(win_header_, COLOR_PAIR(color::HEADER));
        wattron(win_header_, COLOR_PAIR(color::HEADER)|A_BOLD);
        mvwprintw(win_header_, 0, 0, "  Network Threat Engine v2.0.0 — NIDS Dashboard");
        mvwhline(win_header_, 1, 0, ACS_HLINE, cols);
        mvwprintw(win_header_, 2, 0, "  %s", ThreatAlert::make_iso8601_now().c_str());
        wattroff(win_header_, COLOR_PAIR(color::HEADER)|A_BOLD); wrefresh(win_header_);

        werase(win_stats_);
        EngineStats st{}; if (stats_fn_) st = stats_fn_();
        wattron(win_stats_, COLOR_PAIR(color::HEADER)|A_BOLD);
        mvwprintw(win_stats_, 0, 2, "[ Engine Statistics ]");
        wattroff(win_stats_, COLOR_PAIR(color::HEADER)|A_BOLD);
        const int h = cols/2;
        auto sl = [&](int r, int c, const char* lbl, const std::string& val, int pair)
        { wattron(win_stats_,COLOR_PAIR(color::NORMAL)); mvwprintw(win_stats_,r,c,"%-22s",lbl); wattroff(win_stats_,COLOR_PAIR(color::NORMAL));
          wattron(win_stats_,COLOR_PAIR(pair)|A_BOLD); wprintw(win_stats_,"%s",val.c_str()); wattroff(win_stats_,COLOR_PAIR(pair)|A_BOLD); };
        sl(1,2,"Packets Captured:",std::to_string(st.packets_captured),color::STAT_VAL);
        sl(1,h,"Active Flows:",std::to_string(st.active_flows),color::STAT_VAL);
        sl(2,2,"Capture PPS:",format_double(st.capture_pps,0),color::STAT_VAL);
        sl(2,h,"Queue Depth:",std::to_string(st.ring_queue_depth),color::STAT_VAL);
        sl(3,2,"Ring Drops:",std::to_string(st.packets_dropped_ring),color::HIGH);
        sl(4,2,"Total Alerts:",std::to_string(st.total_alerts),st.total_alerts>0?color::MEDIUM:color::STAT_VAL);
        sl(4,h,"Drop Rate:",format_double(st.drop_rate_pct,4)+"%",color::STAT_VAL);
        mvwhline(win_stats_, 5, 0, ACS_HLINE, cols); wrefresh(win_stats_);

        werase(win_alerts_);
        wattron(win_alerts_, COLOR_PAIR(color::HEADER)|A_BOLD);
        mvwprintw(win_alerts_, 0, 2, "[ Recent Alerts ]");
        wattroff(win_alerts_, COLOR_PAIR(color::HEADER)|A_BOLD);
        wattron(win_alerts_, COLOR_PAIR(color::NORMAL)|A_UNDERLINE);
        mvwprintw(win_alerts_, 1, 2, "%-20s %-18s %-18s %-8s %-14s %s",
                  "TIMESTAMP","SRC_IP","DST_IP","DPORT","TYPE","SEVERITY");
        wattroff(win_alerts_, COLOR_PAIR(color::NORMAL)|A_UNDERLINE);

        std::vector<ThreatAlert> ring;
        { std::lock_guard<std::mutex> rl(display_ring_mutex_); ring.assign(display_ring_.begin(), display_ring_.end()); }
        int wr=0,wc=0; getmaxyx(win_alerts_,wr,wc); (void)wc;
        int row=2;
        for (auto it=ring.rbegin(); it!=ring.rend() && row<wr-1; ++it,++row)
        {
            const auto& a=*it;
            std::string ts=a.timestamp_iso; if (ts.size()>=19) ts=ts.substr(11,8);
            wattron(win_alerts_, COLOR_PAIR(severity_to_color_pair(a.severity)));
            mvwprintw(win_alerts_, row, 2, "%-20s %-18s %-18s %-8u %-14s %s",
                      ts.c_str(), truncate(a.src_ip,17).c_str(), truncate(a.dst_ip,17).c_str(),
                      (unsigned)a.dst_port, truncate(a.type_str(),13).c_str(), a.severity_str());
            wattroff(win_alerts_, COLOR_PAIR(severity_to_color_pair(a.severity)));
        }
        wrefresh(win_alerts_);

        werase(win_footer_);
        mvwhline(win_footer_, 0, 0, ACS_HLINE, cols);
        mvwprintw(win_footer_, 1, 2, "Ctrl-C to stop | DB: %s | Persisted: %lu",
                  config_.db_path.c_str(), total_persisted_.load(std::memory_order_relaxed));
        wrefresh(win_footer_); doupdate();
    }

    void DeliveryLayer::dashboard_loop()
    {
        if (!ncurses_active_)
        {
            while (running_.load(std::memory_order_acquire))
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(config_.dashboard_refresh_ms * 10));
                if (!running_.load(std::memory_order_acquire)) break;
                print_stats_to_stdout();
            }
            return;
        }
        while (running_.load(std::memory_order_acquire))
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(config_.dashboard_refresh_ms));
            if (!running_.load(std::memory_order_acquire)) break;
            redraw_dashboard();
        }
    }

    void DeliveryLayer::start()
    {
        if (running_.load(std::memory_order_acquire)) return;
        init_database();
        init_ncurses();
        running_.store(true, std::memory_order_release);
        writer_thread_    = std::thread([this]{ writer_loop();    });
        dashboard_thread_ = std::thread([this]{ dashboard_loop(); });
        std::cout << "[DeliveryLayer] Started. DB: " << config_.db_path << "\n";
    }

    void DeliveryLayer::stop() noexcept
    {
        if (!running_.load(std::memory_order_acquire)) return;
        running_.store(false, std::memory_order_release);
        queue_cv_.notify_all();
        if (writer_thread_.joinable())    writer_thread_.join();
        if (dashboard_thread_.joinable()) dashboard_thread_.join();
        teardown_ncurses();
        close_database();
        std::cout << "[DeliveryLayer] Stopped. Persisted: " << total_persisted_.load() << "\n";
    }

    void DeliveryLayer::enqueue_alert(const ThreatAlert& alert)
    {
        { std::lock_guard<std::mutex> lk(queue_mutex_); alert_queue_.push(alert); }
        queue_cv_.notify_one();
    }

    static DeliveryLayer* g_delivery_layer = nullptr;
    DeliveryLayer* get_delivery_layer() noexcept { return g_delivery_layer; }
    void set_delivery_layer(DeliveryLayer* dl) noexcept { g_delivery_layer = dl; }

    void delivery_fire_alert(const ThreatAlert& alert)
    {
        if (g_delivery_layer) g_delivery_layer->enqueue_alert(alert);
        else std::cout << "[ALERT] " << alert.type_str() << " | " << alert.src_ip << "\n";
    }
}