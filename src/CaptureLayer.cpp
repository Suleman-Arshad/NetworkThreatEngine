#include "Config.hpp"
#include "PacketInfo.hpp"
#include "PacketRingBuffer.hpp"
#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <pcap.h>
#include <unistd.h>

namespace nte
{
    // Forward declarations of file-scope helpers
    static void packet_callback(u_char *user,
                                const struct pcap_pkthdr *pkthdr,
                                const u_char *packet);
    static std::string discover_interface();
    static pcap_t *open_pcap_handle(const CaptureConfig &cfg);

    // CallbackContext - passed as the user pointer through pcap_loop
    struct CallbackContext
    {
        PacketRingBuffer *ring_buffer{nullptr};
        std::atomic<uint64_t> *captured_count{nullptr};
        std::atomic<uint64_t> *dropped_count{nullptr};
    };

    // CaptureLayer
    class CaptureLayer
    {
    public:
        // Construction / Destruction

        explicit CaptureLayer(const Config &config,
                              PacketRingBuffer &ring_buffer)
            : config_(config.capture), ring_buffer_(ring_buffer), pcap_handle_(nullptr), captured_count_(0), dropped_by_ring_(0), running_(false)
        {
        }

        ~CaptureLayer()
        {
            stop();
        }

        CaptureLayer(const CaptureLayer &) = delete;
        CaptureLayer &operator=(const CaptureLayer &) = delete;
        CaptureLayer(CaptureLayer &&) = delete;
        CaptureLayer &operator=(CaptureLayer &&) = delete;

        // Lifecycle
        void start()
        {
            if (running_.load(std::memory_order_acquire))
            {
                return; // Already running
            }

            // Resolve interface name
            const std::string iface = config_.interface.empty()
                                          ? discover_interface()
                                          : config_.interface;

            std::cout << "[CaptureLayer] Opening interface: " << iface << "\n";
            std::cout << "[CaptureLayer] Snaplen          : "
                      << config_.snaplen << " bytes\n";
            std::cout << "[CaptureLayer] Kernel buffer    : "
                      << (config_.kernel_buffer_bytes / (1024 * 1024)) << " MB\n";
            std::cout << "[CaptureLayer] Promiscuous mode : "
                      << (config_.promiscuous ? "ON" : "OFF") << "\n";
            std::cout.flush();

            // Store interface name for the thread lambda
            active_interface_ = iface;

            // Open the pcap handle (create -> configure -> activate)
            pcap_handle_ = open_pcap_handle_for_interface(iface);

            // Print datalink type
            const int dl = pcap_datalink(pcap_handle_);
            std::cout << "[CaptureLayer] Datalink type    : "
                      << dl
                      << " (" << pcap_datalink_val_to_name(dl)
                      << " - " << pcap_datalink_val_to_description(dl) << ")\n";
            std::cout.flush();

            running_.store(true, std::memory_order_release);

            // Launch Producer thread
            producer_thread_ = std::thread([this]()
                                           { producer_loop(); });
        }

        // Signal the capture loop to stop and join the Producer thread.
        void stop() noexcept
        {
            if (!running_.load(std::memory_order_acquire))
            {
                return;
            }

            running_.store(false, std::memory_order_release);

            // pcap_breakloop() is the only safe way to interrupt pcap_loop() from outside the callback.  It sets an internal flag that causes pcap_loop() to return PCAP_ERROR_BREAK after the current callback (if any) returns.
            if (pcap_handle_ != nullptr)
            {
                pcap_breakloop(pcap_handle_);
            }

            if (producer_thread_.joinable())
            {
                producer_thread_.join();
            }

            if (pcap_handle_ != nullptr)
            {
                // Print final kernel-level drop statistics before closing
                struct pcap_stat ps{};
                if (pcap_stats(pcap_handle_, &ps) == 0)
                {
                    std::cout
                        << "\n[CaptureLayer] Kernel stats:\n"
                        << "  Packets received : " << ps.ps_recv << "\n"
                        << "  Kernel drops     : " << ps.ps_drop << "\n"
                        << "  Interface drops  : " << ps.ps_ifdrop << "\n";
                }

                pcap_close(pcap_handle_);
                pcap_handle_ = nullptr;
            }
        }

        // Diagnostics

        [[nodiscard]] uint64_t captured_count() const noexcept
        {
            return captured_count_.load(std::memory_order_relaxed);
        }

        [[nodiscard]] uint64_t dropped_by_ring() const noexcept
        {
            return dropped_by_ring_.load(std::memory_order_relaxed);
        }

        [[nodiscard]] bool is_running() const noexcept
        {
            return running_.load(std::memory_order_acquire);
        }

        [[nodiscard]] const std::string &active_interface() const noexcept
        {
            return active_interface_;
        }

        // Expose pcap handle for signal handler access (to call pcap_breakloop)
        [[nodiscard]] pcap_t *pcap_handle() const noexcept
        {
            return pcap_handle_;
        }

    private:
        // Private state

        CaptureConfig config_;
        PacketRingBuffer &ring_buffer_;
        pcap_t *pcap_handle_;
        std::string active_interface_;
        std::thread producer_thread_;

        std::atomic<uint64_t> captured_count_;
        std::atomic<uint64_t> dropped_by_ring_;
        std::atomic<bool> running_;

        // Producer thread body

        void producer_loop()
        {
            // Build the callback context on the stack - valid for the lifetime of this function, which outlives pcap_loop().
            CallbackContext ctx;
            ctx.ring_buffer = &ring_buffer_;
            ctx.captured_count = &captured_count_;
            ctx.dropped_count = &dropped_by_ring_;

            std::cout << "[CaptureLayer] Producer thread started. "
                         "Capturing on "
                      << active_interface_ << "...\n";
            std::cout.flush();

            // pcap_loop() blocks here, calling packet_callback() for each frame, until pcap_breakloop() is called or an error occurs.
            const int rc = pcap_loop(
                pcap_handle_,
                -1, // capture indefinitely
                packet_callback,
                reinterpret_cast<u_char *>(&ctx));

            if (rc == PCAP_ERROR_BREAK)
            {
                std::cout << "[CaptureLayer] pcap_loop exited cleanly "
                             "(breakloop signal).\n";
            }
            else if (rc == PCAP_ERROR)
            {
                std::cerr << "[CaptureLayer] pcap_loop error: "
                          << pcap_geterr(pcap_handle_) << "\n";
            }

            std::cout << "[CaptureLayer] Producer thread exiting. "
                      << "Total captured: "
                      << captured_count_.load(std::memory_order_relaxed) << "\n";
            std::cout.flush();

            running_.store(false, std::memory_order_release);
        }

        // pcap handle factory

        pcap_t *open_pcap_handle_for_interface(const std::string &iface)
        {
            char errbuf[PCAP_ERRBUF_SIZE];

            // Step 1: Create (does not open the raw socket yet)
            pcap_t *handle = pcap_create(iface.c_str(), errbuf);
            if (handle == nullptr)
            {
                throw std::runtime_error(
                    "[CaptureLayer] pcap_create failed: " + std::string(errbuf));
            }

            // Step 2: Configure before activation
            if (pcap_set_snaplen(handle, config_.snaplen) != 0)
            {
                const std::string err = pcap_geterr(handle);
                pcap_close(handle);
                throw std::runtime_error(
                    "[CaptureLayer] pcap_set_snaplen failed: " + err);
            }

            if (pcap_set_promisc(handle, config_.promiscuous) != 0)
            {
                const std::string err = pcap_geterr(handle);
                pcap_close(handle);
                throw std::runtime_error(
                    "[CaptureLayer] pcap_set_promisc failed: " + err);
            }

            if (pcap_set_buffer_size(handle, config_.kernel_buffer_bytes) != 0)
            {
                // Non-fatal: kernel may cap the buffer silently
                std::cerr << "[CaptureLayer] Warning: pcap_set_buffer_size "
                             "returned non-zero — kernel may have capped it.\n";
            }

            if (pcap_set_timeout(handle, config_.read_timeout_ms) != 0)
            {
                const std::string err = pcap_geterr(handle);
                pcap_close(handle);
                throw std::runtime_error(
                    "[CaptureLayer] pcap_set_timeout failed: " + err);
            }

            // Step 3: Activate (opens the raw socket, applies all settings)
            const int rc = pcap_activate(handle);

            if (rc < 0)
            {
                const std::string err = pcap_geterr(handle);
                pcap_close(handle);

                std::string msg = "[CaptureLayer] pcap_activate failed (rc=" + std::to_string(rc) + "): " + pcap_statustostr(rc) + " - " + err;

                if (rc == PCAP_ERROR_PERM_DENIED)
                {
                    msg += "\n  Run as root or: sudo setcap cap_net_raw+ep ./packet_analyzer";
                }

                throw std::runtime_error(msg);
            }

            if (rc > 0)
            {
                std::cerr << "[CaptureLayer] pcap_activate warning: "
                          << pcap_statustostr(rc) << "\n";
            }

            return handle;
        }
    };

    // packet_callback  (Producer hot path - called by libpcap for every frame)
    static void packet_callback(u_char *user,
                                const struct pcap_pkthdr *pkthdr,
                                const u_char *packet)
    {
        auto *ctx = reinterpret_cast<CallbackContext *>(user);

        // Merge pcap timeval into 64-bit microsecond epoch value
        const int64_t ts_us =
            static_cast<int64_t>(pkthdr->ts.tv_sec) * 1'000'000LL +
            static_cast<int64_t>(pkthdr->ts.tv_usec);

        // Construct packet: this performs the single necessary memcpy
        CapturedPacket pkt(
            reinterpret_cast<const uint8_t *>(packet),
            pkthdr->caplen,
            pkthdr->len,
            ts_us);

        ctx->captured_count->fetch_add(1, std::memory_order_relaxed);

        // Move into ring buffer - no copy of the vector occurs here
        if (!ctx->ring_buffer->push(std::move(pkt)))
        {
            ctx->dropped_count->fetch_add(1, std::memory_order_relaxed);
        }
    }

    // discover_interface
    static std::string discover_interface()
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t *alldevs = nullptr;

        if (pcap_findalldevs(&alldevs, errbuf) != 0)
        {
            throw std::runtime_error(
                "[CaptureLayer] pcap_findalldevs failed: " + std::string(errbuf));
        }

        if (alldevs == nullptr)
        {
            throw std::runtime_error(
                "[CaptureLayer] No network interfaces found. "
                "Run as root or check interface availability.");
        }

        std::string selected;
        std::string first_available;

        std::cout << "[CaptureLayer] Available interfaces:\n";

        for (const pcap_if_t *dev = alldevs; dev != nullptr; dev = dev->next)
        {
            const bool is_up = (dev->flags & PCAP_IF_UP) != 0;
            const bool is_running = (dev->flags & PCAP_IF_RUNNING) != 0;
            const bool is_loopback = (dev->flags & PCAP_IF_LOOPBACK) != 0;

            std::cout << "  " << dev->name
                      << (is_up ? " [UP]" : " [DOWN]")
                      << (is_running ? " [RUNNING]" : "")
                      << (is_loopback ? " [LOOPBACK]" : "")
                      << (dev->description
                              ? std::string("  - ") + dev->description
                              : "")
                      << "\n";

            if (first_available.empty())
            {
                first_available = dev->name;
            }

            if (selected.empty() && is_up && is_running && !is_loopback)
            {
                selected = dev->name;
            }
        }

        pcap_freealldevs(alldevs);

        if (selected.empty())
        {
            selected = first_available;
            std::cerr << "[CaptureLayer] No ideal interface found; "
                         "falling back to: "
                      << selected << "\n";
        }
        else
        {
            std::cout << "[CaptureLayer] Auto-selected: " << selected << "\n";
        }

        return selected;
    }

    static CaptureLayer *g_capture_layer = nullptr;

    CaptureLayer *get_capture_layer() noexcept
    {
        return g_capture_layer;
    }

    void set_capture_layer(CaptureLayer *layer) noexcept
    {
        g_capture_layer = layer;
    }

} // namespace nte