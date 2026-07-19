#include "Capturelayer.hpp"
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <unistd.h>

namespace nte
{
    static void packet_callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet)
    {
        auto *ctx = reinterpret_cast<CallbackContext *>(user);
        const int64_t ts_us = static_cast<int64_t>(pkthdr->ts.tv_sec) * 1'000'000LL + static_cast<int64_t>(pkthdr->ts.tv_usec);
        CapturedPacket pkt(reinterpret_cast<const uint8_t *>(packet), pkthdr->caplen, pkthdr->len, ts_us);
        ctx->captured_count->fetch_add(1, std::memory_order_relaxed);
        if (!ctx->ring_buffer->push(std::move(pkt)))
            ctx->dropped_count->fetch_add(1, std::memory_order_relaxed);
    }

    static std::string discover_interface()
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t *alldevs = nullptr;
        if (pcap_findalldevs(&alldevs, errbuf) != 0)
            throw std::runtime_error("[CaptureLayer] pcap_findalldevs failed: " + std::string(errbuf));
        if (alldevs == nullptr)
            throw std::runtime_error("[CaptureLayer] No network interfaces found.");
        std::string selected, first_available;
        std::cout << "[CaptureLayer] Available interfaces:\n";
        for (const pcap_if_t *dev = alldevs; dev != nullptr; dev = dev->next)
        {
            const bool is_up = (dev->flags & PCAP_IF_UP) != 0;
            const bool is_running = (dev->flags & PCAP_IF_RUNNING) != 0;
            const bool is_loopback = (dev->flags & PCAP_IF_LOOPBACK) != 0;
            std::cout << "  " << dev->name
                      << (is_up ? " [UP]" : " [DOWN]")
                      << (is_running ? " [RUNNING]" : "")
                      << (is_loopback ? " [LOOPBACK]" : "") << "\n";
            if (first_available.empty())
                first_available = dev->name;
            if (selected.empty() && is_up && is_running && !is_loopback)
                selected = dev->name;
        }
        pcap_freealldevs(alldevs);
        if (selected.empty())
        {
            selected = first_available;
        }
        std::cout << "[CaptureLayer] Auto-selected: " << selected << "\n";
        return selected;
    }

    CaptureLayer::CaptureLayer(const Config &config, PacketRingBuffer &ring_buffer)
        : config_(config.capture), ring_buffer_(ring_buffer), pcap_handle_(nullptr),
          captured_count_(0), dropped_by_ring_(0), running_(false) {}

    CaptureLayer::~CaptureLayer() { stop(); }

    pcap_t *CaptureLayer::pcap_handle() const noexcept { return pcap_handle_; }
    uint64_t CaptureLayer::captured_count() const noexcept { return captured_count_.load(std::memory_order_relaxed); }
    uint64_t CaptureLayer::dropped_by_ring() const noexcept { return dropped_by_ring_.load(std::memory_order_relaxed); }
    bool CaptureLayer::is_running() const noexcept { return running_.load(std::memory_order_acquire); }
    const std::string &CaptureLayer::active_interface() const noexcept { return active_interface_; }

    pcap_t *CaptureLayer::open_pcap_handle_for_interface(const std::string &iface)
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle = pcap_create(iface.c_str(), errbuf);
        if (!handle)
            throw std::runtime_error("[CaptureLayer] pcap_create failed: " + std::string(errbuf));
        pcap_set_snaplen(handle, config_.snaplen);
        pcap_set_promisc(handle, config_.promiscuous);
        pcap_set_buffer_size(handle, config_.kernel_buffer_bytes);
        pcap_set_timeout(handle, config_.read_timeout_ms);
        const int rc = pcap_activate(handle);
        if (rc < 0)
        {
            std::string err = pcap_geterr(handle);
            pcap_close(handle);
            throw std::runtime_error("[CaptureLayer] pcap_activate failed: " + err);
        }
        if (rc > 0)
            std::cerr << "[CaptureLayer] pcap_activate warning: " << pcap_statustostr(rc) << "\n";
        return handle;
    }

    void CaptureLayer::producer_loop()
    {
        CallbackContext ctx;
        ctx.ring_buffer = &ring_buffer_;
        ctx.captured_count = &captured_count_;
        ctx.dropped_count = &dropped_by_ring_;
        std::cout << "[CaptureLayer] Producer thread started on " << active_interface_ << "\n";
        std::cout.flush();
        const int rc = pcap_loop(pcap_handle_, -1, packet_callback, reinterpret_cast<u_char *>(&ctx));
        if (rc == PCAP_ERROR_BREAK)
            std::cout << "[CaptureLayer] pcap_loop exited cleanly.\n";
        else if (rc == PCAP_ERROR)
            std::cerr << "[CaptureLayer] pcap_loop error: " << pcap_geterr(pcap_handle_) << "\n";
        std::cout << "[CaptureLayer] Producer exiting. Captured: " << captured_count_.load() << "\n";
        std::cout.flush();
        running_.store(false, std::memory_order_release);
    }

    void CaptureLayer::start()
    {
        if (running_.load(std::memory_order_acquire))
            return;
        active_interface_ = config_.interface.empty() ? discover_interface() : config_.interface;
        std::cout << "[CaptureLayer] Opening: " << active_interface_ << " snaplen=" << config_.snaplen << "\n";
        pcap_handle_ = open_pcap_handle_for_interface(active_interface_);
        const int dl = pcap_datalink(pcap_handle_);
        std::cout << "[CaptureLayer] Datalink: " << dl << " (" << pcap_datalink_val_to_name(dl) << ")\n";
        running_.store(true, std::memory_order_release);
        producer_thread_ = std::thread([this]()
                                       { producer_loop(); });
    }

    void CaptureLayer::stop() noexcept
    {
        if (!running_.load(std::memory_order_acquire))
            return;
        running_.store(false, std::memory_order_release);
        if (pcap_handle_)
            pcap_breakloop(pcap_handle_);
        if (producer_thread_.joinable())
            producer_thread_.join();
        if (pcap_handle_)
        {
            struct pcap_stat ps{};
            if (pcap_stats(pcap_handle_, &ps) == 0)
                std::cout << "[CaptureLayer] Kernel: recv=" << ps.ps_recv << " drop=" << ps.ps_drop << "\n";
            pcap_close(pcap_handle_);
            pcap_handle_ = nullptr;
        }
    }

    static CaptureLayer *g_capture_layer = nullptr;
    CaptureLayer *get_capture_layer() noexcept { return g_capture_layer; }
    void set_capture_layer(CaptureLayer *layer) noexcept { g_capture_layer = layer; }
}