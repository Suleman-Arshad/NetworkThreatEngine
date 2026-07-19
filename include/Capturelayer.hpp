#pragma once
#ifndef NTE_CAPTURE_LAYER_HPP
#define NTE_CAPTURE_LAYER_HPP

#include "Config.hpp"
#include "PacketRingBuffer.hpp"
#include <atomic>
#include <string>
#include <thread>
#include <pcap.h>

namespace nte
{
    struct CallbackContext
    {
        PacketRingBuffer *ring_buffer{nullptr};
        std::atomic<uint64_t> *captured_count{nullptr};
        std::atomic<uint64_t> *dropped_count{nullptr};
    };

    class CaptureLayer
    {
    public:
        explicit CaptureLayer(const Config &config, PacketRingBuffer &ring_buffer);
        ~CaptureLayer();
        CaptureLayer(const CaptureLayer &) = delete;
        CaptureLayer &operator=(const CaptureLayer &) = delete;
        CaptureLayer(CaptureLayer &&) = delete;
        CaptureLayer &operator=(CaptureLayer &&) = delete;

        void start();
        void stop() noexcept;

        [[nodiscard]] pcap_t *pcap_handle() const noexcept;
        [[nodiscard]] uint64_t captured_count() const noexcept;
        [[nodiscard]] uint64_t dropped_by_ring() const noexcept;
        [[nodiscard]] bool is_running() const noexcept;
        [[nodiscard]] const std::string &active_interface() const noexcept;

    private:
        CaptureConfig config_;
        PacketRingBuffer &ring_buffer_;
        pcap_t *pcap_handle_;
        std::string active_interface_;
        std::thread producer_thread_;
        std::atomic<uint64_t> captured_count_;
        std::atomic<uint64_t> dropped_by_ring_;
        std::atomic<bool> running_;

        void producer_loop();
        pcap_t *open_pcap_handle_for_interface(const std::string &iface);
    };

    CaptureLayer *get_capture_layer() noexcept;
    void set_capture_layer(CaptureLayer *layer) noexcept;
}
#endif