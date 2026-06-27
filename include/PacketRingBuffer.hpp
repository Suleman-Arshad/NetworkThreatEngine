#pragma once
#ifndef PACKET_RING_BUFFER_HPP
#define PACKET_RING_BUFFER_HPP
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <queue>
#include <vector>

struct CapturedPacket
{
    // Sized exactly to the captured length (no trailing zero padding).
    std::vector<uint8_t> data;
    // Number of bytes actually captured (may be ≤ original_length when the kernel truncates frames to snaplen).
    uint32_t captured_length{0};
    // Original wire length of the frame before any kernel-level truncation.
    uint32_t original_length{0};
    /*Kernel-assigned capture timestamp.  The pcap_pkthdr supplies tv_sec and tv_usec; we merge them into a single 64-bit microsecond epoch value here to make Consumer logging arithmetic straightforward.*/
    int64_t timestamp{0};
    // Constructors
    CapturedPacket() = default;
    CapturedPacket(const uint8_t *raw_data,
                   uint32_t cap_len,
                   uint32_t orig_len,
                   int64_t ts_us)
        : data(raw_data, raw_data + cap_len), captured_length(cap_len), original_length(orig_len), timestamp(ts_us)
    {
    }
    // Move semantics transfer ownership of the heap-allocated data vector without copying.
    CapturedPacket(CapturedPacket &&) noexcept = default;
    CapturedPacket &operator=(CapturedPacket &&) noexcept = default;
    // Disable copies to enforce move-only semantics across the pipeline.
    CapturedPacket(const CapturedPacket &) = delete;
    CapturedPacket &operator=(const CapturedPacket &) = delete;
};

class PacketRingBuffer
{
private:
    std::queue<CapturedPacket> queue_;
    mutable std::mutex mutex_;
    std::condition_variable cv_not_empty_;
    std::atomic<bool> shutdown_flag_{false};
    std::atomic<uint64_t> pushed_count_{0};
    std::atomic<uint64_t> popped_count_{0};
    std::atomic<uint64_t> dropped_count_{0};

public:
    static constexpr std::size_t MAX_CAPACITY = 10'000;
    // Lifecycle
    PacketRingBuffer() = default;
    ~PacketRingBuffer() = default;
    // Non-copyable, non-movable: the global instance is shared by pointer and must not be relocated after threads have taken references to it.
    PacketRingBuffer(const PacketRingBuffer &) = delete;
    PacketRingBuffer &operator=(const PacketRingBuffer &) = delete;
    PacketRingBuffer(PacketRingBuffer &&) = delete;
    PacketRingBuffer &operator=(PacketRingBuffer &&) = delete;
    // Producer interface
    bool push(CapturedPacket &&packet) noexcept
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);

            if (queue_.size() >= MAX_CAPACITY)
            {
                ++dropped_count_;
                return false;
            }

            queue_.push(std::move(packet));
            ++pushed_count_;
        }
        cv_not_empty_.notify_one();
        return true;
    }
    // Consumer interface
    bool pop(CapturedPacket &out)
    {
        std::unique_lock<std::mutex> lock(mutex_);

        cv_not_empty_.wait(lock, [this]()
                           { return !queue_.empty() || shutdown_flag_.load(std::memory_order_acquire); });

        // If we were woken by shutdown() and the queue is now empty, signal the Consumer to terminate.
        if (queue_.empty())
        {
            return false;
        }

        out = std::move(queue_.front());
        queue_.pop();
        ++popped_count_;
        return true;
    }
    // Lifecycle control
    void shutdown() noexcept
    {
        shutdown_flag_.store(true, std::memory_order_release);
        cv_not_empty_.notify_all();
    }

    // Diagnostics
    [[nodiscard]] std::size_t size() const noexcept
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

    [[nodiscard]] bool empty() const noexcept
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }
    // Cumulative packet counters updated atomically; safe to read from any thread without holding the mutex (approximate real-time metrics).
    [[nodiscard]] uint64_t pushed_count() const noexcept
    {
        return pushed_count_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] uint64_t popped_count() const noexcept
    {
        return popped_count_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] uint64_t dropped_count() const noexcept
    {
        return dropped_count_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] double drop_rate_percent() const noexcept
    {
        const uint64_t pushed = pushed_count_.load(std::memory_order_relaxed);
        const uint64_t dropped = dropped_count_.load(std::memory_order_relaxed);

        if (pushed == 0)
        {
            return 0.0;
        }

        return (static_cast<double>(dropped) / static_cast<double>(pushed)) * 100.0;
    }
};
extern PacketRingBuffer g_ring_buffer;
#endif // NETWORK_THREAT_ENGINE_PACKET_RING_BUFFER_HPP