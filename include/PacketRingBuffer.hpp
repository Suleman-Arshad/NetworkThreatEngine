#pragma once
#ifndef NETWORK_THREAT_ENGINE_PACKET_RING_BUFFER_HPP
#define NETWORK_THREAT_ENGINE_PACKET_RING_BUFFER_HPP
#include "Config.hpp"
#include "PacketInfo.hpp"
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <queue>

namespace nte
{

    class PacketRingBuffer
    {
    public:
        // Construction

        explicit PacketRingBuffer(const RingBufferConfig &cfg = RingBufferConfig{})
            : max_capacity_(cfg.max_capacity)
        {
        }

        ~PacketRingBuffer() = default;

        // Non-copyable, non-movable: shared by raw pointer between threads; must not be relocated after threads are spawned.
        PacketRingBuffer(const PacketRingBuffer &) = delete;
        PacketRingBuffer &operator=(const PacketRingBuffer &) = delete;
        PacketRingBuffer(PacketRingBuffer &&) = delete;
        PacketRingBuffer &operator=(PacketRingBuffer &&) = delete;

        // Producer Interface
        bool push(CapturedPacket &&packet) noexcept
        {
            {
                std::lock_guard<std::mutex> lock(mutex_);

                if (queue_.size() >= max_capacity_)
                {
                    ++dropped_count_;
                    return false;
                }

                queue_.push(std::move(packet));
                ++pushed_count_;
            }

            // Notify after releasing the lock to avoid waking a Consumer that would immediately block again trying to acquire the same mutex.
            cv_not_empty_.notify_one();
            return true;
        }

        // Consumer Interface
        bool pop(CapturedPacket &out)
        {
            std::unique_lock<std::mutex> lock(mutex_);

            cv_not_empty_.wait(lock, [this]()
                               { return !queue_.empty() || shutdown_flag_.load(std::memory_order_acquire); });

            if (queue_.empty())
            {
                // Woken by shutdown() with nothing left to process.
                return false;
            }

            out = std::move(queue_.front());
            queue_.pop();
            ++popped_count_;
            return true;
        }

        // Lifecycle Control

        void shutdown() noexcept
        {
            shutdown_flag_.store(true, std::memory_order_release);
            cv_not_empty_.notify_all();
        }

        // Returns true once shutdown() has been called.
        [[nodiscard]] bool is_shutdown() const noexcept
        {
            return shutdown_flag_.load(std::memory_order_acquire);
        }

        // Diagnostics (thread-safe, approximate)

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

        // Cumulative counters - atomics, safe to read from any thread.
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

        // Percentage of pushed packets dropped due to queue saturation.
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

        // Configured capacity ceiling.
        [[nodiscard]] std::size_t max_capacity() const noexcept
        {
            return max_capacity_;
        }

    private:
        const std::size_t max_capacity_;

        // Queue and synchronisation primitives
        mutable std::mutex mutex_;
        std::condition_variable cv_not_empty_;
        std::queue<CapturedPacket> queue_;

        // Lifecycle
        std::atomic<bool> shutdown_flag_{false};

        // Telemetry
        std::atomic<uint64_t> pushed_count_{0};
        std::atomic<uint64_t> popped_count_{0};
        std::atomic<uint64_t> dropped_count_{0};
    };

} // namespace nte

#endif // NETWORK_THREAT_ENGINE_PACKET_RING_BUFFER_HPP