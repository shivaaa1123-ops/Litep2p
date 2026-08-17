#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// ============================================================================
// ReliableSendManager (v0.4, ask.md §1 + §2)
// ============================================================================
// Engine-level reliable messaging with delivery receipts and a store-and-
// forward offline mailbox.
//
// Sender side:
//   - send_reliable() persists the payload into a JSON outbox under files_dir
//     so pending sends survive stop()/start() and process restart.
//   - A retry loop re-sends every retry_timeout_ms until the receiver ACKs or
//     max_retries is exhausted.
//   - When the peer has no live session and the offline queue is enabled, the
//     payload is handed to the signaling server (STORE) for delivery on the
//     peer's next connect.
//   - Lifecycle is reported via the status callback:
//       QUEUED -> SENT -> DELIVERED | FAILED(reason)
//
// Receiver side:
//   - is_duplicate() provides msg_id dedup so onMessageReceived fires at most
//     once per msg_id within the dedup window.
//
// Wire envelope (carried over APPLICATION_DATA):
//   {"type":"LP_RELIABLE","msg_id":"...","body_b64":"..."}
//   ACK: {"type":"LP_RELIABLE_ACK","msg_id":"..."}
// ============================================================================

enum class ReliableDeliveryStatus : int {
    QUEUED = 0,
    SENT = 1,
    DELIVERED = 2,
    FAILED = 3,
};

struct ReliableMessage {
    std::string msg_id;
    std::string peer_id;
    std::string payload;          // raw application bytes
    int max_retries = 3;
    uint32_t retry_timeout_ms = 10000;
    int attempts = 0;
    ReliableDeliveryStatus status = ReliableDeliveryStatus::QUEUED;
    std::string reason = "OK";
    int64_t created_ms = 0;       // epoch ms
    int64_t next_retry_ms = 0;    // epoch ms
    bool offline_stored = false;
    bool cancelled = false;
};

class ReliableSendManager {
public:
    using StatusCallback =
        std::function<void(const std::string& msg_id, int status, const std::string& reason)>;
    // Sends a fully-encoded wire frame to a connected peer.
    using SendFn = std::function<void(const std::string& peer_id, const std::string& wire_message)>;
    // Whether a live session exists for the peer.
    using IsConnectedFn = std::function<bool(const std::string& peer_id)>;
    // Hands a payload to the signaling server for offline delivery. Returns
    // true when the server accepted the store.
    using OfflineStoreFn =
        std::function<bool(const std::string& peer_id, const std::string& msg_id,
                           const std::string& payload_b64)>;

    ReliableSendManager();
    ~ReliableSendManager();

    // Configure persistence + offline queue policy. Call before start().
    void configure(const std::string& files_dir, bool offline_enabled,
                   int max_messages, int64_t ttl_ms);

    void set_callbacks(StatusCallback on_status, SendFn send_fn,
                       IsConnectedFn is_connected_fn, OfflineStoreFn offline_store_fn);

    // Accept a reliable send. Returns true when queued into the outbox.
    bool send_reliable(const std::string& peer_id, const std::string& msg_id,
                       const std::string& payload, int max_retries, uint32_t retry_timeout_ms);

    // Cancel a pending send. Fires FAILED/CANCELLED when the id was known.
    bool cancel(const std::string& msg_id);

    // Receiver ACK for msg_id -> mark DELIVERED.
    void on_ack(const std::string& msg_id);

    // Receiver-side dedup. Returns true when msg_id was already seen within
    // the dedup window (caller should drop the message).
    bool is_duplicate(const std::string& msg_id);

    // Periodic driver (called from the session timer loop).
    void tick();

    // Flush pending state to disk and stop retry activity.
    void stop();

    // Diagnostics.
    size_t pending_count() const;

    // True when the outbox is at capacity (send_reliable would reject).
    bool is_full() const;

private:
    void load_outbox();
    void save_outbox_locked();
    void attempt_send_locked(ReliableMessage& msg, int64_t now_ms);
    void fail_locked(ReliableMessage& msg, const std::string& reason);
    void deliver_locked(ReliableMessage& msg);
    std::string encode_envelope(const ReliableMessage& msg) const;
    static int64_t now_epoch_ms();

    mutable std::mutex m_mutex;
    std::vector<ReliableMessage> m_outbox;
    // msg_id -> index into m_outbox for O(1) ACK/cancel lookup.
    std::unordered_map<std::string, size_t> m_index;

    // Receiver dedup (msg_id -> first-seen epoch ms).
    std::unordered_map<std::string, int64_t> m_seen;

    std::string m_files_dir;
    bool m_offline_enabled = true;
    int m_max_messages = 500;
    int64_t m_ttl_ms = 604800000;      // 7 days
    int64_t m_dedup_window_ms = 3600000; // 1 hour

    StatusCallback m_on_status;
    SendFn m_send_fn;
    IsConnectedFn m_is_connected_fn;
    OfflineStoreFn m_offline_store_fn;

    std::atomic<bool> m_stopped{false};
};

// Base64 helpers shared by the reliable-send path and offline store.
std::string reliable_base64_encode(const std::string& input);
std::string reliable_base64_decode(const std::string& input);
