#include "reliable_send_manager.h"
#include "logger.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <fstream>

using json = nlohmann::json;

namespace {

constexpr const char* kOutboxFileName = "reliable_outbox.json";
constexpr const char* kEnvelopeType = "LP_RELIABLE";
constexpr const char* kAckType = "LP_RELIABLE_ACK";

} // namespace

// ---------------------------------------------------------------------------
// Base64 (RFC 4648) — self-contained so the reliable path has no extra deps.
// ---------------------------------------------------------------------------
std::string reliable_base64_encode(const std::string& input) {
    static const char* tbl =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((input.size() + 2) / 3) * 4);
    size_t i = 0;
    while (i + 2 < input.size()) {
        const uint32_t v = (static_cast<uint8_t>(input[i]) << 16) |
                           (static_cast<uint8_t>(input[i + 1]) << 8) |
                           static_cast<uint8_t>(input[i + 2]);
        out.push_back(tbl[(v >> 18) & 0x3F]);
        out.push_back(tbl[(v >> 12) & 0x3F]);
        out.push_back(tbl[(v >> 6) & 0x3F]);
        out.push_back(tbl[v & 0x3F]);
        i += 3;
    }
    if (i < input.size()) {
        uint32_t v = static_cast<uint8_t>(input[i]) << 16;
        if (i + 1 < input.size()) v |= static_cast<uint8_t>(input[i + 1]) << 8;
        out.push_back(tbl[(v >> 18) & 0x3F]);
        out.push_back(tbl[(v >> 12) & 0x3F]);
        out.push_back((i + 1 < input.size()) ? tbl[(v >> 6) & 0x3F] : '=');
        out.push_back('=');
    }
    return out;
}

std::string reliable_base64_decode(const std::string& input) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    std::string out;
    out.reserve((input.size() / 4) * 3);
    uint32_t buf = 0;
    int bits = 0;
    for (char c : input) {
        if (c == '=' || c == '\n' || c == '\r') continue;
        const int v = val(c);
        if (v < 0) return {};
        buf = (buf << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((buf >> bits) & 0xFF));
        }
    }
    return out;
}

int64_t ReliableSendManager::now_epoch_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

ReliableSendManager::ReliableSendManager() = default;

ReliableSendManager::~ReliableSendManager() {
    stop();
}

void ReliableSendManager::configure(const std::string& files_dir, bool offline_enabled,
                                    int max_messages, int64_t ttl_ms) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_files_dir = files_dir;
    m_offline_enabled = offline_enabled;
    if (max_messages > 0) m_max_messages = max_messages;
    if (ttl_ms > 0) m_ttl_ms = ttl_ms;
    load_outbox();
}

void ReliableSendManager::set_callbacks(StatusCallback on_status, SendFn send_fn,
                                        IsConnectedFn is_connected_fn,
                                        OfflineStoreFn offline_store_fn) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_on_status = std::move(on_status);
    m_send_fn = std::move(send_fn);
    m_is_connected_fn = std::move(is_connected_fn);
    m_offline_store_fn = std::move(offline_store_fn);
}

std::string ReliableSendManager::encode_envelope(const ReliableMessage& msg) const {
    json j;
    j["type"] = kEnvelopeType;
    j["msg_id"] = msg.msg_id;
    j["body_b64"] = reliable_base64_encode(msg.payload);
    return j.dump();
}

bool ReliableSendManager::send_reliable(const std::string& peer_id, const std::string& msg_id,
                                        const std::string& payload, int max_retries,
                                        uint32_t retry_timeout_ms) {
    if (peer_id.empty() || msg_id.empty()) return false;
    if (m_stopped.load(std::memory_order_acquire)) return false;

    StatusCallback status_cb;
    bool queue_full = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        // Reject duplicate in-flight ids.
        if (m_index.find(msg_id) != m_index.end()) {
            LOG_WARN("RSM: duplicate msg_id rejected: " + msg_id);
            return false;
        }

        // Enforce outbox capacity.
        if (static_cast<int>(m_outbox.size()) >= m_max_messages) {
            LOG_WARN("RSM: outbox full (" + std::to_string(m_outbox.size()) +
                     "); rejecting " + msg_id);
            queue_full = true;
            status_cb = m_on_status;
        } else {
            ReliableMessage msg;
            msg.msg_id = msg_id;
            msg.peer_id = peer_id;
            msg.payload = payload;
            msg.max_retries = max_retries > 0 ? max_retries : 3;
            msg.retry_timeout_ms = retry_timeout_ms > 0 ? retry_timeout_ms : 10000;
            msg.status = ReliableDeliveryStatus::QUEUED;
            msg.created_ms = now_epoch_ms();
            msg.next_retry_ms = msg.created_ms;  // attempt immediately on next tick

            m_index[msg_id] = m_outbox.size();
            m_outbox.push_back(std::move(msg));
            save_outbox_locked();
            status_cb = m_on_status;
        }
    }

    if (queue_full) {
        if (status_cb) status_cb(msg_id, static_cast<int>(ReliableDeliveryStatus::FAILED),
                                 "QUEUE_FULL");
        return false;
    }

    if (status_cb) status_cb(msg_id, static_cast<int>(ReliableDeliveryStatus::QUEUED), "OK");
    LOG_INFO("RSM: queued reliable send " + msg_id + " -> " + peer_id);
    return true;
}

bool ReliableSendManager::cancel(const std::string& msg_id) {
    StatusCallback status_cb;
    std::string failed_id;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_index.find(msg_id);
        if (it == m_index.end()) return false;
        ReliableMessage& msg = m_outbox[it->second];
        if (msg.status == ReliableDeliveryStatus::DELIVERED ||
            msg.status == ReliableDeliveryStatus::FAILED) {
            return false;  // terminal
        }
        msg.cancelled = true;
        msg.status = ReliableDeliveryStatus::FAILED;
        msg.reason = "CANCELLED";
        save_outbox_locked();
        status_cb = m_on_status;
        failed_id = msg_id;
    }
    if (status_cb) status_cb(failed_id, static_cast<int>(ReliableDeliveryStatus::FAILED),
                             "CANCELLED");
    return true;
}

void ReliableSendManager::on_ack(const std::string& msg_id) {
    StatusCallback status_cb;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_index.find(msg_id);
        if (it == m_index.end()) return;
        ReliableMessage& msg = m_outbox[it->second];
        if (msg.status == ReliableDeliveryStatus::DELIVERED) return;
        msg.status = ReliableDeliveryStatus::DELIVERED;
        msg.reason = "OK";
        save_outbox_locked();
        status_cb = m_on_status;
    }
    LOG_INFO("RSM: ACK received for " + msg_id);
    if (status_cb) status_cb(msg_id, static_cast<int>(ReliableDeliveryStatus::DELIVERED), "OK");
}

bool ReliableSendManager::is_duplicate(const std::string& msg_id) {
    if (msg_id.empty()) return false;
    std::lock_guard<std::mutex> lock(m_mutex);
    const int64_t now = now_epoch_ms();

    // Prune expired entries when the map grows large.
    if (m_seen.size() > 4096) {
        for (auto it = m_seen.begin(); it != m_seen.end();) {
            if (now - it->second > m_dedup_window_ms) it = m_seen.erase(it);
            else ++it;
        }
    }

    auto it = m_seen.find(msg_id);
    if (it != m_seen.end() && (now - it->second) <= m_dedup_window_ms) {
        return true;
    }
    m_seen[msg_id] = now;
    return false;
}

void ReliableSendManager::tick() {
    if (m_stopped.load(std::memory_order_acquire)) return;

    const int64_t now = now_epoch_ms();
    std::vector<std::pair<std::string, std::pair<int, std::string>>> status_events;
    std::vector<std::pair<std::string, std::string>> sends;  // (peer_id, wire)
    std::vector<std::tuple<std::string, std::string, std::string>> offline_stores;

    SendFn send_fn;
    IsConnectedFn is_connected_fn;
    OfflineStoreFn offline_store_fn;
    StatusCallback status_cb;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        send_fn = m_send_fn;
        is_connected_fn = m_is_connected_fn;
        offline_store_fn = m_offline_store_fn;
        status_cb = m_on_status;

        for (auto& msg : m_outbox) {
            if (msg.status == ReliableDeliveryStatus::DELIVERED ||
                msg.status == ReliableDeliveryStatus::FAILED ||
                msg.cancelled) {
                continue;
            }

            // TTL expiry.
            if (now - msg.created_ms > m_ttl_ms) {
                msg.status = ReliableDeliveryStatus::FAILED;
                msg.reason = "TTL_EXPIRED";
                status_events.push_back(
                    {msg.msg_id, {static_cast<int>(ReliableDeliveryStatus::FAILED), "TTL_EXPIRED"}});
                continue;
            }

            if (now < msg.next_retry_ms) continue;

            const bool connected = is_connected_fn ? is_connected_fn(msg.peer_id) : false;

            if (connected && send_fn) {
                // Direct send attempt.
                msg.attempts++;
                msg.status = ReliableDeliveryStatus::SENT;
                msg.next_retry_ms = now + msg.retry_timeout_ms;
                sends.push_back({msg.peer_id, encode_envelope(msg)});
                status_events.push_back(
                    {msg.msg_id, {static_cast<int>(ReliableDeliveryStatus::SENT), "OK"}});

                if (msg.attempts > msg.max_retries) {
                    msg.status = ReliableDeliveryStatus::FAILED;
                    msg.reason = "TIMEOUT";
                    status_events.push_back(
                        {msg.msg_id, {static_cast<int>(ReliableDeliveryStatus::FAILED), "TIMEOUT"}});
                }
            } else if (!connected && m_offline_enabled && offline_store_fn && !msg.offline_stored) {
                // Peer offline: hand to the signaling server store (once).
                offline_stores.push_back(
                    {msg.peer_id, msg.msg_id, reliable_base64_encode(msg.payload)});
                msg.offline_stored = true;
                msg.status = ReliableDeliveryStatus::SENT;
                msg.next_retry_ms = now + msg.retry_timeout_ms;
                status_events.push_back(
                    {msg.msg_id, {static_cast<int>(ReliableDeliveryStatus::SENT), "PEER_OFFLINE"}});
            } else if (!connected) {
                // No offline store available (or already stored); count attempts.
                msg.attempts++;
                msg.next_retry_ms = now + msg.retry_timeout_ms;
                if (msg.attempts > msg.max_retries) {
                    msg.status = ReliableDeliveryStatus::FAILED;
                    msg.reason = "PEER_OFFLINE";
                    status_events.push_back(
                        {msg.msg_id, {static_cast<int>(ReliableDeliveryStatus::FAILED), "PEER_OFFLINE"}});
                }
            }
        }

        save_outbox_locked();
    }

    // Fire events outside the lock.
    if (send_fn) {
        for (auto& s : sends) send_fn(s.first, s.second);
    }
    if (offline_store_fn) {
        for (auto& os : offline_stores) {
            const bool stored = offline_store_fn(std::get<0>(os), std::get<1>(os), std::get<2>(os));
            if (stored) {
                LOG_INFO("RSM: offline-stored " + std::get<1>(os) + " for " + std::get<0>(os));
            }
        }
    }
    if (status_cb) {
        for (auto& ev : status_events) {
            status_cb(ev.first, ev.second.first, ev.second.second);
        }
    }
}

void ReliableSendManager::stop() {
    if (m_stopped.exchange(true)) return;
    std::lock_guard<std::mutex> lock(m_mutex);
    save_outbox_locked();
}

size_t ReliableSendManager::pending_count() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    size_t n = 0;
    for (const auto& m : m_outbox) {
        if (m.status == ReliableDeliveryStatus::QUEUED ||
            m.status == ReliableDeliveryStatus::SENT) {
            n++;
        }
    }
    return n;
}

bool ReliableSendManager::is_full() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return static_cast<int>(m_outbox.size()) >= m_max_messages;
}

void ReliableSendManager::load_outbox() {
    if (m_files_dir.empty()) return;
    const std::string path = m_files_dir + "/" + kOutboxFileName;
    std::ifstream f(path);
    if (!f.good()) return;
    try {
        json j;
        f >> j;
        if (!j.is_array()) return;
        m_outbox.clear();
        m_index.clear();
        for (const auto& item : j) {
            ReliableMessage msg;
            msg.msg_id = item.value("msg_id", std::string{});
            msg.peer_id = item.value("peer_id", std::string{});
            msg.payload = reliable_base64_decode(item.value("body_b64", std::string{}));
            msg.max_retries = item.value("max_retries", 3);
            msg.retry_timeout_ms = item.value("retry_timeout_ms", 10000u);
            msg.attempts = item.value("attempts", 0);
            msg.created_ms = item.value("created_ms", static_cast<int64_t>(0));
            msg.offline_stored = item.value("offline_stored", false);
            const std::string st = item.value("status", std::string{"QUEUED"});
            msg.status = (st == "SENT") ? ReliableDeliveryStatus::SENT
                                        : ReliableDeliveryStatus::QUEUED;
            msg.next_retry_ms = now_epoch_ms();  // retry immediately after restart
            m_index[msg.msg_id] = m_outbox.size();
            m_outbox.push_back(std::move(msg));
        }
        LOG_INFO("RSM: loaded " + std::to_string(m_outbox.size()) +
                 " pending reliable sends from " + path);
    } catch (const std::exception& e) {
        LOG_WARN(std::string("RSM: failed to load outbox: ") + e.what());
    }
}

void ReliableSendManager::save_outbox_locked() {
    if (m_files_dir.empty()) return;
    const std::string path = m_files_dir + "/" + kOutboxFileName;
    try {
        json j = json::array();
        for (const auto& msg : m_outbox) {
            // Persist only non-terminal entries to keep the file small.
            if (msg.status == ReliableDeliveryStatus::DELIVERED ||
                msg.status == ReliableDeliveryStatus::FAILED) {
                continue;
            }
            json item;
            item["msg_id"] = msg.msg_id;
            item["peer_id"] = msg.peer_id;
            item["body_b64"] = reliable_base64_encode(msg.payload);
            item["max_retries"] = msg.max_retries;
            item["retry_timeout_ms"] = msg.retry_timeout_ms;
            item["attempts"] = msg.attempts;
            item["created_ms"] = msg.created_ms;
            item["offline_stored"] = msg.offline_stored;
            item["status"] = msg.status == ReliableDeliveryStatus::SENT ? "SENT" : "QUEUED";
            j.push_back(item);
        }
        std::ofstream f(path, std::ios::trunc);
        if (f.good()) f << j.dump();
    } catch (const std::exception& e) {
        LOG_WARN(std::string("RSM: failed to save outbox: ") + e.what());
    }
}



