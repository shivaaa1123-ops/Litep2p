// Network OS Phase 13 — GossipEngine implementation. See header.

#include "networkos/gossip/gossip_engine.h"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <sstream>

namespace networkos {
namespace gossip {

namespace {

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(c);
                }
        }
    }
    return out;
}

}  // namespace

GossipEngine::GossipEngine(const Config& cfg) : m_cfg(cfg) {
    m_local.peer_id = cfg.local_peer_id;
}

void GossipEngine::setSendFn(SendFn fn) { m_send = std::move(fn); }
void GossipEngine::setAcceptedFn(AcceptedFn fn) { m_accepted = std::move(fn); }

void GossipEngine::setLocalPushToken(const std::string& token, uint64_t now_utc) {
    std::lock_guard<std::mutex> lock(m_mu);
    if (token == m_local.fcm_token_id) return;
    m_local.fcm_token_id = token;
    m_local.token_version += 1;
    m_local.last_seen_utc = now_utc;
    normalize_flags(m_local);
    if (!m_cfg.local_peer_id.empty()) {
        PeerRecord self = m_local;
        noteAcceptedLocked_(self, now_utc);
    }
    m_dirty_since_ms = now_ms();
}

size_t GossipEngine::ingestDelta(const std::string& payload, uint64_t now_utc) {
    size_t accepted = 0;
    std::vector<PeerRecord> notify;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        if (payload.empty()) return 0;
        const size_t count = static_cast<uint8_t>(payload[0]);
        if (count > m_cfg.delta_batch_max * 2) return 0;  // abusive batch
        size_t off = 1;
        bool any = false;
        for (size_t i = 0; i < count; ++i) {
            PeerRecord r;
            if (!decode_peer_record_at(payload, off, r)) break;  // strict
            if (r.peer_id == m_cfg.local_peer_id) continue;   // never self-ingest
            auto it = m_records.find(r.peer_id);
            bool changed = false;
            if (it == m_records.end()) {
                // Accept every well-formed record: push-only contacts (token,
                // no endpoint) are exactly what the FCM tier needs later.
                m_records.emplace(r.peer_id, r);
                changed = true;
            } else {
                changed = merge_record(it->second, r);
            }
            if (changed) {
                ++accepted;
                any = true;
                evictIfNeededLocked_();
                notify.push_back(r);
                if (r.has_signaling()) {
                    poolAddLocked_(r.signaling_addr);  // m_mu already held
                }
            }
        }
        if (any) m_dirty_since_ms = now_ms();
        if (count) m_delta_recv += 1;
        m_accepted_total += accepted;
    }
    if (m_accepted) {
        for (const PeerRecord& r : notify) m_accepted(r);
    }
    (void)now_utc;
    return accepted;
}

std::string GossipEngine::buildDeltaFor(const std::string& peer_id,
                                        uint64_t now_utc) {
    std::lock_guard<std::mutex> lock(m_mu);
    const uint64_t seen_through =
        m_sent_version.count(peer_id) ? m_sent_version[peer_id] : 0;
    std::vector<const PeerRecord*> candidates;
    if (m_local.token_version > seen_through && !m_cfg.local_peer_id.empty()) {
        candidates.push_back(&m_local);
    }
    for (const auto& kv : m_records) {
        if (kv.second.token_version > seen_through && kv.first != peer_id) {
            candidates.push_back(&kv.second);
        }
    }
    if (candidates.size() > m_cfg.delta_batch_max) {
        std::partial_sort(candidates.begin(),
                          candidates.begin() + static_cast<long>(m_cfg.delta_batch_max),
                          candidates.end(),
                          [](const PeerRecord* a, const PeerRecord* b) {
                              return a->token_version > b->token_version;
                          });
        candidates.resize(m_cfg.delta_batch_max);
    }
    std::string payload;
    payload.push_back(static_cast<char>(candidates.size()));
    uint64_t max_sent = seen_through;
    for (const PeerRecord* r : candidates) {
        payload.append(encode_peer_record(*r));
        max_sent = std::max(max_sent, r->token_version);
    }
    m_sent_version[peer_id] = max_sent;
    (void)now_utc;
    if (!candidates.empty()) ++m_delta_sent;
    return payload;
}

size_t GossipEngine::purgeStale(uint64_t now_utc) {
    std::lock_guard<std::mutex> lock(m_mu);
    size_t purged = 0;
    for (auto it = m_records.begin(); it != m_records.end();) {
        if (it->second.last_seen_utc + m_cfg.stale_after_s < now_utc) {
            it = m_records.erase(it);
            ++purged;
        } else {
            ++it;
        }
    }
    return purged;
}

size_t GossipEngine::size() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return m_records.size();
}

bool GossipEngine::lookup(const std::string& peer_id, PeerRecord& out) const {
    std::lock_guard<std::mutex> lock(m_mu);
    auto it = m_records.find(peer_id);
    if (it == m_records.end()) return false;
    out = it->second;
    return true;
}

void GossipEngine::signalingPoolAdd(const std::string& url) {
    if (url.empty()) return;
    std::lock_guard<std::mutex> lock(m_mu);
    poolAddLocked_(url);
}

void GossipEngine::poolAddLocked_(const std::string& url) {
    for (auto& e : m_pool) {
        if (e.url == url) return;
    }
    if (m_pool.size() >= m_cfg.signaling_pool_max) {
        auto worst = std::max_element(
            m_pool.begin(), m_pool.end(),
            [](const PoolEntry& a, const PoolEntry& b) {
                if (a.failures != b.failures) return a.failures > b.failures;
                return a.last_used_ms < b.last_used_ms;
            });
        m_pool.erase(worst);
    }
    m_pool.push_back(PoolEntry{url, 0, 0});
}

bool GossipEngine::signalingPoolNext(std::string& out_url) {
    std::lock_guard<std::mutex> lock(m_mu);
    if (m_pool.empty()) return false;
    auto best = std::min_element(
        m_pool.begin(), m_pool.end(),
        [](const PoolEntry& a, const PoolEntry& b) {
            if (a.failures != b.failures) return a.failures < b.failures;
            return a.last_used_ms < b.last_used_ms;
        });
    out_url = best->url;
    best->last_used_ms = now_ms();
    return true;
}

void GossipEngine::signalingPoolMarkBad(const std::string& url) {
    std::lock_guard<std::mutex> lock(m_mu);
    for (auto& e : m_pool) {
        if (e.url == url) e.failures += 1;
    }
}

std::string GossipEngine::encodeFindPeer(const std::string& target_peer_id,
                                         uint32_t nonce) {
    std::string out;
    out.push_back(static_cast<char>(target_peer_id.size()));
    out.append(target_peer_id);
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<char>((nonce >> (8 * i)) & 0xFF));
    }
    return out;
}

bool GossipEngine::decodeFindPeer(const std::string& payload,
                                  std::string& target_peer_id, uint32_t& nonce) {
    size_t off = 0;
    if (payload.empty()) return false;
    const size_t len = static_cast<uint8_t>(payload[off]);
    off += 1;
    if (len == 0 || len > 128 || off + len + 4 != payload.size()) return false;
    target_peer_id.assign(payload, off, len);
    off += len;
    nonce = 0;
    for (int i = 3; i >= 0; --i) {
        nonce = (nonce << 8) | static_cast<uint8_t>(payload[off + i]);
    }
    return true;
}

std::string GossipEngine::encodeFindReply(const PeerRecord* record,
                                          uint32_t nonce) {
    std::string out;
    out.push_back(record ? 1 : 0);
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<char>((nonce >> (8 * i)) & 0xFF));
    }
    if (record) out.append(encode_peer_record(*record));
    return out;
}

bool GossipEngine::decodeFindReply(const std::string& payload, PeerRecord& out,
                                   bool& found, uint32_t& nonce) {
    found = false;
    size_t off = 0;
    if (payload.size() < 5) return false;
    found = static_cast<uint8_t>(payload[off]) != 0;
    off += 1;
    nonce = 0;
    for (int i = 3; i >= 0; --i) {
        nonce = (nonce << 8) | static_cast<uint8_t>(payload[off + i]);
    }
    off += 4;
    if (found && !decode_peer_record_at(payload, off, out)) return false;
    return off == payload.size();
}

void GossipEngine::onFrame(const std::string& peer_id, MessageType type,
                           const std::string& payload, uint64_t now_utc) {
    switch (type) {
        case MessageType::PEER_RECORDS_DELTA:
            ingestDelta(payload, now_utc);
            break;
        case MessageType::FIND_PEER_QUERY: {
            std::string target;
            uint32_t nonce = 0;
            if (!decodeFindPeer(payload, target, nonce)) return;
            PeerRecord rec;
            const bool have = lookup(target, rec);
            if (have) {
                ++m_find_hit;
            } else {
                ++m_find_miss;
            }
            if (m_send) {
                m_send(peer_id, MessageType::FIND_PEER_REPLY,
                       encodeFindReply(have ? &rec : nullptr, nonce));
            }
            break;
        }
        case MessageType::FIND_PEER_REPLY: {
            // Opportunistic ingest of any carried record.
            if (payload.size() < 5 || static_cast<uint8_t>(payload[0]) == 0) break;
            ingestDelta(std::string(1, '\x01') + payload.substr(5), now_utc);
            break;
        }
        default:
            break;
    }
}

void GossipEngine::tick(const std::vector<std::string>& connected_peers,
                        uint64_t now_utc) {
    SendFn send;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        send = m_send;
    }
    if (!send) return;
    for (const std::string& peer : connected_peers) {
        const std::string delta = buildDeltaFor(peer, now_utc);
        if (delta.size() > 1) {
            send(peer, MessageType::PEER_RECORDS_DELTA, delta);
        }
    }
}

void GossipEngine::noteAcceptedLocked_(const PeerRecord& r, uint64_t /*now*/) {
    auto it = m_records.find(r.peer_id);
    if (it == m_records.end()) {
        m_records.emplace(r.peer_id, r);
    } else {
        merge_record(it->second, r);
    }
    evictIfNeededLocked_();
}

void GossipEngine::evictIfNeededLocked_() {
    while (m_records.size() > m_cfg.max_records) {
        auto oldest = m_records.begin();
        for (auto it = m_records.begin(); it != m_records.end(); ++it) {
            if (it->second.last_seen_utc < oldest->second.last_seen_utc) {
                oldest = it;
            }
        }
        m_records.erase(oldest);
    }
}

bool GossipEngine::save(uint64_t /*now_utc*/) {
    if (m_cfg.persist_path.empty()) return false;
    std::ostringstream o;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        o << "{\"local\":\"" << json_escape(m_local.fcm_token_id)
          << "\",\"local_version\":" << m_local.token_version
          << ",\"records\":[";
        bool first = true;
        for (const auto& kv : m_records) {
            const PeerRecord& r = kv.second;
            if (!first) o << ",";
            first = false;
            o << "{\"id\":\"" << json_escape(r.peer_id) << "\",\"ep\":\""
              << json_escape(r.primary_endpoint) << "\",\"tok\":\""
              << json_escape(r.fcm_token_id) << "\",\"sig\":\""
              << json_escape(r.signaling_addr) << "\",\"ver\":"
              << r.token_version << ",\"seen\":" << r.last_seen_utc
              << ",\"fl\":" << static_cast<int>(r.flags) << "}";
        }
        o << "]}";
    }
    const std::string tmp = m_cfg.persist_path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) return false;
        out << o.str();
        out.flush();
        if (!out.good()) return false;
    }
    return std::rename(tmp.c_str(), m_cfg.persist_path.c_str()) == 0;
}

bool GossipEngine::load() {
    if (m_cfg.persist_path.empty()) return false;
    std::ifstream in(m_cfg.persist_path, std::ios::binary);
    if (!in.good()) return false;
    std::stringstream ss;
    ss << in.rdbuf();
    const std::string j = ss.str();

    auto extract_str = [&j](const std::string& key, size_t from,
                            std::string& out) -> size_t {
        const std::string pat = "\"" + key + "\":\"";
        size_t p = j.find(pat, from);
        if (p == std::string::npos) return from;
        p += pat.size();
        size_t e = j.find('"', p);
        if (e == std::string::npos) return from;
        out.assign(j, p, e - p);
        return e + 1;
    };
    auto num_after = [&j](const std::string& key, size_t from) -> uint64_t {
        const std::string pat = "\"" + key + "\":";
        size_t q = j.find(pat, from);
        if (q == std::string::npos) return 0;
        q += pat.size();
        return std::strtoull(j.c_str() + q, nullptr, 10);
    };

    std::lock_guard<std::mutex> lock(m_mu);
    std::string tok;
    extract_str("local", 0, tok);
    if (!tok.empty() && tok != m_local.fcm_token_id) {
        m_local.fcm_token_id = tok;
        normalize_flags(m_local);
    }
    size_t arr = j.find("\"records\":[");
    if (arr == std::string::npos) return true;
    arr += 11;
    while (true) {
        PeerRecord r;
        size_t p2 = j.find("{\"id\":\"", arr);
        const size_t arr_end = j.find(']', arr);
        if (p2 == std::string::npos || (arr_end != std::string::npos && p2 > arr_end)) break;
        p2 = extract_str("id", p2, r.peer_id);
        p2 = extract_str("ep", p2, r.primary_endpoint);
        p2 = extract_str("tok", p2, r.fcm_token_id);
        p2 = extract_str("sig", p2, r.signaling_addr);
        if (r.peer_id.empty()) break;
        r.token_version = num_after("ver", arr);
        r.last_seen_utc = num_after("seen", arr);
        r.flags = static_cast<uint8_t>(num_after("fl", arr));
        m_records.emplace(r.peer_id, r);
        arr = p2;
    }
    return true;
}

std::string GossipEngine::telemetryJson() const {
    std::lock_guard<std::mutex> lock(m_mu);
    std::ostringstream o;
    o << "{\"records\":" << m_records.size()
      << ",\"pool\":" << m_pool.size()
      << ",\"delta_sent\":" << m_delta_sent
      << ",\"delta_recv\":" << m_delta_recv
      << ",\"accepted\":" << m_accepted_total
      << ",\"find_hits\":" << m_find_hit
      << ",\"find_misses\":" << m_find_miss << "}";
    return o.str();
}}  // namespace gossip
}  // namespace networkos
