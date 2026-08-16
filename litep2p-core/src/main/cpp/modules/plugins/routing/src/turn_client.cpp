#include "../include/turn_client.h"
#include "../../../corep2p/core/include/logger.h"
#include "../../../corep2p/crypto/include/sha1_md5.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <cerrno>

namespace {

using litep2p_crypto::hmac_sha1;
using litep2p_crypto::md5;

// ---------------------------------------------------------------------------
// XOR-address helpers (RFC 5766 section 15.1)
// ---------------------------------------------------------------------------

// Encode XOR-PEER-ADDRESS / XOR-RELAYED-ADDRESS value (IPv4):
// reserved(0) | family(0x01) | xor-port(2) | xor-address(4)
std::vector<uint8_t> encode_xor_addr_ipv4(const std::string& ip, uint16_t port) {
    std::vector<uint8_t> v(8, 0);
    v[1] = 0x01; // IPv4

    const uint16_t xor_port = static_cast<uint16_t>(port ^ (STUN_MAGIC_COOKIE >> 16));
    v[2] = static_cast<uint8_t>((xor_port >> 8) & 0xFF);
    v[3] = static_cast<uint8_t>(xor_port & 0xFF);

    struct in_addr a {};
    if (inet_pton(AF_INET, ip.c_str(), &a) != 1) {
        LOG_ERROR("TURN: Invalid IPv4 address for XOR attribute: " + ip);
        return {};
    }
    const uint32_t xor_addr = ntohl(a.s_addr) ^ STUN_MAGIC_COOKIE;
    v[4] = static_cast<uint8_t>((xor_addr >> 24) & 0xFF);
    v[5] = static_cast<uint8_t>((xor_addr >> 16) & 0xFF);
    v[6] = static_cast<uint8_t>((xor_addr >> 8) & 0xFF);
    v[7] = static_cast<uint8_t>(xor_addr & 0xFF);
    return v;
}

bool decode_xor_addr_ipv4(const std::vector<uint8_t>& v, std::string& ip, uint16_t& port) {
    if (v.size() < 8 || v[1] != 0x01) return false;

    port = static_cast<uint16_t>(
        ((static_cast<uint16_t>(v[2]) << 8) | v[3]) ^ (STUN_MAGIC_COOKIE >> 16));

    const uint32_t xor_addr =
        (static_cast<uint32_t>(v[4]) << 24) |
        (static_cast<uint32_t>(v[5]) << 16) |
        (static_cast<uint32_t>(v[6]) << 8) |
        static_cast<uint32_t>(v[7]);

    struct in_addr a {};
    a.s_addr = htonl(xor_addr ^ STUN_MAGIC_COOKIE);

    char buf[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &a, buf, sizeof(buf)) == nullptr) return false;
    ip = buf;
    return true;
}

// STUN MESSAGE-INTEGRITY must be the last attribute (before FINGERPRINT). We
// append it to the already-encoded message: patch the header length to include
// the 24-byte MI attribute, append the MI header, then HMAC-SHA1 over
// everything up to (but excluding) the digest.
bool append_message_integrity(std::vector<uint8_t>& raw, const std::string& key) {
    if (raw.size() < 20) return false;

    const uint16_t new_len = static_cast<uint16_t>((raw.size() - 20) + 24);
    raw[2] = static_cast<uint8_t>((new_len >> 8) & 0xFF);
    raw[3] = static_cast<uint8_t>(new_len & 0xFF);

    // MI attribute header: type 0x0008, length 20.
    raw.push_back(0x00);
    raw.push_back(0x08);
    raw.push_back(0x00);
    raw.push_back(0x14);

    const std::string covered(raw.begin(), raw.end());
    const auto mac = hmac_sha1(key, covered);
    if (mac.size() != 20) return false;
    raw.insert(raw.end(), mac.begin(), mac.end());
    return true;
}

} // namespace

TurnClient::TurnClient(const TurnConfig& config) : m_config(config) {
}

TurnClient::~TurnClient() {
    if (m_socket >= 0) {
        close(m_socket);
        m_socket = -1;
    }
}

bool TurnClient::allocate(TurnAllocation& out_allocation) {
    LOG_INFO("TURN: Attempting allocation on " + m_config.server_ip + ":" +
             std::to_string(m_config.server_port));

    // 1. Create socket
    m_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (m_socket < 0) {
        LOG_ERROR("TURN: Failed to create socket");
        return false;
    }

    // 2. Build Allocate Request (RFC 5766): REQUESTED-TRANSPORT = 17 (UDP).
    STUNMessage request;
    request.setType(STUNMessageType::AllocateRequest);

    std::vector<uint8_t> transport(4, 0);
    transport[0] = 17; // UDP (RFC 5766: protocol byte, then 3 reserved bytes)
    request.addAttribute(STUNAttributeType::RequestedTransport, transport);

    // 3. First attempt (unauthenticated) - expect 401 with realm/nonce.
    STUNMessage response;
    if (!sendRequest(request, response)) {
        LOG_ERROR("TURN: Allocate request failed (no response)");
        return false;
    }

    // 4. Handle 401 Unauthorized challenge.
    if (response.getType() == STUNMessageType::AllocateError) {
        std::vector<uint8_t> realm, nonce;
        if (!response.getAttribute(STUNAttributeType::Realm, realm) ||
            !response.getAttribute(STUNAttributeType::Nonce, nonce)) {
            LOG_ERROR("TURN: 401 response missing REALM or NONCE");
            return false;
        }

        const std::string realm_str(realm.begin(), realm.end());
        const std::string nonce_str(nonce.begin(), nonce.end());
        LOG_INFO("TURN: Got 401 Challenge. Realm: " + realm_str);

        STUNMessage auth_request;
        auth_request.setType(STUNMessageType::AllocateRequest);
        auth_request.addAttribute(STUNAttributeType::RequestedTransport, transport);
        addAuthAttributes(auth_request, realm_str, nonce_str);

        if (!sendAuthenticatedRequest(auth_request, response)) {
            LOG_ERROR("TURN: Authenticated allocate request failed");
            return false;
        }
    }

    if (response.getType() != STUNMessageType::AllocateResponse) {
        LOG_ERROR("TURN: Allocation failed. Response type: " +
                  std::to_string(static_cast<int>(response.getType())));
        return false;
    }

    // 5. Decode XOR-RELAYED-ADDRESS (RFC 5766 section 15.2).
    std::vector<uint8_t> relayed;
    if (!response.getAttribute(STUNAttributeType::XorRelayedAddress, relayed) ||
        !decode_xor_addr_ipv4(relayed, out_allocation.relayed_ip, out_allocation.relayed_port)) {
        LOG_ERROR("TURN: Allocation response missing/invalid XOR-RELAYED-ADDRESS");
        return false;
    }

    // 6. Optional LIFETIME attribute.
    std::vector<uint8_t> lifetime;
    if (response.getAttribute(STUNAttributeType::Lifetime, lifetime) && lifetime.size() >= 4) {
        out_allocation.lifetime =
            (static_cast<uint32_t>(lifetime[0]) << 24) |
            (static_cast<uint32_t>(lifetime[1]) << 16) |
            (static_cast<uint32_t>(lifetime[2]) << 8) |
            static_cast<uint32_t>(lifetime[3]);
    }

    out_allocation.active = true;
    LOG_INFO("TURN: Allocation successful. Relay: " + out_allocation.relayed_ip + ":" +
             std::to_string(out_allocation.relayed_port) +
             " lifetime=" + std::to_string(out_allocation.lifetime) + "s");
    return true;
}

bool TurnClient::createPermission(const std::string& peer_ip) {
    if (m_socket < 0) return false;

    const auto xor_peer = encode_xor_addr_ipv4(peer_ip, 0);
    if (xor_peer.empty()) return false;

    STUNMessage request;
    request.setType(STUNMessageType::CreatePermissionRequest);
    request.addAttribute(STUNAttributeType::XorPeerAddress, xor_peer);
    addAuthAttributes(request, m_config.realm, std::string());

    STUNMessage response;
    if (!sendAuthenticatedRequest(request, response)) {
        LOG_ERROR("TURN: CreatePermission request failed for " + peer_ip);
        return false;
    }

    if (response.getType() != STUNMessageType::CreatePermissionResponse) {
        LOG_ERROR("TURN: CreatePermission failed for " + peer_ip +
                  " (response type " + std::to_string(static_cast<int>(response.getType())) + ")");
        return false;
    }
    return true;
}

bool TurnClient::sendData(const std::string& peer_ip, uint16_t peer_port,
                          const std::vector<uint8_t>& data) {
    if (m_socket < 0) return false;

    const auto xor_peer = encode_xor_addr_ipv4(peer_ip, peer_port);
    if (xor_peer.empty()) return false;

    STUNMessage indication;
    indication.setType(STUNMessageType::SendIndication);
    indication.addAttribute(STUNAttributeType::XorPeerAddress, xor_peer);
    indication.addAttribute(STUNAttributeType::Data, data);
    addAuthAttributes(indication, m_config.realm, std::string());

    // Send indications get no response: build and fire, no waiting.
    std::vector<uint8_t> raw;
    if (!buildAuthenticatedMessage(indication, raw)) {
        LOG_ERROR("TURN: Failed to build Send indication");
        return false;
    }

    struct sockaddr_in servaddr {};
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(m_config.server_port);
    if (inet_pton(AF_INET, m_config.server_ip.c_str(), &servaddr.sin_addr) != 1) {
        return false;
    }

    const ssize_t sent = sendto(m_socket, raw.data(), raw.size(), 0,
                                reinterpret_cast<const struct sockaddr*>(&servaddr),
                                sizeof(servaddr));
    if (sent < 0) {
        LOG_ERROR("TURN: Send indication failed: " + std::string(strerror(errno)));
        return false;
    }
    return true;
}

void TurnClient::addAuthAttributes(STUNMessage& msg, const std::string& realm,
                                   const std::string& nonce,
                                   const uint8_t* /*unused1*/,
                                   const uint8_t* /*unused2*/) {
    // USERNAME (RFC 5766 section 14.3)
    std::vector<uint8_t> user(m_config.username.begin(), m_config.username.end());
    msg.addAttribute(STUNAttributeType::Username, user);

    // REALM (RFC 5766 section 14.9)
    std::vector<uint8_t> realm_vec(realm.begin(), realm.end());
    msg.addAttribute(STUNAttributeType::Realm, realm_vec);

    // NONCE (RFC 5766 section 14.10)
    std::vector<uint8_t> nonce_vec(nonce.begin(), nonce.end());
    msg.addAttribute(STUNAttributeType::Nonce, nonce_vec);
}

bool TurnClient::buildAuthenticatedMessage(const STUNMessage& msg,
                                           std::vector<uint8_t>& raw) {
    // Long-term credential mechanism (RFC 5766 section 4):
    // key = MD5(username ":" realm ":" password)
    const std::string realm = m_config.realm.empty() ? "litep2p" : m_config.realm;
    const std::string secret = m_config.username + ":" + realm + ":" + m_config.password;

    const auto key_bytes = md5(reinterpret_cast<const uint8_t*>(secret.data()),
                               secret.size());
    const std::string key(key_bytes.begin(), key_bytes.end());

    raw = msg.encode();
    return append_message_integrity(raw, key);
}

bool TurnClient::sendAuthenticatedRequest(const STUNMessage& req, STUNMessage& res) {
    std::vector<uint8_t> raw;
    if (!buildAuthenticatedMessage(req, raw)) {
        LOG_ERROR("TURN: Failed to build authenticated message");
        return false;
    }

    struct sockaddr_in servaddr {};
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(m_config.server_port);
    if (inet_pton(AF_INET, m_config.server_ip.c_str(), &servaddr.sin_addr) != 1) {
        return false;
    }

    // Retry with RTO (RFC 5389 section 7.2.1): 500ms base, doubling, 3 tries.
    int timeout_ms = 500;
    for (int attempt = 0; attempt < 3; ++attempt) {
        const ssize_t sent = sendto(m_socket, raw.data(), raw.size(), 0,
                                    reinterpret_cast<const struct sockaddr*>(&servaddr),
                                    sizeof(servaddr));
        if (sent < 0) {
            LOG_ERROR("TURN: sendto failed: " + std::string(strerror(errno)));
            return false;
        }

        char buffer[2048];
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        for (;;) {
            const int n = recvfrom(m_socket, buffer, sizeof(buffer), 0, nullptr, nullptr);
            if (n <= 0) break; // timeout or error -> retry

            std::vector<uint8_t> recv_data(buffer, buffer + n);
            STUNMessage candidate;
            if (!candidate.decode(recv_data)) continue;

            // Only accept responses matching our transaction id.
            if (candidate.getTransactionId() != req.getTransactionId()) continue;

            res = candidate;
            return true;
        }

        timeout_ms *= 2;
    }

    return false;
}

bool TurnClient::sendRequest(const STUNMessage& req, STUNMessage& res) {
    if (m_socket < 0) return false;

    struct sockaddr_in servaddr {};
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(m_config.server_port);
    if (inet_pton(AF_INET, m_config.server_ip.c_str(), &servaddr.sin_addr) != 1) {
        return false;
    }

    const std::vector<uint8_t> raw = req.encode();

    int timeout_ms = 500;
    for (int attempt = 0; attempt < 3; ++attempt) {
        const ssize_t sent = sendto(m_socket, raw.data(), raw.size(), 0,
                                    reinterpret_cast<const struct sockaddr*>(&servaddr),
                                    sizeof(servaddr));
        if (sent < 0) {
            LOG_ERROR("TURN: sendto failed: " + std::string(strerror(errno)));
            return false;
        }

        char buffer[2048];
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        for (;;) {
            const int n = recvfrom(m_socket, buffer, sizeof(buffer), 0, nullptr, nullptr);
            if (n <= 0) break;

            std::vector<uint8_t> recv_data(buffer, buffer + n);
            STUNMessage candidate;
            if (!candidate.decode(recv_data)) continue;

            // Ignore packets for other transactions (e.g., stale responses).
            if (candidate.getTransactionId() != req.getTransactionId()) continue;

            res = candidate;
            return true;
        }

        timeout_ms *= 2;
    }

    return false;
}
