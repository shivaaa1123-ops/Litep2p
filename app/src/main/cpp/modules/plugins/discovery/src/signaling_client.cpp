#include "../include/signaling_client.h"
#include "../../../corep2p/core/include/logger.h"

#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <sstream>
#include <random>
#include <cstring>
#include <iostream>
#include <algorithm>
#include <chrono>

namespace {

std::string errno_string(int err) {
    std::ostringstream oss;
    oss << err;
    const char* s = std::strerror(err);
    if (s) {
        oss << " (" << s << ")";
    }
    return oss.str();
}

// Best-effort: prevent SIGPIPE on send() to a closed socket.
// - Apple platforms: SO_NOSIGPIPE
// - Linux/Android: MSG_NOSIGNAL (per-send)
void set_no_sigpipe_best_effort(int fd) {
#if defined(SO_NOSIGPIPE)
    int one = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)) != 0) {
        // Non-fatal; send() may still fail with EPIPE.
    }
#else
    (void)fd;
#endif
}

int send_flags_no_sigpipe() {
#if defined(MSG_NOSIGNAL)
    return MSG_NOSIGNAL;
#else
    return 0;
#endif
}

bool send_all(int fd, const void* buf, size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    size_t total = 0;
    while (total < len) {
        const ssize_t n = ::send(fd, p + total, len - total, send_flags_no_sigpipe());
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (n == 0) {
            return false;
        }
        total += static_cast<size_t>(n);
    }
    return true;
}

bool connect_with_timeout(int fd, const sockaddr* sa, socklen_t salen, int timeout_ms, std::string* out_err) {
    const int old_flags = fcntl(fd, F_GETFL, 0);
    if (old_flags < 0) {
        if (out_err) *out_err = "fcntl(F_GETFL) failed: " + errno_string(errno);
        return false;
    }
    if (fcntl(fd, F_SETFL, old_flags | O_NONBLOCK) < 0) {
        if (out_err) *out_err = "fcntl(F_SETFL,O_NONBLOCK) failed: " + errno_string(errno);
        return false;
    }

    int res = ::connect(fd, sa, salen);
    if (res == 0) {
        // Connected immediately.
        (void)fcntl(fd, F_SETFL, old_flags);
        return true;
    }
    if (res < 0 && errno != EINPROGRESS) {
        if (out_err) *out_err = "connect() failed: " + errno_string(errno);
        (void)fcntl(fd, F_SETFL, old_flags);
        return false;
    }

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);

    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    for (;;) {
        const int sel = ::select(fd + 1, nullptr, &wfds, nullptr, &tv);
        if (sel < 0) {
            if (errno == EINTR) {
                // Retry with the *remaining* timeout is hard without monotonic bookkeeping.
                // Keep it simple: treat EINTR as a retry without shrinking tv too aggressively.
                continue;
            }
            if (out_err) *out_err = "select() failed: " + errno_string(errno);
            (void)fcntl(fd, F_SETFL, old_flags);
            return false;
        }
        if (sel == 0) {
            if (out_err) *out_err = "connect() timed out";
            (void)fcntl(fd, F_SETFL, old_flags);
            return false;
        }

        int so_error = 0;
        socklen_t slen = sizeof(so_error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &slen) != 0) {
            if (out_err) *out_err = "getsockopt(SO_ERROR) failed: " + errno_string(errno);
            (void)fcntl(fd, F_SETFL, old_flags);
            return false;
        }
        if (so_error != 0) {
            if (out_err) *out_err = "connect() failed after select: " + errno_string(so_error);
            (void)fcntl(fd, F_SETFL, old_flags);
            return false;
        }

        (void)fcntl(fd, F_SETFL, old_flags);
        return true;
    }
}

bool recvExact(int fd, void* out, size_t len) {
    uint8_t* p = static_cast<uint8_t*>(out);
    size_t total = 0;
    while (total < len) {
        const ssize_t n = ::recv(fd, p + total, len - total, 0);
        if (n <= 0) {
            return false;
        }
        total += static_cast<size_t>(n);
    }
    return true;
}

bool recvExactWithSelect(int fd, void* out, size_t len, const std::atomic<bool>& running) {
    uint8_t* p = static_cast<uint8_t*>(out);
    size_t total = 0;
    while (total < len) {
        if (!running.load(std::memory_order_acquire)) {
            return false;
        }

        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(fd, &read_fds);

        timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        const int ready = select(fd + 1, &read_fds, nullptr, nullptr, &tv);
        if (ready == 0) {
            // Timeout - allow periodic liveness checks.
            continue;
        }
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }

        const ssize_t n = ::recv(fd, p + total, len - total, 0);
        if (n == 0) {
            return false;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            return false;
        }
        total += static_cast<size_t>(n);
    }
    return true;
}

} // namespace

// Simple JSON construction to avoid dependency on nlohmann/json in this low-level file if desired,
// but since the project uses nlohmann/json elsewhere, we could use it. 
// For strict "no library" request, I'll use string formatting for simple JSON.

SignalingClient::SignalingClient() : m_socket(-1), m_running(false), m_connected(false) {
}

SignalingClient::~SignalingClient() {
    disconnect();
}

bool SignalingClient::connect(const std::string& url) {
    if (m_connected) return true;

    // Parse URL (ws://ip:port)
    std::string host;
    int port = 80;
    std::string path = "/";
    
    std::string clean_url = url;
    if (clean_url.find("ws://") == 0) {
        clean_url = clean_url.substr(5);
    }
    
    size_t colon_pos = clean_url.find(':');
    size_t slash_pos = clean_url.find('/');
    
    if (colon_pos != std::string::npos) {
        host = clean_url.substr(0, colon_pos);
        if (slash_pos != std::string::npos) {
            port = std::stoi(clean_url.substr(colon_pos + 1, slash_pos - colon_pos - 1));
            path = clean_url.substr(slash_pos);
        } else {
            port = std::stoi(clean_url.substr(colon_pos + 1));
        }
    } else {
        if (slash_pos != std::string::npos) {
            host = clean_url.substr(0, slash_pos);
            path = clean_url.substr(slash_pos);
        } else {
            host = clean_url;
        }
    }

    m_host = host;
    m_port = port;

    LOG_INFO("Signaling: Connecting to " + host + ":" + std::to_string(port) + " path=" + path);

    // Resolve using getaddrinfo (handles IPv4/IPv6 and numeric hosts reliably on Android).
    addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    addrinfo* results = nullptr;
    const std::string port_str = std::to_string(port);
    const int gai_rc = ::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &results);
    if (gai_rc != 0 || results == nullptr) {
        LOG_ERROR(std::string("Signaling: getaddrinfo failed for host=") + host + ":" + port_str + " err=" + (gai_rc != 0 ? gai_strerror(gai_rc) : "no results"));
        return false;
    }

    int connected_fd = -1;
    std::string last_err;
    for (addrinfo* ai = results; ai != nullptr; ai = ai->ai_next) {
        const int fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            last_err = "socket() failed: " + errno_string(errno);
            continue;
        }
        set_no_sigpipe_best_effort(fd);

        std::string err;
        if (!connect_with_timeout(fd, ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen), 5000, &err)) {
            last_err = err;
            ::close(fd);
            continue;
        }

        connected_fd = fd;
        break;
    }

    ::freeaddrinfo(results);

    if (connected_fd < 0) {
        LOG_ERROR("Signaling: TCP connect failed: " + (last_err.empty() ? std::string("unknown") : last_err));
        return false;
    }

    m_socket = connected_fd;

    // 4. WebSocket Handshake
    if (!performHandshake(host, port, path)) {
        LOG_ERROR("Signaling: Handshake failed (host=" + host + " port=" + std::to_string(port) + " path=" + path + ")");
        close(m_socket);
        return false;
    }

    LOG_INFO("Signaling: Connected successfully");
    m_connected = true;
    m_running = true;
    m_event_loop_mode = false;
    m_thread = std::thread(&SignalingClient::receiveLoop, this);

    return true;
}

int SignalingClient::connectEventLoop(const std::string& url) {
    if (m_connected) return m_socket;

    // Parse URL (ws://ip:port)
    std::string host;
    int port = 80;
    std::string path = "/";
    
    std::string clean_url = url;
    if (clean_url.find("ws://") == 0) {
        clean_url = clean_url.substr(5);
    }
    
    size_t colon_pos = clean_url.find(':');
    size_t slash_pos = clean_url.find('/');
    
    if (colon_pos != std::string::npos) {
        host = clean_url.substr(0, colon_pos);
        if (slash_pos != std::string::npos) {
            port = std::stoi(clean_url.substr(colon_pos + 1, slash_pos - colon_pos - 1));
            path = clean_url.substr(slash_pos);
        } else {
            port = std::stoi(clean_url.substr(colon_pos + 1));
        }
    } else {
        if (slash_pos != std::string::npos) {
            host = clean_url.substr(0, slash_pos);
            path = clean_url.substr(slash_pos);
        } else {
            host = clean_url;
        }
    }

    m_host = host;
    m_port = port;

    LOG_INFO("Signaling: Connecting (event-loop mode) to " + host + ":" + std::to_string(port) + " path=" + path);

    addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    addrinfo* results = nullptr;
    const std::string port_str = std::to_string(port);
    const int gai_rc = ::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &results);
    if (gai_rc != 0 || results == nullptr) {
        LOG_ERROR(std::string("Signaling: getaddrinfo failed for host=") + host + ":" + port_str + " err=" + (gai_rc != 0 ? gai_strerror(gai_rc) : "no results"));
        return -1;
    }

    int connected_fd = -1;
    std::string last_err;
    for (addrinfo* ai = results; ai != nullptr; ai = ai->ai_next) {
        const int fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            last_err = "socket() failed: " + errno_string(errno);
            continue;
        }
        set_no_sigpipe_best_effort(fd);

        std::string err;
        if (!connect_with_timeout(fd, ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen), 5000, &err)) {
            last_err = err;
            ::close(fd);
            continue;
        }

        connected_fd = fd;
        break;
    }

    ::freeaddrinfo(results);

    if (connected_fd < 0) {
        LOG_ERROR("Signaling: TCP connect failed (event-loop mode): " + (last_err.empty() ? std::string("unknown") : last_err));
        return -1;
    }

    m_socket = connected_fd;

    // WebSocket Handshake (blocking, but should be fast after connect)
    if (!performHandshake(host, port, path)) {
        LOG_ERROR("Signaling: Handshake failed (event-loop mode)");
        close(m_socket);
        m_socket = -1;
        return -1;
    }

    // Set non-blocking for event loop mode
    const int flags = fcntl(m_socket, F_GETFL, 0);
    if (flags >= 0) {
        if (fcntl(m_socket, F_SETFL, flags | O_NONBLOCK) < 0) {
            LOG_WARN("Signaling: Failed to set O_NONBLOCK for event-loop mode: " + errno_string(errno));
        }
    } else {
        LOG_WARN("Signaling: Failed to get socket flags for event-loop mode: " + errno_string(errno));
    }

    LOG_INFO("Signaling: Connected successfully (event-loop mode)");
    m_connected = true;
    m_running = true;
    m_event_loop_mode = true;
    // No thread spawned - caller polls and calls processIncoming()

    return m_socket;
}

void SignalingClient::disconnect() {
    m_running = false;
    if (m_socket >= 0) {
        ::shutdown(m_socket, SHUT_RDWR);
        close(m_socket);
        m_socket = -1;
    }
    if (!m_event_loop_mode && m_thread.joinable()) {
        m_thread.join();
    }
    m_connected = false;
}

bool SignalingClient::performHandshake(const std::string& host, int port, const std::string& path) {
    std::string key = generateWebSocketKey();
    
    std::stringstream ss;
    ss << "GET " << path << " HTTP/1.1\r\n";
    ss << "Host: " << host << ":" << port << "\r\n";
    ss << "Upgrade: websocket\r\n";
    ss << "Connection: Upgrade\r\n";
    ss << "Sec-WebSocket-Key: " << key << "\r\n";
    ss << "Sec-WebSocket-Version: 13\r\n";
    ss << "\r\n";
    
    std::string request = ss.str();
    if (!send_all(m_socket, request.data(), request.size())) {
        LOG_ERROR("Signaling: Handshake send failed: " + errno_string(errno));
        return false;
    }

    // Read response (may arrive in multiple TCP chunks)
    std::string response;
    response.reserve(2048);
    for (;;) {
        char buffer[1024];
        const int n = recv(m_socket, buffer, sizeof(buffer) - 1, 0);
        if (n <= 0) {
            if (n < 0) {
                LOG_ERROR("Signaling: Handshake recv failed: " + errno_string(errno));
            }
            return false;
        }
        buffer[n] = '\0';
        response.append(buffer);

        // HTTP headers end with CRLF CRLF
        if (response.find("\r\n\r\n") != std::string::npos) {
            break;
        }

        // Safety: avoid unbounded growth if the server is misbehaving.
        if (response.size() > 64 * 1024) {
            LOG_ERROR("Signaling: Handshake response too large");
            return false;
        }
    }

    if (response.find("101") == std::string::npos || response.find("Switching Protocols") == std::string::npos) {
        // Log only the first line to avoid huge logs.
        const size_t eol = response.find("\r\n");
        const std::string first_line = (eol == std::string::npos) ? response : response.substr(0, eol);
        LOG_ERROR("Signaling: Invalid handshake response (first line): " + first_line);
        return false;
    }
    
    return true;
}

void SignalingClient::sendRegister(const std::string& peer_id) {
    // {"type": "REGISTER", "peer_id": "..."}
    std::string json = "{\"type\": \"REGISTER\", \"peer_id\": \"" + peer_id + "\"}";
    sendFrame(json);
}

void SignalingClient::sendRegister(const std::string& peer_id, const std::string& network_id) {
    // {"type": "REGISTER", "peer_id": "...", "network_id": "..."}
    // Note: network_id should be escaped if it contains quotes.
    std::string json = "{\"type\": \"REGISTER\", \"peer_id\": \"" + peer_id +
                      "\", \"network_id\": \"" + network_id + "\"}";
    sendFrame(json);
}

void SignalingClient::sendSignal(const std::string& target_peer_id, const std::string& payload) {
    // {"type": "SIGNAL", "target_peer_id": "...", "payload": "..."}
    // Note: Payload should be escaped if it contains quotes, but for now assuming simple base64 or safe string
    std::string json = "{\"type\": \"SIGNAL\", \"target_peer_id\": \"" + target_peer_id + "\", \"payload\": \"" + payload + "\"}";
    sendFrame(json);
}

void SignalingClient::sendListPeers() {
    // {"type": "LIST_PEERS"}
    sendFrame("{\"type\": \"LIST_PEERS\"}");
}

void SignalingClient::sendUpdateNetworkId(const std::string& network_id) {
    // {"type": "UPDATE", "network_id": "..."}
    // Note: network_id should be escaped if it contains quotes.
    std::string json = "{\"type\": \"UPDATE\", \"network_id\": \"" + network_id + "\"}";
    sendFrame(json);
}

bool SignalingClient::sendFrame(const std::string& data, uint8_t opcode) {
    if (!m_connected) return false;

    std::vector<uint8_t> frame;
    
    // Byte 0: FIN (1) + Opcode
    frame.push_back(0x80 | opcode);
    
    // Byte 1: Mask (1) + Length
    size_t len = data.length();
    if (len <= 125) {
        frame.push_back(0x80 | static_cast<uint8_t>(len));
    } else if (len <= 65535) {
        frame.push_back(0x80 | 126);
        frame.push_back((len >> 8) & 0xFF);
        frame.push_back(len & 0xFF);
    } else {
        frame.push_back(0x80 | 127);
        // 64-bit length (only using lower 32 bits for simplicity)
        for (int i = 0; i < 4; i++) frame.push_back(0);
        frame.push_back((len >> 24) & 0xFF);
        frame.push_back((len >> 16) & 0xFF);
        frame.push_back((len >> 8) & 0xFF);
        frame.push_back(len & 0xFF);
    }
    
    // Masking Key (4 bytes)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    uint8_t mask[4];
    for (int i = 0; i < 4; i++) {
        mask[i] = static_cast<uint8_t>(dis(gen));
        frame.push_back(mask[i]);
    }
    
    // Payload (Masked)
    for (size_t i = 0; i < len; i++) {
        frame.push_back(static_cast<uint8_t>(static_cast<uint8_t>(data[i]) ^ mask[i % 4]));
    }
    
    std::lock_guard<std::mutex> lock(m_mutex);
    if (send(m_socket, frame.data(), frame.size(), send_flags_no_sigpipe()) < 0) {
        LOG_ERROR("Signaling: Send failed: " + errno_string(errno));
        m_connected = false;
        m_running = false;
        if (m_socket >= 0) {
            ::shutdown(m_socket, SHUT_RDWR);
        }
        return false;
    }
    
    return true;
}

void SignalingClient::processIncoming() {
    if (m_socket < 0 || !m_running) return;
    
    // Read one WebSocket frame (non-blocking)
    uint8_t header[2];
    ssize_t n = recv(m_socket, header, sizeof(header), MSG_PEEK);
    if (n <= 0) {
        if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            m_connected = false;
            m_running = false;
        }
        return;
    }
    
    // Have data, read the frame
    if (!recvExact(m_socket, header, sizeof(header))) {
        m_connected = false;
        m_running = false;
        return;
    }

    const bool fin = (header[0] & 0x80) != 0;
    const uint8_t opcode = static_cast<uint8_t>(header[0] & 0x0F);
    const bool masked = (header[1] & 0x80) != 0;
    uint64_t payload_len = static_cast<uint64_t>(header[1] & 0x7F);

    if (payload_len == 126) {
        uint8_t len_bytes[2];
        if (!recvExact(m_socket, len_bytes, sizeof(len_bytes))) return;
        payload_len = (static_cast<uint64_t>(len_bytes[0]) << 8) | static_cast<uint64_t>(len_bytes[1]);
    } else if (payload_len == 127) {
        uint8_t len_bytes[8];
        if (!recvExact(m_socket, len_bytes, sizeof(len_bytes))) return;
        payload_len = 0;
        for (int i = 0; i < 8; i++) {
            payload_len = (payload_len << 8) | static_cast<uint64_t>(len_bytes[i]);
        }
    }

    uint8_t mask_key[4] = {0, 0, 0, 0};
    if (masked) {
        if (!recvExact(m_socket, mask_key, sizeof(mask_key))) return;
    }

    if (payload_len > (64ULL * 1024ULL * 1024ULL)) {
        m_running = false;
        return;
    }

    std::vector<uint8_t> payload(static_cast<size_t>(payload_len));
    if (payload_len > 0) {
        if (!recvExact(m_socket, payload.data(), static_cast<size_t>(payload_len))) return;
    }

    if (masked) {
        for (size_t i = 0; i < payload.size(); ++i) {
            payload[i] = static_cast<uint8_t>(payload[i] ^ mask_key[i % 4]);
        }
    }

    if (opcode == 0x8) { // Close
        m_running = false;
        m_connected = false;
        return;
    }

    if (opcode == 0x9) { // Ping
        std::string pong_payload(payload.begin(), payload.end());
        sendFrame(pong_payload, 0xA);
        return;
    }

    if (opcode == 0xA) { // Pong
        return;
    }

    if (fin && (opcode == 0x1 || opcode == 0x2)) {
        // Complete text/binary frame
        if (opcode == 0x1 && m_callback) {
            std::string message(payload.begin(), payload.end());
            m_callback(message);
        }
    }
    // Note: Fragmented frames not fully supported in event-loop mode for simplicity
}

void SignalingClient::receiveLoop() {
    std::string fragmented_message;
    bool expecting_continuation = false;
    uint8_t initial_opcode = 0;

    auto last_activity = std::chrono::steady_clock::now();
    auto last_ping_sent = last_activity;
    bool awaiting_pong = false;

    constexpr auto kPingInterval = std::chrono::seconds(10);
    constexpr auto kPongTimeout = std::chrono::seconds(10);

    while (m_running) {
        const auto now = std::chrono::steady_clock::now();

        // Client-side keepalive: send a ping if the connection is idle.
        if (m_connected) {
            if (!awaiting_pong && (now - last_activity) >= kPingInterval) {
                // Empty ping payload is valid.
                if (sendFrame("", 0x9)) {
                    awaiting_pong = true;
                    last_ping_sent = now;
                }
            }
            if (awaiting_pong && (now - last_ping_sent) >= kPongTimeout) {
                LOG_WARN("Signaling: Pong timeout - treating connection as dead");
                break;
            }
        }

        uint8_t header[2];
        if (!recvExactWithSelect(m_socket, header, sizeof(header), m_running)) {
            break;
        }

        last_activity = std::chrono::steady_clock::now();

        const bool fin = (header[0] & 0x80) != 0;
        const uint8_t opcode = static_cast<uint8_t>(header[0] & 0x0F);
        const bool masked = (header[1] & 0x80) != 0;
        uint64_t payload_len = static_cast<uint64_t>(header[1] & 0x7F);

        if (payload_len == 126) {
            uint8_t len_bytes[2];
            if (!recvExactWithSelect(m_socket, len_bytes, sizeof(len_bytes), m_running)) {
                break;
            }
            payload_len = (static_cast<uint64_t>(len_bytes[0]) << 8) | static_cast<uint64_t>(len_bytes[1]);
        } else if (payload_len == 127) {
            uint8_t len_bytes[8];
            if (!recvExactWithSelect(m_socket, len_bytes, sizeof(len_bytes), m_running)) {
                break;
            }
            payload_len = 0;
            for (int i = 0; i < 8; i++) {
                payload_len = (payload_len << 8) | static_cast<uint64_t>(len_bytes[i]);
            }
        }

        // If server sends masked frames (non-compliant, but handle defensively)
        uint8_t mask_key[4] = {0, 0, 0, 0};
        if (masked) {
            if (!recvExactWithSelect(m_socket, mask_key, sizeof(mask_key), m_running)) {
                break;
            }
        }

        // Guard against absurd sizes.
        if (payload_len > (64ULL * 1024ULL * 1024ULL)) {
            LOG_WARN("Signaling: Refusing oversized websocket frame: " + std::to_string(payload_len));
            m_running = false;
            break;
        }

        std::vector<uint8_t> payload(static_cast<size_t>(payload_len));
        if (payload_len > 0) {
            if (!recvExactWithSelect(m_socket, payload.data(), static_cast<size_t>(payload_len), m_running)) {
                break;
            }
        }

        if (masked) {
            for (size_t i = 0; i < payload.size(); ++i) {
                payload[i] = static_cast<uint8_t>(payload[i] ^ mask_key[i % 4]);
            }
        }

        if (opcode == 0x8) { // Close
            LOG_INFO("Signaling: Server closed connection");
            m_running = false;
            break;
        }

        if (opcode == 0x9) { // Ping
            // Respond with Pong.
            std::string pong_payload(payload.begin(), payload.end());
            sendFrame(pong_payload, 0xA);
            continue;
        }

        if (opcode == 0xA) { // Pong
            awaiting_pong = false;
            continue;
        }

        if (opcode == 0x1 || opcode == 0x2 || opcode == 0x0) {
            // Text (0x1), Binary (0x2), Continuation (0x0)
            if (opcode == 0x1 || opcode == 0x2) {
                if (expecting_continuation) {
                    // Previous message never finished; drop it.
                    fragmented_message.clear();
                    expecting_continuation = false;
                    initial_opcode = 0;
                }

                initial_opcode = opcode;
                fragmented_message.assign(payload.begin(), payload.end());
                expecting_continuation = !fin;
            } else {
                // Continuation
                if (!expecting_continuation) {
                    // Unexpected continuation, ignore.
                    continue;
                }
                fragmented_message.append(payload.begin(), payload.end());
                expecting_continuation = !fin;
            }

            if (!expecting_continuation) {
                if (initial_opcode == 0x1) {
                    // Only dispatch text frames to the callback.
                    if (m_callback) {
                        m_callback(fragmented_message);
                    }
                }
                fragmented_message.clear();
                initial_opcode = 0;
            }
            continue;
        }

        // Ignore other opcodes.
    }

    m_connected = false;
    m_running = false;
    LOG_INFO("Signaling: Receive loop ended");
}

void SignalingClient::setMessageCallback(MessageCallback callback) {
    m_callback = callback;
}

bool SignalingClient::isConnected() const {
    return m_connected;
}

std::string SignalingClient::generateWebSocketKey() {
    std::vector<uint8_t> nonce(16);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (auto& b : nonce) {
        b = static_cast<uint8_t>(dis(gen));
    }
    return base64Encode(nonce);
}

std::string SignalingClient::base64Encode(const std::vector<uint8_t>& data) {
    static const char* kEncodeTable =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);

    size_t i = 0;
    while (i + 2 < data.size()) {
        const uint32_t n = (static_cast<uint32_t>(data[i]) << 16) |
                           (static_cast<uint32_t>(data[i + 1]) << 8) |
                           static_cast<uint32_t>(data[i + 2]);
        out.push_back(kEncodeTable[(n >> 18) & 0x3F]);
        out.push_back(kEncodeTable[(n >> 12) & 0x3F]);
        out.push_back(kEncodeTable[(n >> 6) & 0x3F]);
        out.push_back(kEncodeTable[n & 0x3F]);
        i += 3;
    }

    const size_t rem = data.size() - i;
    if (rem == 1) {
        const uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        out.push_back(kEncodeTable[(n >> 18) & 0x3F]);
        out.push_back(kEncodeTable[(n >> 12) & 0x3F]);
        out.push_back('=');
        out.push_back('=');
    } else if (rem == 2) {
        const uint32_t n = (static_cast<uint32_t>(data[i]) << 16) |
                           (static_cast<uint32_t>(data[i + 1]) << 8);
        out.push_back(kEncodeTable[(n >> 18) & 0x3F]);
        out.push_back(kEncodeTable[(n >> 12) & 0x3F]);
        out.push_back(kEncodeTable[(n >> 6) & 0x3F]);
        out.push_back('=');
    }

    return out;
}
