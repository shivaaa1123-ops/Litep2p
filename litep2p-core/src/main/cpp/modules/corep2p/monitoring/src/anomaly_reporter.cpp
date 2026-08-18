#include "anomaly_reporter.h"

#include "telemetry.h"
#include "logger.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <iomanip>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

namespace {

int64_t system_now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

// Recursive directory creation (POSIX). Returns true on success or when the
// directory already exists. Avoids <filesystem> for maximum NDK portability.
bool mkdirs(const std::string& path) {
    if (path.empty()) return false;
    std::string cur;
    size_t i = 0;
    if (path[0] == '/') {
        cur = "/";
        i = 1;
    }
    while (i <= path.size()) {
        const size_t nxt = path.find('/', i);
        const size_t end = (nxt == std::string::npos) ? path.size() : nxt;
        if (end > i) {
            cur += path.substr(i, end - i);
            if (::mkdir(cur.c_str(), 0755) != 0 && errno != EEXIST) {
                return false;
            }
            cur += '/';
        }
        i = end + 1;
    }
    return true;
}

// Parse "http://host[:port]/path" into host, port, path. Returns false on
// malformed/non-http URLs (https is not supported by the plain-socket uploader).
bool parse_http_url(const std::string& url, std::string& host, std::string& port,
                    std::string& path) {
    if (url.rfind("http://", 0) != 0) return false;
    const std::string rest = url.substr(7);
    const size_t slash = rest.find('/');
    const std::string authority = (slash == std::string::npos) ? rest : rest.substr(0, slash);
    path = (slash == std::string::npos) ? "/" : rest.substr(slash);
    if (path.empty()) path = "/";

    const size_t colon = authority.rfind(':');
    if (colon == std::string::npos) {
        host = authority;
        port = "80";
    } else {
        host = authority.substr(0, colon);
        port = authority.substr(colon + 1);
    }
    return !host.empty();
}

} // namespace

// ============================================================================
// Singleton
// ============================================================================

AnomalyReporter& AnomalyReporter::getInstance() {
    static AnomalyReporter instance;
    return instance;
}

void AnomalyReporter::configure(const Config& cfg) {
    std::lock_guard<std::mutex> lock(m_mu);
    m_cfg = cfg;
    m_configured_at_ms = system_now_ms();
    if (!m_cfg.base_dir.empty()) {
        m_directory = m_cfg.base_dir;
        if (m_directory.back() != '/') m_directory += '/';
        m_directory += m_cfg.subdir;
    } else {
        m_directory = m_cfg.subdir;
    }
    mkdirs(m_directory);
    rotate_locked_(m_cfg.max_files);
}

bool AnomalyReporter::isEnabled() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return m_cfg.enabled;
}

void AnomalyReporter::setDeviceInfo(const std::string& json) {
    std::lock_guard<std::mutex> lock(m_mu);
    if (json.empty()) return;
    m_device_info = json;
}

void AnomalyReporter::setUptimeProvider(std::function<int64_t()> provider) {
    std::lock_guard<std::mutex> lock(m_mu);
    m_uptime_provider = std::move(provider);
}

std::string AnomalyReporter::directory() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return m_directory;
}

int AnomalyReporter::pendingFileCount() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return static_cast<int>(list_pending_locked_().size());
}

void AnomalyReporter::report(const Event& ev) {
    std::string dir;
    bool include_telemetry = true;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        if (!m_cfg.enabled || m_directory.empty()) return;
        dir = m_directory;
        include_telemetry = m_cfg.include_telemetry;
    }

    const int64_t now_ms = system_now_ms();
    int64_t uptime_ms = 0;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        if (m_uptime_provider) {
            uptime_ms = m_uptime_provider();
        } else {
            uptime_ms = now_ms - m_configured_at_ms;
        }
    }

    std::string telemetry_json;
    if (include_telemetry) {
        try {
            telemetry_json = Telemetry::getInstance().snapshot_json("anomaly");
        } catch (...) {
            telemetry_json.clear();
        }
    }

    const std::string incident = build_incident_(ev, now_ms, uptime_ms, telemetry_json);
    std::string path;
    if (!write_incident_(incident, path)) {
        nativeLog("AnomalyReporter: failed to write incident (" + ev.type + ")");
        return;
    }
    nativeLog("AnomalyReporter: incident written (" + ev.type + "): " + path);
}

// ============================================================================
// Incident JSON
// ============================================================================

std::string AnomalyReporter::build_incident_(const Event& ev, int64_t now_ms,
                                             int64_t uptime_ms,
                                             const std::string& telemetry_json) {
    std::lock_guard<std::mutex> lock(m_mu);
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"schema\": \"litep2p-anomaly/1\",\n";
    oss << "  \"incident_id\": \"" << random_hex_(12) << "\",\n";
    oss << "  \"timestamp_utc\": \"" << iso8601_utc_(now_ms) << "\",\n";
    oss << "  \"engine_uptime_ms\": " << uptime_ms << ",\n";
    oss << "  \"engine_version\": \"" << json_escape_(m_cfg.engine_version) << "\",\n";
    oss << "  \"local_peer_id\": \"" << json_escape_(m_cfg.peer_id) << "\",\n";
    oss << "  \"event_type\": \"" << json_escape_(ev.type) << "\",\n";
    oss << "  \"peer_id\": \"" << json_escape_(ev.peer_id) << "\",\n";
    oss << "  \"network_id\": \"" << json_escape_(ev.network_id) << "\",\n";
    oss << "  \"detail\": \"" << json_escape_(ev.detail) << "\",\n";
    if (!ev.extras.empty()) {
        oss << "  \"extras\": {\n";
        for (size_t i = 0; i < ev.extras.size(); ++i) {
            oss << "    \"" << json_escape_(ev.extras[i].first) << "\": \""
                << json_escape_(ev.extras[i].second) << "\""
                << (i + 1 < ev.extras.size() ? "," : "") << "\n";
        }
        oss << "  },\n";
    }
    oss << "  \"device\": " << (m_device_info.empty() ? "{}" : m_device_info) << ",\n";
    if (!telemetry_json.empty()) {
        oss << "  \"telemetry\": " << telemetry_json << ",\n";
    }
    oss << "  \"reporter\": \"AnomalyReporter\"\n";
    oss << "}\n";
    return oss.str();
}

bool AnomalyReporter::write_incident_(const std::string& json, std::string& out_path) {
    std::lock_guard<std::mutex> lock(m_mu);
    if (m_directory.empty()) return false;
    if (!mkdirs(m_directory)) return false;

    const int64_t now_ms = system_now_ms();
    const time_t t = static_cast<time_t>(now_ms / 1000);
    std::tm tmv{};
#if defined(_WIN32)
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif
    char stamp[64];
    std::strftime(stamp, sizeof(stamp), "%Y%m%d_%H%M%S", &tmv);

    ++m_seq;
    out_path = m_directory + "/anomaly_" + stamp + "_" + std::to_string(m_seq) + ".json";

    FILE* f = std::fopen(out_path.c_str(), "wb");
    if (!f) return false;
    const bool ok = std::fwrite(json.data(), 1, json.size(), f) == json.size();
    std::fclose(f);
    if (!ok) {
        std::remove(out_path.c_str());
        return false;
    }
    rotate_locked_(m_cfg.max_files);
    return true;
}

void AnomalyReporter::rotate_locked_(int max_files) {
    if (max_files <= 0 || m_directory.empty()) return;
    std::vector<std::string> files;
    DIR* d = ::opendir(m_directory.c_str());
    if (!d) return;
    struct dirent* e = nullptr;
    while ((e = ::readdir(d)) != nullptr) {
        const std::string name = e->d_name;
        if (name.rfind("anomaly_", 0) == 0) {
            files.push_back(m_directory + "/" + name);
        }
    }
    ::closedir(d);
    std::sort(files.begin(), files.end());
    while (static_cast<int>(files.size()) > max_files) {
        const std::string victim = files.front();
        files.erase(files.begin());
        std::remove(victim.c_str());
    }
}


// ============================================================================
// Upload (best-effort plain HTTP POST; https deferred to the TLS phase)
// ============================================================================

void AnomalyReporter::tick() {
    bool enabled = false;
    std::string dir;
    int interval_ms = 300000;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        enabled = m_cfg.enabled && m_cfg.upload_enabled && !m_cfg.upload_url.empty();
        dir = m_directory;
        interval_ms = m_cfg.upload_interval_ms > 0 ? m_cfg.upload_interval_ms : 300000;
    }
    if (!enabled || dir.empty()) return;

    // Rate-limit upload attempts to the configured interval.
    {
        std::lock_guard<std::mutex> lock(m_mu);
        const int64_t now = system_now_ms();
        if (m_last_upload_attempt_ms > 0 && now - m_last_upload_attempt_ms < interval_ms) {
            return;
        }
        m_last_upload_attempt_ms = now;
    }

    std::vector<std::string> pending;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        pending = list_pending_locked_();
    }
    for (const auto& path : pending) {
        if (upload_file_(path)) {
            std::remove(path.c_str());
            nativeLog("AnomalyReporter: uploaded + removed " + path);
        } else {
            nativeLog("AnomalyReporter: upload failed for " + path + " (will retry)");
        }
    }
}

std::vector<std::string> AnomalyReporter::list_pending_locked_() const {
    std::vector<std::string> files;
    if (m_directory.empty()) return files;
    DIR* d = ::opendir(m_directory.c_str());
    if (!d) return files;
    struct dirent* e = nullptr;
    while ((e = ::readdir(d)) != nullptr) {
        const std::string name = e->d_name;
        if (name.rfind("anomaly_", 0) == 0) {
            files.push_back(m_directory + "/" + name);
        }
    }
    ::closedir(d);
    std::sort(files.begin(), files.end());
    return files;
}

bool AnomalyReporter::upload_file_(const std::string& path) {
    std::string url;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        url = m_cfg.upload_url;
    }

    std::string host, port, req_path;
    if (!parse_http_url(url, host, port, req_path)) return false;

    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    std::vector<char> body;
    char buf[4096];
    size_t n = 0;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) {
        body.insert(body.end(), buf, buf + n);
    }
    std::fclose(f);
    if (body.empty()) return false;

    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0 || !res) {
        return false;
    }

    int sock = -1;
    for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
        sock = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) continue;
        // 8s connect/IO timeouts so a dead collector never blocks the engine.
        timeval tv{8, 0};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (::connect(sock, ai->ai_addr, ai->ai_addrlen) == 0) break;
        ::close(sock);
        sock = -1;
    }
    ::freeaddrinfo(res);
    if (sock < 0) return false;

    std::ostringstream req;
    req << "POST " << req_path << " HTTP/1.1\r\n";
    req << "Host: " << host << ":" << port << "\r\n";
    req << "Content-Type: application/json\r\n";
    req << "Content-Length: " << body.size() << "\r\n";
    req << "Connection: close\r\n";
    req << "X-LiteP2P-Anomaly: 1\r\n";
    req << "\r\n";
    const std::string head = req.str();
    const bool sent_head = ::send(sock, head.data(), head.size(), 0) == static_cast<ssize_t>(head.size());
    bool sent_body = false;
    if (sent_head) {
        sent_body = ::send(sock, body.data(), body.size(), 0) == static_cast<ssize_t>(body.size());
    }

    std::string response;
    char rbuf[1024];
    ssize_t rn = 0;
    while ((rn = ::recv(sock, rbuf, sizeof(rbuf) - 1, 0)) > 0) {
        rbuf[rn] = '\0';
        response += rbuf;
    }
    ::close(sock);

    if (!sent_head || !sent_body) return false;
    // Accept any HTTP 2xx status.
    const bool ok = response.rfind("HTTP/1.", 0) == 0 && response.size() > 12 &&
                    response[9] == '2';
    return ok;
}

// ============================================================================
// Helpers
// ============================================================================

std::string AnomalyReporter::iso8601_utc_(int64_t ms) {
    const time_t t = static_cast<time_t>(ms / 1000);
    std::tm tmv{};
#if defined(_WIN32)
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tmv);
    std::ostringstream oss;
    oss << buf << "." << std::setw(3) << std::setfill('0') << static_cast<int>(ms % 1000) << "Z";
    return oss.str();
}

std::string AnomalyReporter::random_hex_(size_t bytes) {
    static thread_local std::mt19937_64 rng(std::random_device{}());
    std::ostringstream oss;
    oss << std::hex;
    for (size_t i = 0; i < bytes; ++i) {
        oss << std::setw(2) << std::setfill('0') << static_cast<unsigned>(rng() & 0xFF);
    }
    return oss.str();
}

std::string AnomalyReporter::json_escape_(const std::string& s) {
    std::ostringstream oss;
    for (const char c : s) {
        switch (c) {
            case '"': oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\n': oss << "\\n"; break;
            case '\r': oss << "\\r"; break;
            case '\t': oss << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char tmp[8];
                    std::snprintf(tmp, sizeof(tmp), "\\u%04x", c);
                    oss << tmp;
                } else {
                    oss << c;
                }
        }
    }
    return oss.str();
}

