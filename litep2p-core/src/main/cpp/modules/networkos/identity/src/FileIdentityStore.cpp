// FileIdentityStore.cpp — Network OS Phase 1 identity persistence.
//
// Persists the stable PeerID to `files_dir/identity.json` with an atomic
// tmp+rename write. The identity is create-once: loadOrCreate never replaces
// an existing peer id, so PeerID is identical across restarts and IP changes
// (master doc §12). This closes the Phase 0 gap where the random-fallback
// device id was regenerated every process run.

#include "networkos/IIdentityStore.h"

#include "device_utils.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <system_error>

namespace networkos {

namespace {

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

bool file_exists(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return in.good();
}

bool write_atomic(const std::string& path, const std::string& content) {
    const std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) return false;
        out << content;
        out.flush();
        if (!out.good()) return false;
    }
    if (std::rename(tmp.c_str(), path.c_str()) != 0) return false;
    return true;
}

class FileIdentityStore : public IIdentityStore {
public:
    explicit FileIdentityStore(std::string files_dir)
        : m_files_dir(std::move(files_dir)), m_path(m_files_dir + "/identity.json") {}

    Result load(Identity& out) override {
        std::lock_guard<std::mutex> lock(m_mu);
        if (m_loaded) {
            out = m_identity;
            return m_identity.valid() ? Result::kOk : Result::kNotFound;
        }
        if (!load_locked_()) return Result::kNotFound;
        out = m_identity;
        return m_identity.valid() ? Result::kOk : Result::kNotFound;
    }

    Result create(const std::string& preferred, Identity& out) override {
        std::lock_guard<std::mutex> lock(m_mu);
        // Never regenerate an existing identity.
        if (!m_loaded) load_locked_();
        if (m_identity.valid()) {
            out = m_identity;
            return Result::kOk;
        }
        std::string id = preferred;
        if (id.empty()) id = get_persistent_device_id();
        if (id.empty()) return Result::kIo;

        Identity ident;
        ident.peer_id = id;
        ident.keystore_path = m_files_dir + "/keystore";
        ident.created_at_ms = now_ms();
        if (!persist_locked_(ident)) return Result::kIo;
        m_identity = std::move(ident);
        m_loaded = true;
        out = m_identity;
        return Result::kOk;
    }

    Result loadOrCreate(const std::string& preferred, Identity& out) override {
        Result rc = load(out);
        if (rc == Result::kOk) return rc;
        return create(preferred, out);
    }

    Result exportJson(std::string& out_json) const override {
        std::lock_guard<std::mutex> lock(m_mu);
        out_json = "{";
        out_json += "\"peer_id\":\"" + m_identity.peer_id + "\",";
        out_json += "\"keystore_path\":\"" + m_identity.keystore_path + "\",";
        out_json += "\"created_at_ms\":" + std::to_string(m_identity.created_at_ms);
        out_json += "}";
        return Result::kOk;
    }

private:
    bool load_locked_() {
        std::ifstream in(m_path, std::ios::binary);
        if (!in.good()) return false;
        std::string content((std::istreambuf_iterator<char>(in)),
                            std::istreambuf_iterator<char>());
        m_loaded = true;
        if (content.empty()) return false;
        // Simple line format: peer_id\nkeystore_path\ncreated_at_ms
        const size_t nl1 = content.find('\n');
        if (nl1 == std::string::npos) return false;
        const size_t nl2 = content.find('\n', nl1 + 1);
        m_identity.peer_id = content.substr(0, nl1);
        if (nl2 != std::string::npos) {
            m_identity.keystore_path = content.substr(nl1 + 1, nl2 - nl1 - 1);
            m_identity.created_at_ms = std::atoll(content.c_str() + nl2 + 1);
        } else {
            m_identity.keystore_path = content.substr(nl1 + 1);
        }
        return m_identity.valid();
    }

    bool persist_locked_(const Identity& ident) {
        // Ensure the directory exists (best-effort).
        const size_t slash = m_files_dir.find_last_of('/');
        if (slash != std::string::npos && slash > 0) {
            const std::string parent = m_files_dir.substr(0, slash);
            const int rc = system_mkdir(parent);
            (void)rc;
        }
        if (!m_files_dir.empty()) {
            const int rc = system_mkdir(m_files_dir);
            (void)rc;
        }
        std::string content = ident.peer_id + "\n" + ident.keystore_path + "\n" +
                              std::to_string(ident.created_at_ms) + "\n";
        return write_atomic(m_path, content);
    }

    static int system_mkdir(const std::string& path) {
        // Portable best-effort mkdir -p for a single level.
        std::error_code ec;
        return std::filesystem::create_directories(path, ec) ? 0 : 1;
    }

    std::string m_files_dir;
    std::string m_path;
    mutable std::mutex m_mu;
    Identity m_identity;
    bool m_loaded{false};
};

} // namespace

std::unique_ptr<IIdentityStore> createFileIdentityStore(const std::string& files_dir) {
    return std::make_unique<FileIdentityStore>(files_dir);
}

} // namespace networkos
