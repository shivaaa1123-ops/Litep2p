#include "crypto_utils.h"
#include "logger.h"
#include "config_manager.h"

#include <cstring>
#include <cstdio>
#include <fstream>
#include <map>
#include <mutex>
#include <string>
#include <vector>
#include <filesystem>
#include <random>
#include <ctime>

#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>

#if defined(HAVE_NOISE_PROTOCOL)
#include <sodium.h>
#endif

// ============================================================================
// CSPRNG
// ============================================================================

#if !defined(HAVE_NOISE_PROTOCOL)

namespace {

void os_random_bytes(void* buffer, size_t length) {
    uint8_t* out = static_cast<uint8_t*>(buffer);
#if defined(__APPLE__)
    arc4random_buf(out, length);
#elif defined(__linux__) || defined(__ANDROID__)
#if defined(__linux__) && __has_include(<sys/random.h>)
    // getrandom(2) - blocks only before the kernel RNG is seeded.
    size_t done = 0;
    while (done < length) {
        ssize_t n = ::getrandom(out + done, length - done, 0);
        if (n > 0) {
            done += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        break; // fall through to /dev/urandom
    }
    if (done == length) return;
#endif
    // Portable fallback: /dev/urandom.
    static FILE* urandom = nullptr;
    static std::mutex urandom_mutex;
    std::lock_guard<std::mutex> lock(urandom_mutex);
    if (!urandom) {
        urandom = ::fopen("/dev/urandom", "rb");
    }
    size_t done = 0;
    while (urandom && done < length) {
        const size_t n = ::fread(out + done, 1, length - done, urandom);
        if (n == 0) break;
        done += static_cast<size_t>(n);
    }
    // Last-resort: never return uninitialized memory. Mix what we got with a
    // per-process random seed (weak, but strictly better than all-zero).
    if (done < length) {
        static uint64_t seed = static_cast<uint64_t>(::time(nullptr)) ^
                               static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&done));
        for (size_t i = done; i < length; ++i) {
            seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
            out[i] = static_cast<uint8_t>(seed >> 33);
        }
    }
#else
    // Unknown platform: best effort using std::random_device.
    static std::mutex rd_mutex;
    static std::random_device* rd = nullptr;
    std::lock_guard<std::mutex> lock(rd_mutex);
    if (!rd) rd = new std::random_device();
    for (size_t i = 0; i < length; ++i) out[i] = static_cast<uint8_t>((*rd)());
#endif
}

} // namespace

#endif // !HAVE_NOISE_PROTOCOL

void random_bytes(void* buffer, size_t length) {
    if (!buffer || length == 0) return;
#if defined(HAVE_NOISE_PROTOCOL)
    randombytes_buf(buffer, length);
#else
    os_random_bytes(buffer, length);
#endif
}

// ============================================================================
// Transport key resolution
// ============================================================================

namespace {

constexpr size_t kTransportKeyLen = 32;

std::mutex g_key_mutex;
bool g_key_resolved = false;
uint8_t g_transport_key[kTransportKeyLen] = {0};

int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

bool hex_to_key(const std::string& hex, uint8_t* out) {
    if (hex.size() < kTransportKeyLen * 2) return false;
    for (size_t i = 0; i < kTransportKeyLen; ++i) {
        const int hi = hex_val(hex[i * 2]);
        const int lo = hex_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

std::string key_to_hex(const uint8_t* key) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(kTransportKeyLen * 2);
    for (size_t i = 0; i < kTransportKeyLen; ++i) {
        out.push_back(kHex[key[i] >> 4]);
        out.push_back(kHex[key[i] & 0x0F]);
    }
    return out;
}

// Resolve the transport key file next to the Noise keystore, mirroring the
// path logic in NoiseKeyStore (directory vs explicit .json file).
std::string resolve_transport_key_file() {
    const std::string configured = ConfigManager::getInstance().getKeyStorePath();
    const std::string base = configured.empty() ? std::string("keystore") : configured;

    std::string dir = base;
    // If the configured path looks like a .json file, place the key next to it.
    if (base.size() >= 5 && base.compare(base.size() - 5, 5, ".json") == 0) {
        const size_t slash = base.find_last_of('/');
        dir = (slash == std::string::npos) ? std::string(".") : base.substr(0, slash);
    }

    std::string path = dir;
    if (!path.empty() && path.back() != '/') path.push_back('/');
    path += "transport_key.hex";
    return path;
}

bool load_key_from_file(uint8_t* out) {
    const std::string path = resolve_transport_key_file();
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) return false;
    std::string content((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());
    return hex_to_key(content, out);
}

bool persist_key_to_file(const uint8_t* key) {
    const std::string path = resolve_transport_key_file();
    try {
        // Best-effort parent dir creation (key may live in a fresh directory).
        const size_t slash = path.find_last_of('/');
        if (slash != std::string::npos && slash > 0) {
            std::error_code ec;
            std::filesystem::create_directories(path.substr(0, slash), ec);
        }

        std::ofstream out(path, std::ios::out | std::ios::trunc);
        if (!out.is_open()) return false;
        out << key_to_hex(key) << "\n";
        out.close();
        if (!out) return false;

        // Restrict to owner-only; failure is non-fatal but worth noting.
        if (::chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0) {
            LOG_WARN("Transport key: chmod 0600 failed for " + path);
        }
        return true;
    } catch (const std::exception& e) {
        LOG_WARN(std::string("Transport key: persist failed: ") + e.what());
        return false;
    }
}

bool resolve_key_locked(uint8_t* out) {
    // 1) Operator-provisioned shared network key (config).
    const std::string configured_hex = ConfigManager::getInstance().getTransportKeyHex();
    if (!configured_hex.empty() && hex_to_key(configured_hex, out)) {
        return true;
    }

    // 2) Persisted key file (shared across instances on the same filesystem).
    if (load_key_from_file(out)) {
        return true;
    }

    // 3) Generate and persist a new random key (last resort for cross-device
    //    interop; same-machine peers share the same file and work fine).
    random_bytes(out, kTransportKeyLen);
    (void)persist_key_to_file(out);
    return true;
}

} // namespace

bool transport_key_resolve(uint8_t* out_key_32) {
    if (!out_key_32) return false;

    std::lock_guard<std::mutex> lock(g_key_mutex);
    if (!g_key_resolved) {
        g_key_resolved = resolve_key_locked(g_transport_key);

        if (!g_key_resolved) {
            LOG_ERROR("Transport crypto: failed to resolve a transport key; "
                      "message encryption will be unavailable.");
            return false;
        }

        const std::string configured_hex = ConfigManager::getInstance().getTransportKeyHex();
        if (!configured_hex.empty() && hex_to_key(configured_hex, g_transport_key)) {
            LOG_INFO("Transport crypto: using configured security.transport_key (shared network key).");
        } else {
            LOG_WARN("Transport crypto: no security.transport_key configured; using device-local "
                     "key file. Devices that must communicate MUST share the same key.");
        }

#if defined(HAVE_NOISE_PROTOCOL)
        LOG_DEBUG("Transport crypto: ChaCha20-Poly1305 (authenticated) enabled.");
#else
        LOG_WARN("Transport crypto: libsodium unavailable - falling back to AES-256-CBC. "
                 "Messages are encrypted but NOT authenticated. Enable the Noise protocol "
                 "for full security.");
#endif
    }

    std::memcpy(out_key_32, g_transport_key, kTransportKeyLen);
    return true;
}


// ============================================================================
// Per-peer key registry
// ============================================================================

namespace {

struct PeerKeys {
    uint8_t send_key[32];
    uint8_t recv_key[32];
};

std::mutex g_peer_key_mutex;
std::map<std::string, PeerKeys> g_peer_keys;

} // namespace

bool set_peer_transport_keys(const std::string& id,
                             const uint8_t* send_key_32,
                             const uint8_t* recv_key_32) {
    if (!send_key_32 || !recv_key_32) return false;
    std::lock_guard<std::mutex> lock(g_peer_key_mutex);
    PeerKeys& k = g_peer_keys[id];
    std::memcpy(k.send_key, send_key_32, 32);
    std::memcpy(k.recv_key, recv_key_32, 32);
    // Cap to prevent unbounded growth from malformed peers.
    if (g_peer_keys.size() > 4096) {
        g_peer_keys.erase(g_peer_keys.begin());
    }
    return true;
}

void clear_peer_transport_keys(const std::string& id) {
    std::lock_guard<std::mutex> lock(g_peer_key_mutex);
    g_peer_keys.erase(id);
}

bool has_peer_transport_keys(const std::string& id) {
    std::lock_guard<std::mutex> lock(g_peer_key_mutex);
    return g_peer_keys.find(id) != g_peer_keys.end();
}


// ============================================================================
// Encryption / decryption
// ============================================================================

#if defined(HAVE_NOISE_PROTOCOL)

// Key-explicit AEAD helpers (used by both network-key and per-peer paths).
static std::string encrypt_with_key(const uint8_t* key, const std::string& plain_text) {
    if (!key) return {};
    const size_t npub = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    const size_t abytes = crypto_aead_chacha20poly1305_ietf_ABYTES;

    std::string out;
    out.resize(npub + plain_text.size() + abytes);

    uint8_t* nonce = reinterpret_cast<uint8_t*>(&out[0]);
    randombytes_buf(nonce, npub);

    unsigned long long clen = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            reinterpret_cast<unsigned char*>(&out[0]) + npub, &clen,
            reinterpret_cast<const unsigned char*>(plain_text.data()), plain_text.size(),
            nullptr, 0, nullptr, nonce, key) != 0) {
        LOG_ERROR("Transport crypto: encrypt failed.");
        return {};
    }
    out.resize(npub + static_cast<size_t>(clen));
    return out;
}

static std::string decrypt_with_key(const uint8_t* key, const std::string& encrypted_text) {
    if (!key) return {};
    const size_t npub = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    const size_t abytes = crypto_aead_chacha20poly1305_ietf_ABYTES;

    if (encrypted_text.size() < npub + abytes) return {};

    const uint8_t* nonce = reinterpret_cast<const uint8_t*>(encrypted_text.data());
    std::string plain(encrypted_text.size() - npub - abytes, '\0');

    unsigned long long mlen = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char*>(&plain[0]), &mlen, nullptr,
            reinterpret_cast<const unsigned char*>(encrypted_text.data()) + npub,
            encrypted_text.size() - npub,
            nullptr, 0, nonce, key) != 0) {
        return {};
    }
    plain.resize(static_cast<size_t>(mlen));
    return plain;
}

// Thin wrappers for the shared network key (handshake/bootstrap traffic).
std::string encrypt_message(const std::string& plain_text) {
    uint8_t key[kTransportKeyLen];
    if (!transport_key_resolve(key)) return {};
    return encrypt_with_key(key, plain_text);
}

std::string decrypt_message(const std::string& encrypted_text) {
    const size_t npub = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    const size_t abytes = crypto_aead_chacha20poly1305_ietf_ABYTES;
    if (encrypted_text.size() < npub + abytes) return {};
    uint8_t key[kTransportKeyLen];
    if (!transport_key_resolve(key)) return {};
    return decrypt_with_key(key, encrypted_text);
}

#else // !HAVE_NOISE_PROTOCOL

// Fallback: AES-256-CBC with CSPRNG IV (unauthenticated - see header note).
#include "aes.h"

// Helper to apply PKCS7 padding
static void pkcs7_pad(std::string& data) {
    int padding = AES_BLOCKLEN - (data.length() % AES_BLOCKLEN);
    data.append(static_cast<size_t>(padding), static_cast<char>(padding));
}

// Helper to remove PKCS7 padding (bounds-checked)
static void pkcs7_unpad(std::string& data) {
    if (data.empty()) return;
    const int padding = static_cast<unsigned char>(data.back());
    if (padding <= 0 || padding > AES_BLOCKLEN ||
        static_cast<size_t>(padding) > data.size()) {
        return;
    }
    bool ok = true;
    for (int i = 0; i < padding; ++i) {
        if (static_cast<unsigned char>(data[data.length() - 1 - static_cast<size_t>(i)]) !=
            static_cast<unsigned char>(padding)) {
            ok = false;
            break;
        }
    }
    if (ok) data.resize(data.length() - static_cast<size_t>(padding));
}

static std::string encrypt_with_key_aes(const uint8_t* key, const std::string& plain_text) {
    if (!key) return {};
    struct AES_ctx ctx;
    uint8_t iv[AES_BLOCKLEN];
    random_bytes(iv, AES_BLOCKLEN);
    AES_init_ctx_iv(&ctx, key, iv);
    std::string encrypted = plain_text;
    pkcs7_pad(encrypted);
    AES_CBC_encrypt_buffer(&ctx, reinterpret_cast<uint8_t*>(&encrypted[0]),
                           static_cast<uint32_t>(encrypted.length()));
    std::string result(reinterpret_cast<const char*>(iv), AES_BLOCKLEN);
    result.append(encrypted);
    return result;
}

static std::string decrypt_with_key_aes(const uint8_t* key, const std::string& encrypted_text) {
    if (!key) return {};
    if (encrypted_text.length() < AES_BLOCKLEN) return {};
    uint8_t iv[AES_BLOCKLEN];
    std::memcpy(iv, encrypted_text.data(), AES_BLOCKLEN);
    const std::string ciphertext = encrypted_text.substr(AES_BLOCKLEN);
    if (ciphertext.empty() || ciphertext.length() % AES_BLOCKLEN != 0) return {};
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    std::string decrypted = ciphertext;
    AES_CBC_decrypt_buffer(&ctx, reinterpret_cast<uint8_t*>(&decrypted[0]),
                           static_cast<uint32_t>(decrypted.length()));
    pkcs7_unpad(decrypted);
    return decrypted;
}

std::string encrypt_message(const std::string& plain_text) {
    uint8_t key[kTransportKeyLen];
    if (!transport_key_resolve(key)) return {};
    return encrypt_with_key_aes(key, plain_text);
}

std::string decrypt_message(const std::string& encrypted_text) {
    uint8_t key[kTransportKeyLen];
    if (!transport_key_resolve(key)) return {};
    return decrypt_with_key_aes(key, encrypted_text);
}

// ============================================================================
#endif // HAVE_NOISE_PROTOCOL
// Per-peer transport encryption (forward secrecy)
// ============================================================================

std::string encrypt_message_for_peer(const std::string& id, const std::string& plain_text) {
    // Try the per-peer send key first.
    {
        std::lock_guard<std::mutex> lock(g_peer_key_mutex);
        auto it = g_peer_keys.find(id);
        if (it != g_peer_keys.end()) {
#if defined(HAVE_NOISE_PROTOCOL)
            return encrypt_with_key(it->second.send_key, plain_text);
#else
            return encrypt_with_key_aes(it->second.send_key, plain_text);
#endif
        }
    }
    // Fall back to the shared network key (handshake/bootstrap / no-Noise).
    return encrypt_message(plain_text);
}

std::string decrypt_message_for_peer(const std::string& id, const std::string& encrypted_text) {
    // 1) Try the per-peer recv key registered under this exact id.
    {
        std::lock_guard<std::mutex> lock(g_peer_key_mutex);
        auto it = g_peer_keys.find(id);
        if (it != g_peer_keys.end()) {
#if defined(HAVE_NOISE_PROTOCOL)
            const std::string plain = decrypt_with_key(it->second.recv_key, encrypted_text);
#else
            const std::string plain = decrypt_with_key_aes(it->second.recv_key, encrypted_text);
#endif
            if (!plain.empty()) {
                return plain;
            }
        }
    }

    // 2) Fall back to trying every registered recv key. network_ids can be
    //    aliased (ephemeral port mappings, duplicate network_id collisions),
    //    so the source address observed on the wire may not match the id we
    //    registered the key under. AEAD authentication fails fast, so this is
    //    safe and correct; the peer count is small in practice.
    {
        std::vector<uint8_t> candidate_keys;
        {
            std::lock_guard<std::mutex> lock(g_peer_key_mutex);
            candidate_keys.reserve(g_peer_keys.size() * 32);
            for (const auto& kv : g_peer_keys) {
                candidate_keys.insert(candidate_keys.end(),
                                      kv.second.recv_key, kv.second.recv_key + 32);
            }
        }
        for (size_t i = 0; i + 32 <= candidate_keys.size(); i += 32) {
#if defined(HAVE_NOISE_PROTOCOL)
            const std::string plain = decrypt_with_key(candidate_keys.data() + i, encrypted_text);
#else
            const std::string plain = decrypt_with_key_aes(candidate_keys.data() + i, encrypted_text);
#endif
            if (!plain.empty()) {
                return plain;
            }
        }
    }

    // 3) Fall back to the shared network key (handshake/bootstrap / no-Noise).
    return decrypt_message(encrypted_text);
}


std::string encrypt_message_udp(const std::string& plain_text) {
    return encrypt_message(plain_text);
}

std::string decrypt_message_udp(const std::string& encrypted_text) {
    return decrypt_message(encrypted_text);
}

void generate_random_iv(uint8_t* iv, size_t length) {
    if (!iv || length == 0) return;
    random_bytes(iv, length);
}
