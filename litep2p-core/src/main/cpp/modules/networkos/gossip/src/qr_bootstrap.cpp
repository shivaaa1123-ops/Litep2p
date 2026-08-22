// Network OS Phase 13 — QR contact codec (signing via libsodium Ed25519).

#include "networkos/gossip/qr_bootstrap.h"

#include <sodium.h>

#include <cstring>
#include <string>
#include <vector>

namespace networkos {
namespace gossip {

namespace {

constexpr char kMagic[4] = {'L', 'P', 'Q', '1'};
constexpr size_t kPkLen = 32;
constexpr size_t kSigLen = 64;
constexpr size_t kMaxBody = 512;

const char* kB64url =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string b64url_encode(const std::string& raw) {
    std::string out;
    out.reserve(((raw.size() + 2) / 3) * 4);
    size_t i = 0;
    while (i + 2 < raw.size()) {
        const uint32_t n = (static_cast<uint8_t>(raw[i]) << 16) |
                           (static_cast<uint8_t>(raw[i + 1]) << 8) |
                           static_cast<uint8_t>(raw[i + 2]);
        out.push_back(kB64url[(n >> 18) & 63]);
        out.push_back(kB64url[(n >> 12) & 63]);
        out.push_back(kB64url[(n >> 6) & 63]);
        out.push_back(kB64url[n & 63]);
        i += 3;
    }
    if (i + 1 == raw.size()) {
        const uint32_t n = static_cast<uint8_t>(raw[i]) << 16;
        out.push_back(kB64url[(n >> 18) & 63]);
        out.push_back(kB64url[(n >> 12) & 63]);
    } else if (i + 2 == raw.size()) {
        const uint32_t n = (static_cast<uint8_t>(raw[i]) << 16) |
                           (static_cast<uint8_t>(raw[i + 1]) << 8);
        out.push_back(kB64url[(n >> 18) & 63]);
        out.push_back(kB64url[(n >> 12) & 63]);
        out.push_back(kB64url[(n >> 6) & 63]);
    }
    return out;
}

bool b64url_decode(const std::string& in, std::string& out) {
    out.clear();
    uint32_t buf = 0;
    int bits = 0;
    for (char c : in) {
        const char* p = strchr(kB64url, c);
        if (!p || c == '\0') return false;
        buf = (buf << 6) | static_cast<uint32_t>(p - kB64url);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((buf >> bits) & 0xFF));
        }
    }
    return true;
}

bool hex_to_bytes(const std::string& hex, std::string& out) {
    if (hex.size() % 2 != 0) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    out.clear();
    for (size_t i = 0; i < hex.size(); i += 2) {
        const int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<char>((hi << 4) | lo));
    }
    return true;
}

std::string bytes_to_hex(const unsigned char* raw, size_t len) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(kHex[raw[i] >> 4]);
        out.push_back(kHex[raw[i] & 0x0F]);
    }
    return out;
}

}  // namespace

std::string build_contact_qr(const std::string& secret_seed_hex,
                             const PeerRecord& record) {
    if (record.peer_id.empty() || record.peer_id.size() > 128) return "";
    if (record.primary_endpoint.empty() ||
        record.primary_endpoint.size() > 128) {
        return "";
    }
    std::string seed;
    if (!hex_to_bytes(secret_seed_hex, seed) || seed.size() != 32) return "";
    if (sodium_init() < 0) return "";

    // Body: ver | id | endpoint | flags | [signaling]
    std::string body;
    body.push_back('\x01');
    body.push_back(static_cast<char>(record.peer_id.size()));
    body.append(record.peer_id);
    body.push_back(static_cast<char>(record.primary_endpoint.size()));
    body.append(record.primary_endpoint);
    const bool has_sig =
        !record.signaling_addr.empty() && record.signaling_addr.size() <= 256;
    body.push_back(has_sig ? '\x01' : '\x00');
    if (has_sig) {
        const size_t sl = record.signaling_addr.size();
        body.push_back(static_cast<char>(sl & 0xFF));
        body.push_back(static_cast<char>((sl >> 8) & 0xFF));
        body.append(record.signaling_addr);
    }
    if (body.size() + kPkLen > kMaxBody) return "";

    // Derive the bootstrap keypair from the seed. Both out-buffers are
    // required by libsodium (sk is written as seed||pk, 64 bytes); signing
    // MUST use the secret key, never the raw seed.
    std::vector<unsigned char> pk(kPkLen);
    std::vector<unsigned char> sk(crypto_sign_SECRETKEYBYTES);
    std::vector<unsigned char> sig(kSigLen);
    if (crypto_sign_seed_keypair(pk.data(), sk.data(),
                                 reinterpret_cast<const unsigned char*>(
                                     seed.data())) != 0) {
        return "";
    }
    unsigned long long sig_len = 0;
    if (crypto_sign_detached(sig.data(), &sig_len,
                             reinterpret_cast<const unsigned char*>(body.data()),
                             body.size(), sk.data()) != 0) {
        return "";
    }

    std::string raw;
    raw.reserve(4 + body.size() + kPkLen + kSigLen);
    raw.append(kMagic, 4);
    raw.append(body);
    raw.append(reinterpret_cast<const char*>(pk.data()), kPkLen);
    raw.append(reinterpret_cast<const char*>(sig.data()), kSigLen);
    return b64url_encode(raw);
}

bool parse_contact_qr(const std::string& qr_text, ContactCard& out) {
    std::string raw;
    if (!b64url_decode(qr_text, raw)) return false;
    if (raw.size() < 4 + 1 + 1 + kPkLen + kSigLen) return false;
    if (std::memcmp(raw.data(), kMagic, 4) != 0) return false;

    size_t off = 4;
    if (static_cast<uint8_t>(raw[off]) != 0x01) return false;  // version
    off += 1;

    PeerRecord r;
    const size_t id_len = static_cast<uint8_t>(raw[off]);
    off += 1;
    if (id_len == 0 || id_len > 128 || off + id_len > raw.size()) return false;
    r.peer_id.assign(raw, off, id_len);
    off += id_len;

    const size_t ep_len = static_cast<uint8_t>(raw[off]);
    off += 1;
    if (ep_len == 0 || ep_len > 128 || off + ep_len > raw.size()) return false;
    r.primary_endpoint.assign(raw, off, ep_len);
    off += ep_len;

    const uint8_t fl = static_cast<uint8_t>(raw[off]);
    off += 1;
    if (fl & 0x01) {
        if (off + 2 > raw.size()) return false;
        const size_t s_len =
            static_cast<uint8_t>(raw[off]) |
            (static_cast<size_t>(static_cast<uint8_t>(raw[off + 1])) << 8);
        off += 2;
        if (s_len > 256 || off + s_len > raw.size()) return false;
        r.signaling_addr.assign(raw, off, s_len);
        off += s_len;
    }
    if (off + kPkLen + kSigLen != raw.size()) return false;  // strict tail

    const std::string body = raw.substr(4, off - 4);
    const unsigned char* pk =
        reinterpret_cast<const unsigned char*>(raw.data()) + off;
    const unsigned char* sig = pk + kPkLen;

    if (sodium_init() < 0) return false;
    if (crypto_sign_verify_detached(sig,
                                    reinterpret_cast<const unsigned char*>(body.data()),
                                    body.size(), pk) != 0) {
        return false;
    }
    r.flags = fl;
    out.record = r;
    out.signer_pk_hex = bytes_to_hex(pk, kPkLen);
    return true;
}

}  // namespace gossip
}  // namespace networkos