// object_id.cpp — ObjectID encoding.

#include "networkos/object/object_id.h"

#include <cstring>
#include <random>

namespace networkos {

namespace {

const char kHex[] = "0123456789abcdef";

inline char nibble(uint8_t b) { return kHex[b & 0x0F]; }
inline int unhex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

} // namespace

bool ObjectId::nonce_is_zero() const {
    for (int i = 0; i < 16; ++i) {
        if (nonce[i] != 0) return false;
    }
    return true;
}

bool ObjectId::nonce_eq(const uint8_t other[16]) const {
    for (int i = 0; i < 16; ++i) {
        if (nonce[i] != other[i]) return false;
    }
    return true;
}

std::string ObjectId::toHex() const {
    std::string raw;
    raw.reserve(16 + 1 + network_id.size() + 1 + origin.size());
    raw.append(reinterpret_cast<const char*>(nonce), 16);
    if (network_id.size() > 255) return {};  // bounded
    raw.push_back(static_cast<char>(network_id.size()));
    raw.append(network_id);
    if (origin.size() > 255) return {};
    raw.push_back(static_cast<char>(origin.size()));
    raw.append(origin);

    std::string hex;
    hex.reserve(raw.size() * 2);
    for (unsigned char c : raw) {
        hex.push_back(nibble(c >> 4));
        hex.push_back(nibble(c));
    }
    return hex;
}

bool ObjectId::fromHex(const std::string& hex, ObjectId& out) {
    if (hex.size() < 32 || hex.size() % 2 != 0 || hex.size() > kMaxHexLength) {
        return false;
    }
    std::string raw;
    raw.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        const int hi = unhex(hex[i]);
        const int lo = unhex(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        raw.push_back(static_cast<char>((hi << 4) | lo));
    }
    // Layout: [nonce:16][u8 netlen][netid][u8 originlen][origin]
    if (raw.size() < 16 + 2) return false;
    const uint8_t net_len = static_cast<uint8_t>(raw[16]);
    if (raw.size() < 16 + 1 + static_cast<size_t>(net_len) + 1) return false;
    const size_t origin_len_off = 16 + 1 + static_cast<size_t>(net_len);
    const uint8_t origin_len = static_cast<uint8_t>(raw[origin_len_off]);
    if (raw.size() != origin_len_off + 1 + static_cast<size_t>(origin_len)) {
        return false;
    }
    std::memcpy(out.nonce, raw.data(), 16);
    out.network_id.assign(raw.data() + 17, net_len);
    out.origin.assign(raw.data() + origin_len_off + 1, origin_len);
    return true;
}

ObjectId ObjectId::generate(const std::string& network_id, const std::string& origin) {
    ObjectId id;
    id.network_id = network_id;
    id.origin = origin;
    std::random_device rd;
    for (int i = 0; i < 16; ++i) {
        id.nonce[i] = static_cast<uint8_t>(rd());
    }
    return id;
}

} // namespace networkos
