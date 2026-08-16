#include "sha1_md5.h"

#include <cstring>
#include <cmath>

namespace litep2p_crypto {

namespace {

inline uint32_t rotl32(uint32_t v, int s) {
    return (v << s) | (v >> (32 - s));
}

inline uint32_t load_be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

inline void store_be32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

inline uint32_t load_le32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

inline void store_le32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

} // namespace

// ============================================================================
// SHA-1 (RFC 3174)
// ============================================================================

std::vector<uint8_t> sha1(const uint8_t* data, size_t len) {
    uint32_t h0 = 0x67452301u;
    uint32_t h1 = 0xEFCDAB89u;
    uint32_t h2 = 0x98BADCFEu;
    uint32_t h3 = 0x10325476u;
    uint32_t h4 = 0xC3D2E1F0u;

    const uint64_t bit_len = static_cast<uint64_t>(len) * 8u;

    // Build padded message: data || 0x80 || zeros || 64-bit BE length.
    const size_t rem = len % 64;
    size_t padded_len;
    if (rem <= 55) {
        padded_len = len + 64 - rem;
    } else {
        padded_len = len + 128 - rem;
    }

    std::vector<uint8_t> msg(padded_len, 0);
    if (len > 0) {
        std::memcpy(msg.data(), data, len);
    }
    msg[len] = 0x80;
    // Append bit length as big-endian 64-bit at the end.
    for (int i = 0; i < 8; ++i) {
        msg[padded_len - 1 - i] = static_cast<uint8_t>(bit_len >> (i * 8));
    }

    uint32_t w[80];
    for (size_t off = 0; off < padded_len; off += 64) {
        for (int i = 0; i < 16; ++i) {
            w[i] = load_be32(msg.data() + off + static_cast<size_t>(i) * 4);
        }
        for (int i = 16; i < 80; ++i) {
            w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }

        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;

        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999u;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1u;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDCu;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6u;
            }

            const uint32_t tmp = rotl32(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = rotl32(b, 30);
            b = a;
            a = tmp;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    std::vector<uint8_t> out(20);
    store_be32(out.data(), h0);
    store_be32(out.data() + 4, h1);
    store_be32(out.data() + 8, h2);
    store_be32(out.data() + 12, h3);
    store_be32(out.data() + 16, h4);
    return out;
}

// ============================================================================
// MD5 (RFC 1321)
// ============================================================================

namespace {

// Per-round shift amounts (RFC 1321).
const uint32_t kMd5S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

} // namespace

std::vector<uint8_t> md5(const uint8_t* data, size_t len) {
    uint32_t a0 = 0x67452301u;
    uint32_t b0 = 0xEFCDAB89u;
    uint32_t c0 = 0x98BADCFEu;
    uint32_t d0 = 0x10325476u;

    const uint64_t bit_len = static_cast<uint64_t>(len) * 8u;

    // Padding: data || 0x80 || zeros || 64-bit LE length.
    const size_t rem = len % 64;
    size_t padded_len;
    if (rem <= 55) {
        padded_len = len + 64 - rem;
    } else {
        padded_len = len + 128 - rem;
    }

    std::vector<uint8_t> msg(padded_len, 0);
    if (len > 0) {
        std::memcpy(msg.data(), data, len);
    }
    msg[len] = 0x80;
    // 64-bit little-endian bit length in the final 8 bytes.
    for (int i = 0; i < 8; ++i) {
        msg[padded_len - 8 + i] = static_cast<uint8_t>(bit_len >> (i * 8));
    }

    for (size_t off = 0; off < padded_len; off += 64) {
        uint32_t m[16];
        for (int i = 0; i < 16; ++i) {
            m[i] = load_le32(msg.data() + off + static_cast<size_t>(i) * 4);
        }

        uint32_t a = a0, b = b0, c = c0, d = d0;

        for (int i = 0; i < 64; ++i) {
            uint32_t f;
            uint32_t g;
            if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = static_cast<uint32_t>(i);
            } else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (5u * static_cast<uint32_t>(i) + 1u) % 16u;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3u * static_cast<uint32_t>(i) + 5u) % 16u;
            } else {
                f = c ^ (b | (~d));
                g = (7u * static_cast<uint32_t>(i)) % 16u;
            }

            // K[i] = floor(abs(sin(i+1)) * 2^32) computed on the fly (RFC 1321).
            const double k_float = std::fabs(std::sin(static_cast<double>(i + 1))) * 4294967296.0;
            const uint32_t k = static_cast<uint32_t>(k_float);

            const uint32_t tmp = d;
            d = c;
            c = b;
            b = b + rotl32(a + f + k + m[g], static_cast<int>(kMd5S[i]));
            a = tmp;
        }

        a0 += a;
        b0 += b;
        c0 += c;
        d0 += d;
    }

    std::vector<uint8_t> out(16);
    store_le32(out.data(), a0);
    store_le32(out.data() + 4, b0);
    store_le32(out.data() + 8, c0);
    store_le32(out.data() + 12, d0);
    return out;
}

// ============================================================================
// HMAC-SHA1 (RFC 2104)
// ============================================================================

std::vector<uint8_t> hmac_sha1(const uint8_t* key, size_t key_len,
                               const uint8_t* data, size_t data_len) {
    constexpr size_t kBlock = 64;

    std::vector<uint8_t> k(kBlock, 0);
    if (key_len > kBlock) {
        std::vector<uint8_t> h = sha1(key, key_len);
        std::memcpy(k.data(), h.data(), h.size());
    } else if (key_len > 0) {
        std::memcpy(k.data(), key, key_len);
    }

    std::vector<uint8_t> inner(kBlock);
    std::vector<uint8_t> outer(kBlock);
    for (size_t i = 0; i < kBlock; ++i) {
        inner[i] = k[i] ^ 0x36;
        outer[i] = k[i] ^ 0x5C;
    }

    // inner = SHA1(ipad_key || data)
    std::vector<uint8_t> inner_input(inner.begin(), inner.end());
    inner_input.insert(inner_input.end(), data, data + data_len);
    const std::vector<uint8_t> inner_hash = sha1(inner_input.data(), inner_input.size());

    // outer = SHA1(opad_key || inner_hash)
    std::vector<uint8_t> outer_input(outer.begin(), outer.end());
    outer_input.insert(outer_input.end(), inner_hash.begin(), inner_hash.end());
    return sha1(outer_input.data(), outer_input.size());
}

std::vector<uint8_t> hmac_sha1(const std::string& key, const std::string& data) {
    return hmac_sha1(reinterpret_cast<const uint8_t*>(key.data()), key.size(),
                     reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

// ============================================================================
// Constant-time comparison
// ============================================================================

bool ct_equal(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

} // namespace litep2p_crypto

