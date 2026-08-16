#ifndef SHA1_MD5_H
#define SHA1_MD5_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace litep2p_crypto {

// SHA-1 (RFC 3174). Provided for legacy protocol interop (TURN
// MESSAGE-INTEGRITY per RFC 5766). Not intended for new designs.
std::vector<uint8_t> sha1(const uint8_t* data, size_t len);

// MD5 (RFC 1321). Provided for TURN long-term credential key derivation
// (key = MD5(username:realm:password)). Not intended for new designs.
std::vector<uint8_t> md5(const uint8_t* data, size_t len);

// HMAC-SHA1 (RFC 2104).
std::vector<uint8_t> hmac_sha1(const uint8_t* key, size_t key_len,
                               const uint8_t* data, size_t data_len);
std::vector<uint8_t> hmac_sha1(const std::string& key, const std::string& data);

// Constant-time comparison (for MAC verification).
bool ct_equal(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

} // namespace litep2p_crypto

#endif // SHA1_MD5_H
