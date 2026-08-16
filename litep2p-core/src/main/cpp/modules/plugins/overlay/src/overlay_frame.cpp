#include "overlay_frame.h"
#include "logger.h"

#include <sodium.h>
#include <cstring>

namespace overlay {
namespace {

bool sodium_ready() {
    static const int rc = sodium_init();
    return rc >= 0;
}

} // namespace

// ---------------------------------------------------------------------------
// Little-endian integer + string helpers
// ---------------------------------------------------------------------------

void put_u16_le(std::string& out, uint16_t v) {
    out.push_back(static_cast<char>(v & 0xFF));
    out.push_back(static_cast<char>((v >> 8) & 0xFF));
}

void put_u32_le(std::string& out, uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
}

void put_u64_le(std::string& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
}

void put_str(std::string& out, const std::string& s) {
    put_u16_le(out, static_cast<uint16_t>(s.size()));
    out.append(s);
}

bool get_u16_le(std::string_view in, size_t& off, uint16_t& v) {
    if (off + 2 > in.size()) return false;
    v = static_cast<uint16_t>(static_cast<uint8_t>(in[off])) |
        (static_cast<uint16_t>(static_cast<uint8_t>(in[off + 1])) << 8);
    off += 2;
    return true;
}

bool get_u32_le(std::string_view in, size_t& off, uint32_t& v) {
    if (off + 4 > in.size()) return false;
    v = 0;
    for (int i = 0; i < 4; ++i) {
        v |= static_cast<uint32_t>(static_cast<uint8_t>(in[off + i])) << (8 * i);
    }
    off += 4;
    return true;
}

bool get_u64_le(std::string_view in, size_t& off, uint64_t& v) {
    if (off + 8 > in.size()) return false;
    v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<uint64_t>(static_cast<uint8_t>(in[off + i])) << (8 * i);
    }
    off += 8;
    return true;
}

bool get_str(std::string_view in, size_t& off, std::string& v) {
    uint16_t len = 0;
    if (!get_u16_le(in, off, len)) return false;
    if (off + len > in.size()) return false;
    v.assign(in.data() + off, len);
    off += len;
    return true;
}

// ---------------------------------------------------------------------------
// Sealed hop instruction
// ---------------------------------------------------------------------------

std::string seal_hop(const std::vector<uint8_t>& hop_public_key,
                     const HopInstruction& instr) {
    if (!sodium_ready() || hop_public_key.size() != crypto_box_PUBLICKEYBYTES) {
        return {};
    }

    std::string plain;
    plain.reserve(1 + 2 + instr.next_peer.size() + 2 + instr.mailbox_key.size() +
                  4 + instr.inner.size());
    plain.push_back(static_cast<char>(instr.kind));
    put_str(plain, instr.next_peer);
    put_str(plain, instr.mailbox_key);
    put_u32_le(plain, static_cast<uint32_t>(instr.inner.size()));
    plain.append(instr.inner);

    std::string sealed(crypto_box_SEALBYTES + plain.size(), '\0');
    const int rc = crypto_box_seal(reinterpret_cast<unsigned char*>(&sealed[0]),
                                   reinterpret_cast<const unsigned char*>(plain.data()),
                                   plain.size(),
                                   hop_public_key.data());
    if (rc != 0) return {};
    return sealed;
}

bool open_hop(const std::vector<uint8_t>& local_public_key,
              const std::vector<uint8_t>& local_secret_key,
              std::string_view body, HopInstruction& out) {
    if (!sodium_ready()) return false;
    if (body.size() < crypto_box_SEALBYTES) return false;
    if (local_public_key.size() != crypto_box_PUBLICKEYBYTES ||
        local_secret_key.size() != crypto_box_SECRETKEYBYTES) {
        return false;
    }

    const size_t plain_len = body.size() - crypto_box_SEALBYTES;
    std::string plain(plain_len, '\0');
    const int rc = crypto_box_seal_open(
        reinterpret_cast<unsigned char*>(&plain[0]),
        reinterpret_cast<const unsigned char*>(body.data()), body.size(),
        local_public_key.data(), local_secret_key.data());
    if (rc != 0) return false;

    size_t off = 0;
    if (plain.empty()) return false;
    out.kind = static_cast<HopKind>(static_cast<uint8_t>(plain[off++]));
    if (out.kind != HopKind::Forward && out.kind != HopKind::Deliver &&
        out.kind != HopKind::MailboxStore && out.kind != HopKind::MailboxPickup &&
        out.kind != HopKind::Cover) {
        return false;
    }
    if (!get_str(plain, off, out.next_peer)) return false;
    if (!get_str(plain, off, out.mailbox_key)) return false;
    uint32_t inner_len = 0;
    if (!get_u32_le(plain, off, inner_len)) return false;
    if (off + inner_len > plain.size()) return false;
    out.inner.assign(plain.data() + off, inner_len);
    off += inner_len;
    return off == plain.size();  // strict: reject trailing garbage
}

// ---------------------------------------------------------------------------
// Final payload (sealed to destination)
// ---------------------------------------------------------------------------

std::string seal_final(const std::vector<uint8_t>& dest_public_key,
                       const FinalPayload& payload,
                       const uint8_t* sign_sk, const uint8_t* sign_pk) {
    if (!sodium_ready() || dest_public_key.size() != crypto_box_PUBLICKEYBYTES) {
        return {};
    }

    std::string plain;
    plain.reserve(2 + payload.origin_peer_id.size() + 8 + 2 + 4 +
                  payload.app_payload.size() + 2 + payload.ack_of.size() +
                  2 + payload.message_frame_id_hex.size() +
                  2 + payload.reply_relays.size() * 40);
    put_str(plain, payload.origin_peer_id);
    put_u64_le(plain, payload.created_ts_ms);
    put_u16_le(plain, payload.flags);
    put_u32_le(plain, static_cast<uint32_t>(payload.app_payload.size()));
    plain.append(payload.app_payload);
    put_str(plain, payload.ack_of);
    put_str(plain, payload.message_frame_id_hex);
    put_u16_le(plain, static_cast<uint16_t>(payload.reply_relays.size()));
    for (const auto& r : payload.reply_relays) put_str(plain, r);

    // Optional Ed25519 origin signature over everything serialized so far.
    // (Signing keys are 32B public / 64B secret; signature is 64B.)
    if (sign_sk && sign_pk) {
        std::string sig(64, '\0');
        if (crypto_sign_detached(reinterpret_cast<unsigned char*>(&sig[0]),
                                 nullptr,
                                 reinterpret_cast<const unsigned char*>(plain.data()),
                                 plain.size(), sign_sk) != 0) {
            return {};
        }
        plain.append(reinterpret_cast<const char*>(sign_pk), 32);
        plain.append(sig);
    }

    std::string sealed(crypto_box_SEALBYTES + plain.size(), '\0');
    const int rc = crypto_box_seal(reinterpret_cast<unsigned char*>(&sealed[0]),
                                   reinterpret_cast<const unsigned char*>(plain.data()),
                                   plain.size(), dest_public_key.data());
    if (rc != 0) return {};
    return sealed;
}

bool open_final(const std::vector<uint8_t>& local_public_key,
                const std::vector<uint8_t>& local_secret_key,
                std::string_view body, FinalPayload& out) {
    if (!sodium_ready()) return false;
    if (body.size() < crypto_box_SEALBYTES) return false;
    if (local_public_key.size() != crypto_box_PUBLICKEYBYTES ||
        local_secret_key.size() != crypto_box_SECRETKEYBYTES) {
        return false;
    }

    const size_t plain_len = body.size() - crypto_box_SEALBYTES;
    std::string plain(plain_len, '\0');
    const int rc = crypto_box_seal_open(
        reinterpret_cast<unsigned char*>(&plain[0]),
        reinterpret_cast<const unsigned char*>(body.data()), body.size(),
        local_public_key.data(), local_secret_key.data());
    if (rc != 0) return false;

    size_t off = 0;
    if (!get_str(plain, off, out.origin_peer_id)) return false;
    if (!get_u64_le(plain, off, out.created_ts_ms)) return false;
    if (!get_u16_le(plain, off, out.flags)) return false;
    uint32_t app_len = 0;
    if (!get_u32_le(plain, off, app_len)) return false;
    if (off + app_len > plain.size()) return false;
    out.app_payload.assign(plain.data() + off, app_len);
    off += app_len;
    if (!get_str(plain, off, out.ack_of)) return false;
    if (!get_str(plain, off, out.message_frame_id_hex)) return false;
    uint16_t n_relays = 0;
    if (!get_u16_le(plain, off, n_relays)) return false;
    out.reply_relays.clear();
    out.reply_relays.reserve(n_relays);
    for (uint16_t i = 0; i < n_relays; ++i) {
        std::string r;
        if (!get_str(plain, off, r)) return false;
        out.reply_relays.push_back(std::move(r));
    }
    // Optional signer pk + signature tail.
    if (off + 32 + 64 <= plain.size()) {
        out.signer_pk.assign(plain.data() + off, 32);
        off += 32;
        out.signature.assign(plain.data() + off, 64);
        off += 64;
    }
    return off == plain.size();  // strict parse
}

bool verify_final_signature(const FinalPayload& payload,
                            const std::vector<uint8_t>& expected_signer_pk) {
    // Unsigned payloads trivially "verify" (caller enforces require_origin_auth).
    if (payload.signature.empty()) return true;
    if (payload.signer_pk.size() != 32 || payload.signature.size() != 64) return false;
    if (!expected_signer_pk.empty() &&
        (expected_signer_pk.size() != payload.signer_pk.size() ||
         std::memcmp(expected_signer_pk.data(), payload.signer_pk.data(),
                     payload.signer_pk.size()) != 0)) {
        return false;  // signed by a different key than we registered for this peer
    }
    if (!sodium_ready()) return false;

    // Rebuild the exact bytes that were signed (everything before signer_pk).
    std::string plain;
    put_str(plain, payload.origin_peer_id);
    put_u64_le(plain, payload.created_ts_ms);
    put_u16_le(plain, payload.flags);
    put_u32_le(plain, static_cast<uint32_t>(payload.app_payload.size()));
    plain.append(payload.app_payload);
    put_str(plain, payload.ack_of);
    put_str(plain, payload.message_frame_id_hex);
    put_u16_le(plain, static_cast<uint16_t>(payload.reply_relays.size()));
    for (const auto& r : payload.reply_relays) put_str(plain, r);

    return crypto_sign_verify_detached(
               reinterpret_cast<const unsigned char*>(payload.signature.data()),
               reinterpret_cast<const unsigned char*>(plain.data()), plain.size(),
               reinterpret_cast<const unsigned char*>(payload.signer_pk.data())) == 0;
}

// ---------------------------------------------------------------------------
// Relay advertisement
// ---------------------------------------------------------------------------

std::string encode_relay_advert(const std::string& peer_id,
                                uint16_t capacity, uint8_t max_hops) {
    std::string body;
    put_str(body, peer_id);
    put_u16_le(body, capacity);
    body.push_back(static_cast<char>(max_hops));
    return body;
}

bool decode_relay_advert(std::string_view body, std::string& peer_id,
                         uint16_t& capacity, uint8_t& max_hops) {
    size_t off = 0;
    if (!get_str(body, off, peer_id)) return false;
    if (!get_u16_le(body, off, capacity)) return false;
    if (off + 1 > body.size()) return false;
    max_hops = static_cast<uint8_t>(body[off++]);
    return off == body.size();
}

// ---------------------------------------------------------------------------
// Relay-list exchange (PEX)
// ---------------------------------------------------------------------------

std::string encode_relay_pex(const std::vector<std::string>& relay_ids) {
    std::string body;
    put_u16_le(body, static_cast<uint16_t>(relay_ids.size()));
    for (const auto& r : relay_ids) put_str(body, r);
    return body;
}

bool decode_relay_pex(std::string_view body, std::vector<std::string>& out) {
    size_t off = 0;
    uint16_t n = 0;
    if (!get_u16_le(body, off, n)) return false;
    out.clear();
    out.reserve(n);
    for (uint16_t i = 0; i < n; ++i) {
        std::string r;
        if (!get_str(body, off, r)) return false;
        out.push_back(std::move(r));
    }
    return off == body.size();
}

// ---------------------------------------------------------------------------
// Outer frame
// ---------------------------------------------------------------------------

void random_frame_id(uint8_t out[kFrameIdSize]) {
    if (sodium_ready()) {
        randombytes_buf(out, kFrameIdSize);
    } else {
        for (size_t i = 0; i < kFrameIdSize; ++i) out[i] = static_cast<uint8_t>(i * 31);
    }
}

std::string frame_id_to_hex(const uint8_t id[kFrameIdSize]) {
    static const char* hexd = "0123456789abcdef";
    std::string out;
    out.reserve(kFrameIdSize * 2);
    for (size_t i = 0; i < kFrameIdSize; ++i) {
        out.push_back(hexd[id[i] >> 4]);
        out.push_back(hexd[id[i] & 0xF]);
    }
    return out;
}

std::string encode_frame(uint8_t flags, uint8_t ttl,
                         const uint8_t frame_id[kFrameIdSize], std::string_view body) {
    std::string out;
    out.reserve(kLpx2HeaderSize + kPadFieldSize + body.size());
    out.append(kLpx2Magic, 4);
    out.push_back(static_cast<char>(kLpx2Version));
    out.push_back(static_cast<char>(flags));
    out.push_back(static_cast<char>(ttl));
    out.push_back('\0');
    out.append(reinterpret_cast<const char*>(frame_id), kFrameIdSize);
    out.push_back('\0');  // pad_len u16 = 0 (no padding by default)
    out.push_back('\0');
    out.append(body.data(), body.size());
    return out;
}

bool decode_frame(std::string_view data, OverlayFrameHeader& hdr,
                  std::string_view& body) {
    if (data.size() < kLpx2HeaderSize + kPadFieldSize) return false;
    if (std::memcmp(data.data(), kLpx2Magic, 4) != 0) return false;
    hdr.version = static_cast<uint8_t>(data[4]);
    if (hdr.version != kLpx2Version) return false;
    hdr.flags = static_cast<uint8_t>(data[5]);
    hdr.ttl = static_cast<uint8_t>(data[6]);
    hdr.reserved = static_cast<uint8_t>(data[7]);
    std::memcpy(hdr.frame_id, data.data() + 8, kFrameIdSize);
    hdr.pad_len = static_cast<size_t>(static_cast<uint8_t>(data[24])) |
                  (static_cast<size_t>(static_cast<uint8_t>(data[25])) << 8);

    const size_t body_off = kLpx2HeaderSize + kPadFieldSize;
    if (data.size() < body_off + hdr.pad_len) return false;
    body = data.substr(body_off, data.size() - body_off - hdr.pad_len);
    return true;
}

void pad_wire_frame(std::string& wire, size_t bucket) {
    if (wire.size() < kLpx2HeaderSize + kPadFieldSize) return;
    if (std::memcmp(wire.data(), kLpx2Magic, 4) != 0) return;

    // Strip any previous padding before re-padding (fresh random bytes each time).
    const size_t old_pad = static_cast<size_t>(static_cast<uint8_t>(wire[24])) |
                           (static_cast<size_t>(static_cast<uint8_t>(wire[25])) << 8);
    const size_t body_off = kLpx2HeaderSize + kPadFieldSize;
    if (wire.size() < body_off + old_pad) return;
    wire.resize(wire.size() - old_pad);

    size_t new_pad = 0;
    if (bucket > 1) {
        const size_t remainder = wire.size() % bucket;
        if (remainder != 0) new_pad = bucket - remainder;
    }
    if (new_pad > 4096) new_pad = 4096;  // u16 field cap

    wire[24] = static_cast<char>(new_pad & 0xFF);
    wire[25] = static_cast<char>((new_pad >> 8) & 0xFF);

    if (new_pad > 0) {
        std::string pad(new_pad, '\0');
        if (sodium_ready()) randombytes_buf(&pad[0], pad.size());
        wire.append(pad);
    }
}

// Envelope layout (all integers little-endian):
//   [0..3]   magic "OBF1"
//   [4..35]  sender X25519 public key (32)
//   [36..59] secretbox nonce (24)
//   [60..61] pad_len (u16) — trailing pad bytes OUTSIDE the AEAD ciphertext
//   [62..]   secretbox(ciphertext + MAC)  (encrypts the UNPADDED plaintext)
//   [...+pad_len]  random pad bytes (cover traffic; ignored on unwrap)
//
// The shared secret is X25519 (crypto_box_beforenm) between the sender's
// STATIC secret key and the RECEIVER's static public key — no new key exchange
// is needed; the same Noise static keys already exchanged are reused.
// `pad_to_bucket`: 0 = no padding, else the TOTAL envelope length is padded to
// the next bucket multiple so the wire distribution hides message sizes.
// ---------------------------------------------------------------------------
std::string obfuscate_wrap(const std::vector<uint8_t>& receiver_public_key,
                           const std::vector<uint8_t>& local_secret_key,
                           std::string_view plaintext, size_t pad_to_bucket) {
    if (!sodium_ready()) return {};
    if (receiver_public_key.size() != crypto_box_PUBLICKEYBYTES ||
        local_secret_key.size() != crypto_box_SECRETKEYBYTES) {
        return {};
    }

    // Shared secret: X25519 between our static secret key and the receiver's
    // static public key (the same keys already exchanged for Noise NK).
    unsigned char k[crypto_box_BEFORENMBYTES];
    if (crypto_box_beforenm(k, receiver_public_key.data(), local_secret_key.data()) != 0) {
        return {};
    }

    unsigned char sender_pk[crypto_box_PUBLICKEYBYTES];
    if (crypto_scalarmult_base(sender_pk, local_secret_key.data()) != 0) return {};

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    // Cover-traffic padding: pad the TOTAL envelope to the requested bucket so
    // wire sizes are uniform. Padding sits OUTSIDE the AEAD (plaintext length
    // is preserved exactly); pad_len travels in clear (it is not secret).
    constexpr size_t kFixed = 4 + 32 + crypto_secretbox_NONCEBYTES + 2;
    size_t pad_len = 0;
    if (pad_to_bucket > 1) {
        const size_t total = kFixed + crypto_secretbox_MACBYTES + plaintext.size();
        const size_t remainder = total % pad_to_bucket;
        if (remainder != 0) pad_len = pad_to_bucket - remainder;
        if (pad_len > 4096) pad_len = 4096;  // u16 cap
    }

    std::string out;
    out.reserve(kFixed + crypto_secretbox_MACBYTES + plaintext.size() + pad_len);
    out.append("OBF1", 4);
    out.append(reinterpret_cast<const char*>(sender_pk), sizeof(sender_pk));
    out.append(reinterpret_cast<const char*>(nonce), sizeof(nonce));
    out.push_back(static_cast<char>(pad_len & 0xFF));
    out.push_back(static_cast<char>((pad_len >> 8) & 0xFF));

    std::string ct(crypto_secretbox_MACBYTES + plaintext.size(), '\0');
    if (crypto_secretbox_easy(reinterpret_cast<unsigned char*>(&ct[0]),
                              reinterpret_cast<const unsigned char*>(plaintext.data()),
                              plaintext.size(), nonce, k) != 0) {
        return {};
    }
    out.append(ct);

    if (pad_len > 0) {
        std::string pad(pad_len, '\0');
        randombytes_buf(&pad[0], pad.size());
        out.append(pad);
    }
    return out;
}

bool obfuscate_unwrap(const std::vector<uint8_t>& local_public_key,
                      const std::vector<uint8_t>& local_secret_key,
                      std::string_view envelope, std::string& plaintext) {
    if (!sodium_ready()) return false;
    if (envelope.size() < 4 + 32 + crypto_secretbox_NONCEBYTES + 2 + crypto_secretbox_MACBYTES) {
        return false;
    }
    if (std::memcmp(envelope.data(), "OBF1", 4) != 0) return false;
    if (local_public_key.size() != crypto_box_PUBLICKEYBYTES ||
        local_secret_key.size() != crypto_box_SECRETKEYBYTES) {
        return false;
    }

    const unsigned char* sender_pk =
        reinterpret_cast<const unsigned char*>(envelope.data() + 4);
    const unsigned char* nonce =
        reinterpret_cast<const unsigned char*>(envelope.data() + 4 + 32);
    const size_t pad_len = static_cast<size_t>(static_cast<uint8_t>(envelope[60])) |
                           (static_cast<size_t>(static_cast<uint8_t>(envelope[61])) << 8);

    const size_t fixed = 4 + 32 + crypto_secretbox_NONCEBYTES + 2;
    if (envelope.size() < fixed + crypto_secretbox_MACBYTES + pad_len) return false;
    const size_t ct_len = envelope.size() - fixed - pad_len;
    const unsigned char* ct =
        reinterpret_cast<const unsigned char*>(envelope.data() + fixed);

    unsigned char k[crypto_box_BEFORENMBYTES];
    if (crypto_box_beforenm(k, sender_pk, local_secret_key.data()) != 0) return false;

    std::string pt(ct_len - crypto_secretbox_MACBYTES, '\0');
    if (crypto_secretbox_open_easy(reinterpret_cast<unsigned char*>(&pt[0]),
                                   ct, ct_len, nonce, k) != 0) {
        return false;
    }
    (void)local_public_key;
    plaintext = std::move(pt);
    return true;
}

} // namespace overlay
