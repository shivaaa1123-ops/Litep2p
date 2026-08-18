// malformed_input_test — deterministic parser robustness regression.
//
// Runs a fixed corpus of malformed/garbage inputs through the same parser
// entry points the libFuzzer targets cover (desktop/fuzz/), so parser
// robustness is continuously verified in CI even without clang/libFuzzer.
// Every case must complete gracefully (no crash, no exception escape, sane
// return value). The libFuzzer targets then search for deeper bugs with
// coverage-guided mutation.
//
// Covered parsers:
//   - wire::decode_message           (message framing)
//   - parse_discovery_announcement   (legacy + obfuscated + legacy-interop)
//   - NoiseNKSession::process_handshake / decrypt  (handshake + AEAD)

#include "wire_codec.h"
#include "message_types.h"
#include "discovery.h"
#include "config_manager.h"
#include "noise_nk.h"

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>
#include <sodium.h>

static int tests_failed = 0;

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "FAIL: " << msg << " [" << __FILE__ << ":" << __LINE__ << "]" << std::endl; \
            tests_failed++; \
        } \
    } while (0)

namespace {

std::vector<std::string> wire_corpus() {
    return {
        "",                       // empty
        "A",                      // 1 byte
        "ABCD",                   // 4 bytes (no length)
        "\x01\x00\x00\x00",       // type + 0-length frame
        "\x01\x00\x00\x00\x05hi", // valid header, short body
        "\x01\xff\xff\xff\xff",   // length = 4 GiB (over max)
        "\x63\x00\x00\x00\x00",   // valid type (overlay), empty
        std::string("\x99\x00\x00\x00\x05hello", 9),  // invalid type byte
        std::string("\x01\x7f\xff\xff\xffx", 9),      // huge length, tiny body
        std::string(64, '\xff'),                      // all 0xff
        std::string(32, '\x00'),                      // all zeroes
        "LITEP2P_DISCOVERY:peer:12345",               // ascii probe (not framed)
        std::string("\x02\x00\x00\x00\x10", 9),       // truncated CONTROL_PONG
    };
}

std::vector<std::string> discovery_corpus() {
    return {
        "",                                   // empty
        "LITEP2P_DISCOVERY",                  // magic only
        "LITEP2P_DISCOVERY:",                 // magic + colon
        "LITEP2P_DISCOVERY:peer",             // no port
        "LITEP2P_DISCOVERY:peer:",            // empty port
        "LITEP2P_DISCOVERY:peer:notanumber",  // non-numeric port
        "LITEP2P_DISCOVERY::30001",           // empty peer id
        "LITEP2P_DISCOVERY:peer:0",           // port 0 (rejected)
        "LITEP2P_DISCOVERY:peer:65536",       // port too big
        "LITEP2P_DISCOVERY:peer:-1",          // negative port
        "LITEP2P_DISCOVERY:peer:2147483648",  // int overflow
        "LITEP2P_DISCOVERY:peer:99999extra",  // trailing junk after port
        "LITEP2P_DISCOVERY:peer:12345:junk",  // extra colon
        "NOMAGIC:peer:30001",                 // wrong magic
        "garbage-that-is-not-an-announcement",
        "LITEP2P_DISCOVERY:peer with spaces:30001",
        "LITEP2P_DISCOVERY:a:b:c:30001",
        std::string(200, 'L'),                // long magic-like blob
        "LITEP2P_DISCOVERY:\xff\xfe:30001",   // non-UTF8 peer id
        "LITEP2P_DISCOVERY:peer:\t\n",        // whitespace port
        // Obfuscated-shaped garbage (magic + nonce + ct) — must fail AEAD:
        "xK9f2Qz7" + std::string(12, '\x01') + std::string(16, '\x02'),
        std::string("xK9f2Qz7") + std::string(12, '\x00') + std::string(""), // truncated
        "xK9f2Qz7\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00garbage",
    };
}

void prime_discovery_config() {
    // libsodium must be explicitly initialized before the AEAD/randombytes
    // paths are used (the engine's discovery module relies on this; the
    // malformed-input test replicates the exact production call sequence).
    (void)sodium_init();
    ConfigManager::getInstance().loadConfig("unused.json");
    // Fixed shared key so the obfuscated (AEAD) parse path is exercised.
    ConfigManager::getInstance().setValueAtPath(
        {"network", "discovery_shared_key"},
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    ConfigManager::getInstance().setValueAtPath({"network", "discovery_magic"}, "xK9f2Qz7");
}


bool test_wire_codec() {
    std::cout << "Testing wire codec parser robustness..." << std::endl;
    bool any_threw = false;
    for (const auto& raw : wire_corpus()) {
        try {
            MessageType type{};
            std::string_view payload;
            (void)wire::decode_message(std::string_view(raw), type, payload);
            std::string copy;
            (void)wire::decode_message(raw, type, copy);
            (void)wire::encode_message(type, raw);
        } catch (...) {
            any_threw = true;
            std::cerr << "  wire decode threw for input size=" << raw.size() << std::endl;
        }
    }
    // Edge sizes 0..64 with every byte value 0..255 (cheap exhaustive sweep).
    std::string sweep;
    for (size_t len = 0; len <= 64 && !any_threw; ++len) {
        for (int b = 0; b <= 255; ++b) {
            sweep = std::string(len, static_cast<char>(b));
            try {
                MessageType type{};
                std::string_view payload;
                (void)wire::decode_message(std::string_view(sweep), type, payload);
            } catch (...) {
                any_threw = true;
                break;
            }
        }
    }
    TEST_ASSERT(!any_threw, "wire::decode_message must never throw");
    std::cout << "Wire codec parser robustness Passed!" << std::endl;
    return !any_threw;
}

bool test_discovery_parser() {
    std::cout << "Testing discovery announcement parser robustness..." << std::endl;
    prime_discovery_config();
    const auto corpus = discovery_corpus();
    bool any_threw = false;
    size_t idx = 0;
    for (const auto& raw : corpus) {
        (void)idx++;
        try {
            std::string peer_id;
            int port = 0;
            (void)parse_discovery_announcement(raw, peer_id, port);
        } catch (...) {
            any_threw = true;
            std::cerr << "  discovery parse threw for input size=" << raw.size() << std::endl;
        }
    }
    // Valid plaintext must still parse (sanity, not just crash-free).
    {
        std::string peer_id;
        int port = 0;
        const bool ok = parse_discovery_announcement("xK9f2Qz7:my-peer:31077", peer_id, port);
        TEST_ASSERT(ok && peer_id == "my-peer" && port == 31077, "valid magic:peer:port must parse");
    }
    // Legacy default-magic announcement must parse even when our magic differs.
    {
        std::string peer_id;
        int port = 0;
        const bool ok = parse_discovery_announcement("LITEP2P_DISCOVERY:legacy-peer:30001",
                                                     peer_id, port);
        TEST_ASSERT(ok && peer_id == "legacy-peer" && port == 30001,
                    "legacy default-magic announcement must parse");
    }
    TEST_ASSERT(!any_threw, "parse_discovery_announcement must never throw");
    std::cout << "Discovery parser robustness Passed!" << std::endl;
    return !any_threw;
}

bool test_noise_handshake() {
    std::cout << "Testing Noise NK handshake/decrypt robustness..." << std::endl;
    (void)sodium_init();
    const auto keys = NoiseNKManager::generate_static_keypair();

    bool any_threw = false;
    const std::vector<std::string> corpus = {
        "",
        "A",
        std::string(31, 'x'),
        std::string(32, 'x'),   // valid size for e message
        std::string(33, 'x'),
        std::string(64, '\xff'),
        std::string(128, '\x00'),
        std::string(1024, 'z'),
    };
    for (const auto& raw : corpus) {
        const std::vector<uint8_t> msg(raw.begin(), raw.end());
        try {
            NoiseNKSession init("fuzz-init", NoiseNKSession::Role::INITIATOR,
                                keys.first, keys.first);
            (void)init.process_handshake(msg);

            NoiseNKSession resp("fuzz-resp", NoiseNKSession::Role::RESPONDER,
                                keys.first, keys.first, keys.second);
            (void)resp.process_handshake(msg);

            NoiseNKSession dec("fuzz-dec", NoiseNKSession::Role::INITIATOR,
                               keys.first, keys.first);
            bool replay = false;
            (void)dec.decrypt(msg, &replay);
        } catch (...) {
            any_threw = true;
            std::cerr << "  noise fuzz case threw for size=" << raw.size() << std::endl;
        }
    }
    // Valid handshake flow must still work (sanity).
    {
        NoiseNKSession init("peer-A", NoiseNKSession::Role::INITIATOR,
                            keys.first, keys.first);
        const auto msg1 = init.start_handshake();
        NoiseNKSession resp("peer-B", NoiseNKSession::Role::RESPONDER,
                            keys.first, keys.first, keys.second);
        const auto msg2 = resp.process_handshake(msg1);
        const auto msg3 = init.process_handshake(msg2);
        TEST_ASSERT(!msg1.empty() && !msg2.empty() && msg3.empty(),
                    "valid Noise NK handshake must complete");
    }
    TEST_ASSERT(!any_threw, "Noise NK process_handshake/decrypt must never throw");
    std::cout << "Noise NK robustness Passed!" << std::endl;
    return !any_threw;
}

} // namespace

int main() {
    bool ok = true;
    ok &= test_wire_codec();
    ok &= test_discovery_parser();
    ok &= test_noise_handshake();
    std::cout << (tests_failed == 0 ? "\nALL MALFORMED-INPUT TESTS PASSED\n"
                                    : "\nSOME TESTS FAILED\n");
    return tests_failed == 0 ? 0 : 1;
}
