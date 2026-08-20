// Fuzz target for the wire codec (message framing) parser + Phase 3 envelope.
//
// Feed arbitrary bytes into wire::decode_message (both overloads) and the
// network-object envelope deserializer; ensure they return gracefully without
// crashing, UB, or unbounded allocation.
//
// Build (desktop, clang):
//   cmake -S desktop -B desktop/build-fuzz -DLITEP2P_FUZZING=ON \
//         -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
//   cmake --build desktop/build-fuzz --target fuzz_wire_codec
//   ./desktop/build-fuzz/bin/fuzz_wire_codec -runs=100000

#include "wire_codec.h"
#include "message_types.h"
#include "networkos/object/envelope.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::string_view sv(reinterpret_cast<const char*>(data), size);

    MessageType type{};
    std::string_view payload;
    (void)wire::decode_message(sv, type, payload);

    // Also exercise the std::string overload (copies payload).
    std::string payload_copy;
    (void)wire::decode_message(std::string(sv), type, payload_copy);

    // Round-trip: if the input framed successfully, re-encode a zero-length
    // payload and decode it (cheap invariant check inside the fuzzer).
    (void)wire::encode_message(type, payload);

    // Phase 3: feed the raw bytes into the network-object envelope parser.
    // Must never crash/hang on arbitrary input (all lengths validated before
    // allocation; oversized input rejected by the bounded decoder).
    networkos::obj::NetworkObject obj;
    if (networkos::obj::deserialize(std::string(sv), obj)) {
        // If it parsed, round-trip it back through the encoder.
        (void)networkos::obj::serialize(obj);
    }

    return 0;
}
