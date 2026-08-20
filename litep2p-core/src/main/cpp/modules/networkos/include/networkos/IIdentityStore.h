#pragma once

// Network OS — IIdentityStore (master doc §12 identity invariant, §19.1
// secure storage, §89 Phase 1).
//
// Contract: PeerID is STABLE across process restarts and IP changes. The
// identity store owns the create-once-then-persist rule; it never regenerates
// an existing identity. Key material stays in NoiseKeyStore (Phase 0 map 05);
// this interface only guarantees a stable peer identity and its key material
// reference.

#include <cstdint>
#include <string>
#include <vector>

#include "Runtime.h"

namespace networkos {

struct Identity {
    // Stable device identity, e.g. "litep2p-device-<mac>" or a persisted
    // random id (desktop fallback; persisted here so it survives restarts).
    std::string peer_id;

    // Where the Noise keystore (static keypair + signing keys) lives.
    std::string keystore_path;

    int64_t created_at_ms{0};

    bool valid() const { return !peer_id.empty(); }
};

class IIdentityStore {
public:
    virtual ~IIdentityStore() = default;

    // Load the persisted identity. kNotFound when none exists yet.
    virtual Result load(Identity& out) = 0;

    // Create once: resolve a stable peer id (prefer `preferred` if given,
    // else device-derived) and persist it. Never overwrites an existing id.
    // Returns the resolved identity.
    virtual Result create(const std::string& preferred, Identity& out) = 0;

    // Ensure an identity exists (load or create) and return it.
    virtual Result loadOrCreate(const std::string& preferred, Identity& out) = 0;

    // Export the raw identity record as JSON (diagnostics / backup).
    virtual Result exportJson(std::string& out_json) const = 0;
};

// File-backed identity store (desktop default and Android fallback). Writes
// are atomic (tmp file + rename). Path = files_dir + "/identity.json".
std::unique_ptr<IIdentityStore> createFileIdentityStore(const std::string& files_dir);

} // namespace networkos
