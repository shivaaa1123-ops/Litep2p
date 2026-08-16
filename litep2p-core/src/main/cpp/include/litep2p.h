/*
 * litep2p.h — LiteP2P public C ABI (THE PUBLIC CONTRACT).
 *
 * This header is the stable interface between integrators and the LiteP2P
 * engine. The C++ internals may change freely; this ABI changes only with a
 * major version bump (see docs/api-spec.md §3).
 *
 * Design decisions codified here (api-spec.md §9):
 *   - Process-wide singleton: NO handles. Initialize once with litep2p_init(),
 *     tear down with litep2p_shutdown().
 *   - litep2p_send() is fire-and-forget: LITEP2P_OK means "accepted into the
 *     send path", not "delivered". No engine-level delivery callback.
 *   - File-transfer receive is callback-accepted: nothing is written to disk
 *     until litep2p_accept_file_transfer() is called.
 *
 * Thread-safety: all functions are safe to call from any thread unless noted.
 * Callbacks may be invoked from engine threads; consumers must not block in them.
 */
#ifndef LITEP2P_H
#define LITEP2P_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------ */
/* Versioning (§3.3)                                                         */
/* ------------------------------------------------------------------------ */
/* The version is derived from gradle.properties LITEP2P_VERSION at build     */
/* time (CMake defines these macros); the values below are the fallback for   */
/* consumers that compile the header without the build system.                */
#ifndef LITEP2P_VERSION_MAJOR
#define LITEP2P_VERSION_MAJOR 0
#endif
#ifndef LITEP2P_VERSION_MINOR
#define LITEP2P_VERSION_MINOR 3
#endif
#ifndef LITEP2P_VERSION_PATCH
#define LITEP2P_VERSION_PATCH 0
#endif
#ifndef LITEP2P_VERSION_STRING
#define LITEP2P_VERSION_STRING "0.3.0"
#endif

/* Packed version: major<<16 | minor<<8 | patch. */
uint32_t litep2p_version(void);
/* Human-readable version string, e.g. "0.3.0". */
const char* litep2p_version_string(void);

/* ------------------------------------------------------------------------ */
/* Feature detection (compile-time module availability)                      */
/* ------------------------------------------------------------------------ */
/* Flags returned by litep2p_get_feature_flags(); each reflects whether the  */
/* corresponding module was compiled into this build. Safe to call before    */
/* litep2p_init() — the value is fixed for the lifetime of the process.      */
#define LITEP2P_FEATURE_FILE_TRANSFER (1u << 0)
#define LITEP2P_FEATURE_OVERLAY       (1u << 1)
#define LITEP2P_FEATURE_PROXY         (1u << 2)
#define LITEP2P_FEATURE_ENCRYPTION    (1u << 3)
#define LITEP2P_FEATURE_DISCOVERY     (1u << 4)
#define LITEP2P_FEATURE_TELEMETRY     (1u << 5)

/* Bitmask of LITEP2P_FEATURE_* for this build. */
uint32_t litep2p_get_feature_flags(void);

/* ------------------------------------------------------------------------ */
/* Result codes (§3.2)                                                       */
/* ------------------------------------------------------------------------ */
typedef enum litep2p_result {
    LITEP2P_OK                =   0,
    LITEP2P_ERR_INVALID_ARG   =  -1,
    LITEP2P_ERR_INVALID_STATE =  -2,  /* e.g. send before start */
    LITEP2P_ERR_BUSY          =  -3,  /* start/stop already in progress */
    LITEP2P_ERR_NOT_FOUND     =  -4,  /* unknown peer / transfer id */
    LITEP2P_ERR_IO            =  -5,
    LITEP2P_ERR_TIMEOUT       =  -6,
    LITEP2P_ERR_UNSUPPORTED   =  -7,  /* feature compiled out / not wired yet */
    LITEP2P_ERR_NO_ROUTE      =  -8,  /* overlay: no relay path available */
    LITEP2P_ERR_INTERNAL      = -99,
} litep2p_result_t;

const char* litep2p_result_string(litep2p_result_t result);

/* ------------------------------------------------------------------------ */
/* Configuration (§3.4)                                                      */
/* ------------------------------------------------------------------------ */
typedef struct litep2p_config {
    uint32_t struct_size;        /* = sizeof(litep2p_config); set by caller */

    const char* peer_id;         /* stable identity; NULL = engine generates one */
    const char* comms_mode;      /* "TCP" | "UDP" | "AUTO" */
    int listen_port;             /* 0 = engine default */
    const char* files_dir;       /* writable dir for config.json, keystore, peer DB */
    const char* config_path;     /* optional explicit config.json path; NULL = auto */

    /* Feature toggles (runtime-disable where supported). */
    int enable_encryption;       /* Noise NK sessions (default 1) */
    int enable_discovery;        /* LAN discovery (default 1) */
    int enable_file_transfer;    /* (default 1) */

    /* Telemetry. */
    int telemetry_enabled;       /* default 1 */
    int telemetry_interval_ms;   /* default 30000 */

    /* Threading. */
    int single_thread_mode;      /* default 0 (multi-thread); 1 = reduced threads */
} litep2p_config_t;

/* Populate a config with safe defaults. Callers may then override fields.
 * Always sets struct_size = sizeof(litep2p_config_t). */
void litep2p_config_init(litep2p_config_t* config);

/* ------------------------------------------------------------------------ */
/* Lifecycle (§3.5)                                                          */
/* ------------------------------------------------------------------------ */
typedef enum litep2p_state {
    LITEP2P_STATE_STOPPED  = 0,
    LITEP2P_STATE_STARTING = 1,
    LITEP2P_STATE_RUNNING  = 2,
    LITEP2P_STATE_STOPPING = 3,
} litep2p_state_t;

/* Initialize the (single) engine for this process. Must be called before
 * litep2p_start(). Calling again while the engine is RUNNING/STARTING/STOPPING
 * returns LITEP2P_ERR_INVALID_STATE; calling again while STOPPED simply replaces
 * the stored configuration (matches the Kotlin LiteP2P.init contract and lets the
 * Android harness re-init across stop/start cycles without a full shutdown). */
litep2p_result_t litep2p_init(const litep2p_config_t* config);

/* Start the engine asynchronously. Completion is reported via
 * on_engine_started. Returns LITEP2P_OK if the start was accepted. */
litep2p_result_t litep2p_start(void);

/* Stop the engine asynchronously. Completion is reported via
 * on_engine_stopped. Returns LITEP2P_OK if the stop was accepted. */
litep2p_result_t litep2p_stop(void);

/* Stop (if running) and release all engine state. Idempotent. After this call
 * litep2p_init() may be invoked again. */
litep2p_result_t litep2p_shutdown(void);

litep2p_state_t litep2p_get_state(void);

/* Copy the local peer id into buf (NUL-terminated). Returns the number of
 * bytes written (excluding NUL) on success, or a negative error code. */
litep2p_result_t litep2p_get_peer_id(char* buf, uint32_t buf_len);

/* ------------------------------------------------------------------------ */
/* Events and callbacks (§3.6)                                               */
/* ------------------------------------------------------------------------ */
typedef struct litep2p_peer_info {
    char peer_id[128];
    char ip[64];
    int port;
    int connected;               /* 0/1 */
    int latency;                 /* measured RTT in ms, -1 when unknown */
    char network_id[128];
    char connection_path[32];    /* "LAN_DIRECT" | "WAN_HOLE_PUNCH" | "TURN_RELAY"
                                  * | "SIGNALING_RELAY" | "UNKNOWN" */
    char fsm_state[32];          /* best-effort peer FSM state string */
} litep2p_peer_info_t;

typedef struct litep2p_callbacks {
    uint32_t struct_size;        /* = sizeof(litep2p_callbacks) */
    void* user_data;

    /* Lifecycle. */
    void (*on_engine_started)(void* user_data);
    void (*on_engine_stopped)(void* user_data);

    /* Peers — full snapshot each time. */
    void (*on_peers_changed)(void* user_data,
                             const litep2p_peer_info_t* peers, uint32_t count);

    /* Messaging — buffer valid only for the duration of the call. */
    void (*on_message_received)(void* user_data, const char* peer_id,
                                const uint8_t* data, uint32_t len);

    /* Logging — level: 0=DEBUG 1=INFO 2=WARN 3=ERROR. */
    void (*on_log)(void* user_data, int level, const char* line);

    /* Telemetry — single-line JSON snapshot (see api-spec.md §6). */
    void (*on_telemetry)(void* user_data, const char* json);

    /* Overlay reliable-send completion: frame_id + delivered (1/0). Fires for
     * want_ack overlay sends when the destination ACKs (delivered=1) or the
     * bounded retry budget is exhausted (delivered=0). */
    void (*on_overlay_delivery)(void* user_data, const char* frame_id, int delivered);
} litep2p_callbacks_t;

/* Register the event callbacks. Must be called before litep2p_start() to
 * receive lifecycle/peer/message events. May be re-registered at any time;
 * the engine copies the struct, so the caller's memory is not retained. */
litep2p_result_t litep2p_set_callbacks(const litep2p_callbacks_t* callbacks);

/* ------------------------------------------------------------------------ */
/* Peer operations (§3.7)                                                    */
/* ------------------------------------------------------------------------ */
litep2p_result_t litep2p_connect(const char* peer_id);
litep2p_result_t litep2p_add_peer(const char* peer_id, const char* network_id);
litep2p_result_t litep2p_disconnect(const char* peer_id);

litep2p_result_t litep2p_peer_is_connected(const char* peer_id, int* out_connected);
litep2p_result_t litep2p_peer_get_connection_path(const char* peer_id,
                                                  char* buf, uint32_t buf_len);

/* ------------------------------------------------------------------------ */
/* Messaging (§3.8) — fire-and-forget                                        */
/* ------------------------------------------------------------------------ */
litep2p_result_t litep2p_send(const char* peer_id, const uint8_t* data, uint32_t len);

/* ------------------------------------------------------------------------ */
/* Security — Noise NK (§3.9)                                                */
/* ------------------------------------------------------------------------ */
/* Local static public key, hex-encoded. buf_len must be >= 65. */
litep2p_result_t litep2p_get_local_public_key(char* buf, uint32_t buf_len);
litep2p_result_t litep2p_register_peer_key(const char* peer_id,
                                           const char* public_key_hex);
litep2p_result_t litep2p_has_peer_key(const char* peer_id, int* out_has_key);

/* ------------------------------------------------------------------------ */
/* File transfer (§3.10) — optional module                                   */
/* ------------------------------------------------------------------------ */
typedef struct litep2p_file_offer {
    char transfer_id[64];
    char peer_id[128];
    char file_name[256];
    uint64_t size_bytes;
} litep2p_file_offer_t;

typedef struct litep2p_transfer_callbacks {
    uint32_t struct_size;        /* = sizeof(litep2p_transfer_callbacks) */
    void* user_data;
    /* Sender side: progress/completion of an outgoing transfer. */
    void (*on_progress)(void* user_data, const char* transfer_id, float progress,
                        float bytes_per_sec);
    void (*on_completed)(void* user_data, const char* transfer_id, int success,
                         const char* error);
    /* Receiver side: an incoming transfer offer; accept with
     * litep2p_accept_file_transfer(save_path) or decline it. */
    void (*on_file_transfer_offered)(void* user_data,
                                     const litep2p_file_offer_t* offer);
} litep2p_transfer_callbacks_t;

litep2p_result_t litep2p_set_transfer_callbacks(const litep2p_transfer_callbacks_t* callbacks);

litep2p_result_t litep2p_send_file(const char* peer_id, const char* file_path,
                                   int priority, char* out_transfer_id, uint32_t buf_len);
litep2p_result_t litep2p_accept_file_transfer(const char* transfer_id,
                                              const char* save_path);
litep2p_result_t litep2p_decline_file_transfer(const char* transfer_id);
litep2p_result_t litep2p_pause_transfer(const char* transfer_id);
litep2p_result_t litep2p_resume_transfer(const char* transfer_id);
litep2p_result_t litep2p_cancel_transfer(const char* transfer_id);

/* ------------------------------------------------------------------------ */
/* Proxy / relay (§3.11) — optional module                                   */
/* ------------------------------------------------------------------------ */
/* role: "off" | "gateway" | "exit" | "client" | "both" */
litep2p_result_t litep2p_set_proxy_role(const char* role);

/* ------------------------------------------------------------------------ */
/* Overlay / multi-hop routing (§3.14) — censorship-resistance layer         */
/* ------------------------------------------------------------------------ */
/* The overlay routes application messages through N sealed relay hops       */
/* (onion-lite LPX2). Payloads are signed with the local Ed25519 key and     */
/* verified by the destination; `overlay.*` config.json keys control static  */
/* knobs (padding_bucket, obfuscate_transport, cover_interval_ms,            */
/* relay_peers, require_origin_auth). Runtime operations live here.          */

/* Opt in/out of forwarding frames and holding mailboxes for other peers.    */
/* Origin/destination roles need no opt-in. */
litep2p_result_t litep2p_set_overlay_relay_enabled(int enabled);

/* Send `data` through the overlay to `peer_id` (the peer's Noise NK static  */
/* key must be registered first — see litep2p_register_peer_key).            */
/*   want_ack    = request reliable delivery (ACK/fail via on_overlay_delivery) */
/*   via_mailbox = hold at the terminal relay until the peer collects it     */
/* On success fills out_frame_id (32 hex chars) and returns LITEP2P_OK.      */
/* Errors: NOT_FOUND (no peer key), NO_ROUTE (no relay path), BUSY,          */
/*         INVALID_ARG (payload too large), INVALID_STATE, INTERNAL.         */
litep2p_result_t litep2p_send_overlay(const char* peer_id,
                                      const uint8_t* data, uint32_t len,
                                      int want_ack, int via_mailbox,
                                      char* out_frame_id, uint32_t buf_len);

/* Ask `relay_peer_id` to hand over any mailboxes it holds for us. */
litep2p_result_t litep2p_overlay_pickup_mailbox(const char* relay_peer_id);

/* Add a relay candidate (bootstrap list, QR code, etc.). persistent=1 keeps */
/* it regardless of advertisement freshness. */
litep2p_result_t litep2p_overlay_register_relay(const char* peer_id,
                                                int capacity, int max_hops,
                                                int persistent);

/* Register a peer's Ed25519 signing public key (64 hex chars) as the trust  */
/* anchor for origin authentication. Once registered, overlay payloads       */
/* claiming to be from `peer_id` must be signed by this exact key.           */
litep2p_result_t litep2p_overlay_register_peer_signing_key(const char* peer_id,
                                                           const char* public_key_hex);

/* Overlay counters as single-line JSON (malloc'd; free with litep2p_free). */
litep2p_result_t litep2p_overlay_stats(char** out_json);

/* ------------------------------------------------------------------------ */
/* Environment hints (§3.12)                                                 */
/* ------------------------------------------------------------------------ */
litep2p_result_t litep2p_set_network_info(int is_wifi, int network_available);
litep2p_result_t litep2p_set_battery_level(int percent, int is_charging);
/* mode: "auto" | "aggressive" | "balanced" | "power_saver" */
litep2p_result_t litep2p_set_reconnect_mode(const char* mode);

/* ------------------------------------------------------------------------ */
/* Telemetry and diagnostics (§3.13)                                         */
/* ------------------------------------------------------------------------ */
/* Force an immediate snapshot. On success *out_json points to a malloc'd,
 * NUL-terminated JSON string the caller must free with litep2p_free(). Also
 * delivered via the on_telemetry callback when one is registered. */
litep2p_result_t litep2p_telemetry_snapshot(char** out_json);

/* Free memory returned by the engine (e.g. litep2p_telemetry_snapshot). */
void litep2p_free(void* ptr);

/* Logging level: 0=DEBUG 1=INFO 2=WARN 3=ERROR. */
litep2p_result_t litep2p_set_log_level(int level);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LITEP2P_H */

