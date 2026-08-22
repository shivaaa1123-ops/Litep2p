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
#define LITEP2P_VERSION_MINOR 4
#endif
#ifndef LITEP2P_VERSION_PATCH
#define LITEP2P_VERSION_PATCH 0
#endif
#ifndef LITEP2P_VERSION_STRING
#define LITEP2P_VERSION_STRING "0.4.0"
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
#define LITEP2P_FEATURE_VOICE_CALL    (1u << 6)

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
    LITEP2P_ERR_QUEUE_FULL    = -10,  /* v0.4: send rejected, engine queue at capacity */
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
    int64_t last_seen_ms;        /* v0.4: epoch ms when the peer was last observed
                                  * online (session, discovery, or signaling);
                                  * 0 when never seen */
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

    /* Reliable-send delivery receipts (v0.4, ask.md §1). msg_id is the
     * caller-supplied id passed to litep2p_send_reliable().
     * status: 0=QUEUED 1=SENT 2=DELIVERED 3=FAILED.
     * reason: "OK" | "NO_ROUTE" | "PEER_OFFLINE" | "QUEUE_FULL" | "TIMEOUT"
     *         | "TTL_EXPIRED" | "CANCELLED" (machine-readable). */
    void (*on_delivery_status)(void* user_data, const char* msg_id,
                               int status, const char* reason);

    /* Presence updates (v0.4, ask.md §5). Fires for subscribed peers on
     * online/offline transitions. last_seen_ms is epoch ms of the last time
     * the peer was observed online (0 when unknown). */
    void (*on_presence)(void* user_data, const char* peer_id, int online,
                        int64_t last_seen_ms);

    /* Ping result (v0.4, ask.md §5). rtt_ms >= 0 on success, -1 when the
     * peer is unreachable within the timeout. */
    void (*on_ping_result)(void* user_data, const char* peer_id, int64_t rtt_ms);

    /* Alias lookup result (v0.4, ask.md §3). alias is the requested hash;
     * peer_id is "" when the alias is unregistered. online/last_seen_ms
     * reflect server-side presence knowledge. */
    void (*on_lookup_result)(void* user_data, const char* alias, const char* peer_id,
                             int online, int64_t last_seen_ms);

    /* Invite received (v0.4, ask.md §3). from_peer_id is the inviter. */
    void (*on_invite_received)(void* user_data, const char* from_peer_id);
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
/* Fire-and-forget send. LITEP2P_OK means "accepted into the send path", not
 * "delivered". Failure reasons (v0.4, ask.md honorable mention):
 *   LITEP2P_ERR_INVALID_STATE  engine not initialized / not RUNNING
 *   LITEP2P_ERR_NOT_FOUND      peer unknown (never discovered/added)
 *   LITEP2P_ERR_QUEUE_FULL     engine send queue at capacity — back off and
 *                              retry, or use litep2p_send_reliable() which
 *                              persists into the durable outbox instead. */
litep2p_result_t litep2p_send(const char* peer_id, const uint8_t* data, uint32_t len);

/* ------------------------------------------------------------------------ */
/* Reliable messaging (v0.4, ask.md §1) — at-least-once with engine receipts */
/* ------------------------------------------------------------------------ */
/* Send a message with delivery guarantees. msg_id is caller-supplied (unique
 * per message; the receiver dedupes on it). The engine persists the payload
 * into an outbox under files_dir, retries every retry_timeout_ms until the
 * peer ACKs or max_retries is exhausted, and — when the offline queue is
 * enabled and the peer has no session — stores the message on the signaling
 * server for delivery on the peer's next connect.
 *
 * Lifecycle is reported via on_delivery_status:
 *   QUEUED -> SENT -> DELIVERED | FAILED(reason).
 * Returns LITEP2P_OK when accepted into the persistent outbox. Plain
 * litep2p_send() semantics are unchanged (fire-and-forget). */
litep2p_result_t litep2p_send_reliable(const char* peer_id, const char* msg_id,
                                       const uint8_t* data, uint32_t len,
                                       int max_retries, uint32_t retry_timeout_ms);

/* Cancel a pending reliable send (no further retries / offline store).
 * Fires on_delivery_status(FAILED, "CANCELLED") when the id was known. */
litep2p_result_t litep2p_reliable_cancel(const char* msg_id);

/* ------------------------------------------------------------------------ */
/* Presence & reachability (v0.4, ask.md §5)                                 */
/* ------------------------------------------------------------------------ */
/* Cheap liveness probe without holding a full session open. The result is
 * delivered via on_ping_result: rtt_ms >= 0 on success, -1 after timeout. */
litep2p_result_t litep2p_ping(const char* peer_id, uint32_t timeout_ms);

/* Subscribe to server-assisted presence for a set of peers. The engine asks
 * the signaling server for current state and then receives transition
 * updates via on_presence. Works without holding an open session. */
litep2p_result_t litep2p_subscribe_presence(const char* const* peer_ids, uint32_t count);

/* ------------------------------------------------------------------------ */
/* Identity directory & invites (v0.4, ask.md §3)                            */
/* ------------------------------------------------------------------------ */
/* Register a stable lookup alias (e.g. SHA-256 of a normalized phone number)
 * for this peer on the signaling server. Alias values are opaque hashes —
 * the server never sees raw identifiers. Persisted server-side. */
litep2p_result_t litep2p_register_alias(const char* alias_hash);

/* Resolve an alias hash to a peer id (+ presence). Result delivered via
 * on_lookup_result; resolves even when the target peer is offline. */
litep2p_result_t litep2p_lookup_peer(const char* alias_hash);

/* Nudge a remote/offline peer to connect via a signaling push. The target
 * receives on_invite_received and typically responds with litep2p_connect(). */
litep2p_result_t litep2p_invite_peer(const char* peer_id);

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
/* Voice calls (§3.10a) — realtime audio between peers (optional module)      */
/* ------------------------------------------------------------------------ */
/* Call control mirrors the file-transfer offer/accept idiom. Audio frames   */
/* are fire-and-forget (no ACK/retransmit): the app supplies and consumes    */
/* raw codec bytes (e.g. PCM S16LE). The engine is codec-agnostic.            */

typedef struct litep2p_voice_offer {
    char call_id[64];
    char peer_id[128];
    char codec[32];              /* opaque codec name, e.g. "PCM_S16LE" */
    uint16_t sample_rate;        /* Hz, e.g. 16000 */
    uint8_t channels;            /* 1 = mono, 2 = stereo */
    uint8_t frame_ms;            /* audio frames per packet, e.g. 20 */
} litep2p_voice_offer_t;

/* Call states delivered via on_voice_call_state (values match VoiceCallState). */
#define LITEP2P_VOICE_STATE_IDLE      0
#define LITEP2P_VOICE_STATE_OUTGOING  1
#define LITEP2P_VOICE_STATE_RINGING   2
#define LITEP2P_VOICE_STATE_IN_CALL   3
#define LITEP2P_VOICE_STATE_ENDED     4

typedef struct litep2p_voice_callbacks {
    uint32_t struct_size;        /* = sizeof(litep2p_voice_callbacks) */
    void* user_data;
    /* Callee side: an incoming call offer; accept/decline it. */
    void (*on_voice_call_offered)(void* user_data, const litep2p_voice_offer_t* offer);
    /* Call state change on either side (state is LITEP2P_VOICE_STATE_*). */
    void (*on_voice_call_state)(void* user_data, const char* call_id,
                                const char* peer_id, int state, const char* detail);
    /* Incoming audio frame. data is valid only for the duration of the call. */
    void (*on_voice_frame)(void* user_data, const char* call_id,
                           const char* peer_id, const uint8_t* data, uint32_t len);
} litep2p_voice_callbacks_t;

litep2p_result_t litep2p_set_voice_call_callbacks(const litep2p_voice_callbacks_t* callbacks);

/* Offer a call to a connected peer. Returns the call id in out_call_id
 * (buf_len >= 64) on success. */
litep2p_result_t litep2p_start_voice_call(const char* peer_id, const char* codec,
                                          uint16_t sample_rate, uint8_t channels,
                                          uint8_t frame_ms,
                                          char* out_call_id, uint32_t buf_len);
litep2p_result_t litep2p_accept_voice_call(const char* call_id);
litep2p_result_t litep2p_decline_voice_call(const char* call_id);
litep2p_result_t litep2p_end_voice_call(const char* call_id);
/* Fire-and-forget audio frame; only valid while the call is IN_CALL. */
litep2p_result_t litep2p_send_voice_frame(const char* call_id,
                                          const uint8_t* data, uint32_t len);

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

/* ------------------------------------------------------------------------ */
/* Backpressure metrics (v0.4)                                               */
/* ------------------------------------------------------------------------ */
/* Number of plain-send events currently queued in the engine event loop
 * (accepted by litep2p_send() but not yet handed to the transport). Use to
 * gauge backpressure before sending bursts; litep2p_send() starts returning
 * LITEP2P_ERR_QUEUE_FULL once the internal limit is reached. */
uint32_t litep2p_pending_send_count(void);

/* Number of reliable sends currently in the durable outbox (QUEUED or SENT,
 * i.e. not yet DELIVERED/FAILED). Bounded by offline_queue.max_messages. */
uint32_t litep2p_reliable_pending_count(void);

/* Free memory returned by the engine (e.g. litep2p_telemetry_snapshot). */
void litep2p_free(void* ptr);

/* Logging level: 0=DEBUG 1=INFO 2=WARN 3=ERROR. */
litep2p_result_t litep2p_set_log_level(int level);

/* ------------------------------------------------------------------------ */
/* Network OS object runtime (Phases 3–12) — additive v0.4 surface          */
/* (master doc §54/§55; locked decision 10: singleton, no handles).         */
/*                                                                          */
/* The NOS runtime is an independent engine instance created lazily on the  */
/* first litep2p_nos_* call while the engine is RUNNING; it listens on      */
/* main_port + 11 so the two engines never bind the same socket. Delivery   */
/* events arrive via a single callback; status/diagnostics are pull JSON.   */
/* ------------------------------------------------------------------------ */
#define LITEP2P_FEATURE_NETWORK_OS    (1u << 7)

/* Wire protocol version this build speaks (negotiated per connection). */
#define LITEP2P_WIRE_PROTOCOL_VERSION 1

/* Per-send delivery policy (§55). Every field is clamped by
 * litep2p_delivery_policy_clamp() / the runtime — unsafe values never reach
 * the engine. NULL policy = documented defaults. */
typedef struct litep2p_delivery_policy {
    int64_t  ttl_ms;                /* clamped [60_000 .. 2_592_000_000]       */
    int32_t  priority;              /* clamped [0 .. ns.priority_ceiling]      */
    uint8_t  min_remote_copies;     /* clamped [0 .. 4]                        */
    uint8_t  desired_remote_copies; /* clamped [min .. 4]                      */
    int      require_receipt;       /* v1: receipts always on (clamped true)   */
    int      allow_store_and_forward; /* 0 => direct-only (NOT_FOUND if down)  */
    uint32_t max_payload_bytes;     /* clamped to ns cap / 16 MiB             */
} litep2p_delivery_policy_t;

/* Per-namespace registration policy (§53): quota, priority ceiling,
 * per-object cap, carrier permission, app protocol version tag. */
typedef struct litep2p_namespace_policy {
    const char* namespace_id;       /* [a-z0-9_-]{1,32}                        */
    uint64_t    quota_bytes;        /* per-namespace storage quota             */
    uint32_t    priority_ceiling;   /* clamped [0..255]                        */
    uint32_t    max_object_bytes;   /* clamped [1 .. 16 MiB]                   */
    int         allow_carrier;      /* third-party carriage permitted          */
    uint8_t     protocol_version;   /* app-level protocol version for this ns  */
} litep2p_namespace_policy_t;

/* Delivery state changes (DELIVERED / CONFIRMED / FAILED / TTL_EXPIRED ...).
 * json_event is a flat JSON object; cb runs on an engine thread — do not
 * block. Register NULL to unregister. */
typedef void (*litep2p_delivery_event_cb)(const char* json_event, void* user);

/* Wire protocol version of this build (for pre-connect capability checks). */
uint8_t litep2p_wire_protocol_version(void);

/* Clamp a caller-supplied policy in place (pure; safe to call anytime). */
void litep2p_delivery_policy_clamp(litep2p_delivery_policy_t* policy);

/* Register/replace a namespace policy (id validated, values clamped). */
litep2p_result_t litep2p_nos_register_namespace(
    const litep2p_namespace_policy_t* ns);

/* Sign + publish an object for `destination`. On LITEP2P_OK writes the hex
 * ObjectId into out_object_id (NUL-terminated). Accepted ≠ delivered —
 * subscribe to delivery events for final state. Errors: INVALID_ARG,
 * INVALID_STATE (not started), NOT_FOUND (direct-only w/o route), IO. */
litep2p_result_t litep2p_nos_send(const char* destination,
                                  const char* namespace_id,
                                  const uint8_t* payload, uint32_t len,
                                  const litep2p_delivery_policy_t* policy,
                                  char* out_object_id, uint32_t buf_len);

/* Cancel a not-yet-delivered object. Errors: NOT_FOUND, INVALID_STATE
 * (already delivered), INVALID_ARG. */
litep2p_result_t litep2p_nos_cancel(const char* object_id);

/* Delivery status as flat JSON (*out_json malloc'd; free with litep2p_free):
 * {"object_id","present","destination","namespace","ttl_ms","priority",
 *  "durability","desired_remote_copies"} */
litep2p_result_t litep2p_nos_status(const char* object_id, char** out_json);

/* Register/unregister the delivery-event callback. */
litep2p_result_t litep2p_nos_set_delivery_event_cb(
    litep2p_delivery_event_cb cb, void* user);

/* Public diagnostics snapshot (§48/§87) — stable keys, privacy-safe:
 * {"sdk_version","wire_protocol_version","config_fingerprint","state",
 *  "peer_id","connected_peers","objects_d0..d3plus","delivery",
 *  "anti_entropy","replication","resources"} (*out_json → litep2p_free). */
litep2p_result_t litep2p_nos_diagnostics(char** out_json);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LITEP2P_H */

