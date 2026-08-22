package com.zeengal.litep2p.core

/**
 * Static binding to the native engine (internal to :litep2p-core).
 *
 * Phase 3: every entry point is a thin wrapper over the public C ABI
 * (`litep2p.h` / `litep2p_c_api.cpp`). The JNI implementations live in
 * `cpp/src/jni_bridge.cpp` (Java_com_zeengal_litep2p_core_LiteP2PNative_*) and
 * forward directly to `litep2p_*` functions; the bridge no longer owns a
 * `SessionManager`. The engine is a process-wide singleton owned by the C ABI.
 *
 * Methods are declared without @JvmStatic so they remain instance methods of the
 * Kotlin object, keeping the JNI signatures (JNIEnv*, jobject) stable.
 *
 * Return values are integer `litep2p_result_t` codes (see [EngineResult.fromCode])
 * unless the method returns a String/Boolean by contract.
 */
internal object LiteP2PNative {

    /* ------------------------------------------------------------------ */
    /* Lifecycle — integer C-ABI result codes                               */
    /* ------------------------------------------------------------------ */

    /**
     * Initializes the engine with the full configuration and registers the C ABI
     * event callbacks that forward into [NativeEvents]. Must be called before
     * [nativeStart]. Returns a `litep2p_result_t` code.
     */
    external fun nativeInit(
        peerId: String?,
        commsMode: String,
        listenPort: Int,
        filesDir: String,
        configPath: String?,
        enableEncryption: Boolean,
        enableDiscovery: Boolean,
        enableFileTransfer: Boolean,
        telemetryEnabled: Boolean,
        telemetryIntervalMs: Int,
        singleThreadMode: Boolean
    ): Int

    /**
     * Starts the engine. This call blocks until the engine is up (or fails); the
     * completion event is still delivered via [NativeEvents.onEngineStartComplete].
     * Returns a `litep2p_result_t` code.
     */
    external fun nativeStart(): Int

    /** Requests asynchronous shutdown; completion arrives via onEngineStopComplete(). */
    external fun nativeStop(): Int

    /** Stops (if running) and releases all native engine state. Idempotent. */
    external fun nativeShutdown(): Int

    /** Current `litep2p_state_t` code (see [EngineState.fromCode]). */
    external fun nativeGetState(): Int

    /** Resolved local peer id (engine-generated when none was configured), or "". */
    external fun nativeGetPeerId(): String

    /**
     * Pushes platform device info (JSON object string: brand/model/os/abi/sdk)
     * into the engine's AnomalyReporter so incident files identify the device.
     * Safe to call before/after start; idempotent.
     */
    external fun nativeSetAnomalyDeviceInfo(json: String)

    /** Resolved incident-log directory ("" when the reporter is disabled). */
    external fun nativeGetAnomalyDirectory(): String

    /**
     * Phase 8 lifecycle bridge: push a platform signal into the NOS runtime
     * ("connectivity"/"metered"/"battery"/"charging"/"storage"/"foreground"/
     * "wakeup_window"). Returns a `litep2p_result_t` code; safe from any
     * thread. Lazily creates the NOS runtime like every litep2p_nos_* call.
     */
    external fun nativeNosPlatformSignal(signal: String, value: String): Int

    /* ------------------------------------------------------------------ */
    /* Peer operations                                                      */
    /* ------------------------------------------------------------------ */

    /** Initiates a connection to a discovered peer. */
    external fun connect(peerId: String): Int

    /** Registers a peer for rendezvous. */
    external fun addPeer(peerId: String, networkId: String): Int

    /** Disconnects a specific peer. */
    external fun disconnect(peerId: String): Int

    /** Whether a peer session is fully established. */
    external fun isPeerConnected(peerId: String): Boolean

    /* ------------------------------------------------------------------ */
    /* Messaging                                                            */
    /* ------------------------------------------------------------------ */

    /** Fire-and-forget message send (accepted into the send path, not delivered). */
    external fun sendMessage(peerId: String, message: ByteArray): Int

    /* ------------------------------------------------------------------ */
    /* Reliable messaging (v0.4)                                            */
    /* ------------------------------------------------------------------ */

    /**
     * At-least-once send with engine receipts. [msgId] is caller-supplied and
     * unique per message (the receiver dedupes on it). The engine persists the
     * payload into an outbox under filesDir, retries every [retryTimeoutMs]
     * until the peer ACKs or [maxRetries] is exhausted, and — when the offline
     * queue is enabled and the peer has no session — stores the message on the
     * signaling server. Lifecycle arrives via NativeEvents.onDeliveryStatus.
     */
    external fun sendReliable(
        peerId: String,
        msgId: String,
        data: ByteArray,
        maxRetries: Int,
        retryTimeoutMs: Int
    ): Int

    /** Cancels a pending reliable send (no further retries / offline store). */
    external fun cancelReliable(msgId: String): Int

    /* ------------------------------------------------------------------ */
    /* Presence & reachability (v0.4)                                       */
    /* ------------------------------------------------------------------ */

    /**
     * Cheap liveness probe. Result arrives via NativeEvents.onPingResult:
     * rttMs >= 0 on success, -1 after timeout.
     */
    external fun ping(peerId: String, timeoutMs: Int): Int

    /**
     * Subscribes to server-assisted presence for a set of peers. Updates arrive
     * via NativeEvents.onPresence. Works without holding an open session.
     */
    external fun subscribePresence(peerIds: Array<String>): Int

    /* ------------------------------------------------------------------ */
    /* Identity directory & invites (v0.4)                                  */
    /* ------------------------------------------------------------------ */

    /**
     * Registers a stable lookup alias (e.g. SHA-256 of a normalized phone
     * number) for this peer on the signaling server. Alias values are opaque
     * hashes — the server never sees raw identifiers.
     */
    external fun registerAlias(aliasHash: String): Int

    /**
     * Resolves an alias hash to a peer id (+ presence). Result arrives via
     * NativeEvents.onLookupResult; resolves even when the target is offline.
     */
    external fun lookupPeer(aliasHash: String): Int

    /**
     * Nudges a remote/offline peer to connect via a signaling push. The target
     * receives NativeEvents.onInviteReceived and typically responds with
     * [connect].
     */
    external fun invitePeer(peerId: String): Int

    /* ------------------------------------------------------------------ */
    /* Security (Noise NK)                                                  */
    /* ------------------------------------------------------------------ */

    /** Local static public key, hex-encoded, or "" when unavailable. */
    external fun localPublicKeyHex(): String

    /** Registers a peer's Noise NK static public key (hex). */
    external fun registerPeerKey(peerId: String, publicKeyHex: String): Int

    /* ------------------------------------------------------------------ */
    /* Overlay / multi-hop routing (censorship-resistance layer)            */
    /* ------------------------------------------------------------------ */

    /** Opt in/out of forwarding frames and holding mailboxes for other peers. */
    external fun nativeSetOverlayRelayEnabled(enabled: Boolean): Int

    /**
     * Send [data] through the onion-lite overlay to [peerId].
     * @return the 32-char frame id on success, or "" on failure
     * (register the peer's Noise NK key first — see [registerPeerKey]).
     */
    external fun sendOverlay(
        peerId: String,
        data: ByteArray,
        wantAck: Boolean,
        viaMailbox: Boolean
    ): String

    /** Collect any mailboxes [relayPeerId] is holding for us. */
    external fun pickupMailbox(relayPeerId: String): Int

    /** Add a relay candidate (bootstrap list, QR code, etc.). */
    external fun registerRelay(
        peerId: String,
        capacity: Int,
        maxHops: Int,
        persistent: Boolean
    ): Int

    /** Register a peer's Ed25519 signing public key (hex) as a trust anchor. */
    external fun registerPeerSigningKey(peerId: String, publicKeyHex: String): Int

    /** Overlay counters as single-line JSON, or "" on failure. */
    external fun overlayStats(): String

    /* ------------------------------------------------------------------ */
    /* File transfer (offer/accept model)                                  */
    /* ------------------------------------------------------------------ */

    /**
     * Sends a file to a connected peer. On success returns the transfer id;
     * returns "" on failure (e.g. peer not connected). Progress/completion are
     * reported through NativeEvents.onTransferProgress / onTransferCompleted.
     */
    external fun sendFile(peerId: String, filePath: String, priority: Int): String

    /** Accepts an incoming offer and writes the file to savePath. */
    external fun acceptFileTransfer(transferId: String, savePath: String): Int

    /** Declines an incoming offer. */
    external fun declineFileTransfer(transferId: String): Int

    /** Pauses an active transfer. */
    external fun pauseTransfer(transferId: String): Int

    /** Resumes a paused transfer. */
    external fun resumeTransfer(transferId: String): Int

    /** Cancels a transfer. */
    external fun cancelTransfer(transferId: String): Int

    /* ------------------------------------------------------------------ */
    /* Voice calls (realtime audio)                                        */
    /* ------------------------------------------------------------------ */

    /**
     * Offers a call to a connected peer. On success returns the call id;
     * returns "" on failure (peer not connected / busy). Offer/state events
     * are reported through NativeEvents.onVoiceCallOffered /
     * onVoiceCallStateChanged.
     */
    external fun startVoiceCall(
        peerId: String,
        codec: String,
        sampleRate: Int,
        channels: Int,
        frameMs: Int
    ): String

    /** Accepts an incoming call offer. */
    external fun acceptVoiceCall(callId: String): Int

    /** Declines an incoming call offer. */
    external fun declineVoiceCall(callId: String): Int

    /** Ends an active call (either side). */
    external fun endVoiceCall(callId: String): Int

    /** Sends one audio frame (fire-and-forget; only valid while IN_CALL). */
    external fun sendVoiceFrame(callId: String, data: ByteArray): Int

    /* ------------------------------------------------------------------ */
    /* Feature detection                                                   */
    /* ------------------------------------------------------------------ */

    /** Bitmask of LITEP2P_FEATURE_* for this build (litep2p_get_feature_flags). */
    external fun nativeGetFeatureFlags(): Int

    /* ------------------------------------------------------------------ */
    /* Proxy / relay                                                        */
    /* ------------------------------------------------------------------ */

    /** Applies proxy roles. Safe to call while running, so roles can change live. */
    external fun nativeConfigureProxy(enableGateway: Boolean, enableClient: Boolean): Int

    /* ------------------------------------------------------------------ */
    /* Environment hints                                                    */
    /* ------------------------------------------------------------------ */

    /** Environment hint: drives signaling/NAT recovery in the native engine. */
    external fun setSystemNetworkInfo(isWiFi: Boolean, isNetworkAvailable: Boolean): Int

    /** Battery hint: drives reconnect/keepalive aggressiveness. */
    external fun setBatteryLevel(percent: Int, isCharging: Boolean): Int

    /** Reconnect aggressiveness: "auto" | "aggressive" | "balanced" | "power_saver". */
    external fun setReconnectMode(mode: String): Int

    /* ------------------------------------------------------------------ */
    /* Diagnostics                                                          */
    /* ------------------------------------------------------------------ */

    /** Logging level: 0=DEBUG 1=INFO 2=WARN 3=ERROR. */
    external fun setLogLevel(level: Int): Int

    /** Pull-based telemetry snapshot as single-line JSON, or "" on failure. */
    external fun telemetrySnapshot(): String

    /* ------------------------------------------------------------------ */
    /* Backpressure metrics (v0.4)                                          */
    /* ------------------------------------------------------------------ */

    /** Plain-send events queued in the engine event loop (not yet sent). */
    external fun pendingSendCount(): Int

    /** Reliable sends in the durable outbox (QUEUED or SENT). */
    external fun reliablePendingCount(): Int

    /* ------------------------------------------------------------------ */
    /* Phase 12 — Network OS object runtime (litep2p_nos_* C ABI)          */
    /* ------------------------------------------------------------------ */

    /** Wire protocol version of this build (capability-negotiated). */
    external fun nosWireProtocolVersion(): Int

    /** Register/replace a namespace policy (values clamped natively). */
    external fun nosRegisterNamespace(
        namespaceId: String,
        quotaBytes: Long,
        priorityCeiling: Int,
        maxObjectBytes: Int,
        allowCarrier: Boolean,
        protocolVersion: Int,
    ): Int

    /**
     * Sign + publish an object. Returns the hex ObjectId when the code written
     * into [resultOut][0] is OK; empty string otherwise.
     */
    external fun nosSend(
        destination: String,
        namespaceId: String,
        payload: ByteArray,
        ttlMs: Long,
        priority: Int,
        minRemoteCopies: Int,
        desiredRemoteCopies: Int,
        requireReceipt: Boolean,
        allowStoreAndForward: Boolean,
        maxPayloadBytes: Int,
        resultOut: IntArray,
    ): String

    /** Cancel a not-yet-delivered object. */
    external fun nosCancel(objectId: String): Int

    /** Delivery status JSON for one object (null when not runnable). */
    external fun nosStatus(objectId: String): String?

    /** Public diagnostics snapshot JSON (null when not runnable). */
    external fun nosDiagnostics(): String?

    init {
        System.loadLibrary("litep2p")
    }
}