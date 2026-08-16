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

    init {
        System.loadLibrary("litep2p")
    }
}