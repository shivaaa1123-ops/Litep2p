package com.zeengal.litep2p.core

import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicReference

/**
 * LiteP2P engine — the public Kotlin API for Android (api-spec.md §4).
 *
 * This is a process-wide singleton mirroring the one-engine-per-process C ABI
 * (litep2p.h §3.5). There is no instance construction and no `close()`; call
 * [shutdown] to stop the engine and release native state.
 *
 * Typical usage:
 * ```
 * LiteP2P.addListener(myListener)
 * LiteP2P.init(
 *     LiteP2PConfig.Builder()
 *         .filesDir(context.filesDir.absolutePath)
 *         .peerId(peerId)
 *         .commsMode(CommsMode.UDP)
 *         .build()
 * )
 * LiteP2P.start()               // completion via LiteP2PListener.onEngineStarted
 * ```
 *
 * Threading: safe to call from any thread. Listener callbacks are dispatched on
 * an internal engine thread and are NOT posted to the main thread (api-spec.md §4.1).
 *
 * Phase 3 status: the JNI bridge is re-pointed onto the public C ABI
 * (litep2p.h). Every method here maps to a `litep2p_*` function; the engine is
 * owned by the C ABI layer, not the binding. [disconnect] still returns
 * [EngineResult.UNSUPPORTED] because the engine has no per-peer disconnect API
 * yet (tracked in litep2p_c_api.cpp); file transfer is not yet part of the
 * Kotlin surface.
 */
object LiteP2P {

    private const val TAG = "LiteP2P"

    /** Matches litep2p.h LITEP2P_VERSION (0.3.0). */
    const val version: String = "0.3.0"

    private val listeners = CopyOnWriteArrayList<LiteP2PListener>()
    private val stateRef = AtomicReference(EngineState.STOPPED)

    @Volatile
    private var config: LiteP2PConfig? = null

    @Volatile
    private var initialized: Boolean = false

    /** Current engine lifecycle state. */
    val state: EngineState get() = stateRef.get()

    /**
     * The local peer id. Once the engine has started this returns the resolved id
     * (engine-generated when none was configured); before start it falls back to
     * the configured id, or empty.
     */
    val peerId: String
        get() {
            val resolved = runCatching { LiteP2PNative.nativeGetPeerId() }.getOrDefault("")
            return resolved.ifEmpty { config?.peerId.orEmpty() }
        }

    /* ------------------------------------------------------------------ */
    /* Lifecycle                                                           */
    /* ------------------------------------------------------------------ */

    /**
     * Initializes the (single) engine for this process.
     *
     * Must be called before [start]. Calling again while the engine is running or
     * starting returns [EngineResult.INVALID_STATE]; calling again while stopped
     * simply replaces the stored configuration.
     *
     * This forwards the full configuration to the C ABI (`litep2p_init`) and
     * registers the event callbacks that feed [LiteP2PListener].
     */
    @Synchronized
    fun init(config: LiteP2PConfig): EngineResult {
        val s = stateRef.get()
        if (s == EngineState.RUNNING || s == EngineState.STARTING) {
            return EngineResult.INVALID_STATE
        }
        this.config = config
        val rc = LiteP2PNative.nativeInit(
            peerId = config.peerId,
            commsMode = config.commsMode.wire,
            listenPort = config.listenPort,
            filesDir = config.filesDir,
            configPath = config.configPath,
            enableEncryption = config.encryptionEnabled,
            enableDiscovery = config.discoveryEnabled,
            enableFileTransfer = config.fileTransferEnabled,
            telemetryEnabled = config.telemetryEnabled,
            telemetryIntervalMs = config.telemetryIntervalMs,
            singleThreadMode = config.singleThreadMode
        )
        val result = EngineResult.fromCode(rc)
        initialized = result == EngineResult.OK
        return result
    }

    /**
     * Requests engine startup.
     *
     * The native call blocks until the engine is up (or fails); completion is
     * additionally reported via [LiteP2PListener.onEngineStarted]. Returns
     * [EngineResult.OK] if the engine started, [EngineResult.BUSY] if it is not
     * currently stopped, or [EngineResult.INVALID_STATE] if [init] was not called.
     */
    @Synchronized
    fun start(): EngineResult {
        val cfg = config
        if (!initialized || cfg == null) {
            return EngineResult.INVALID_STATE
        }
        val s = stateRef.get()
        if (s != EngineState.STOPPED) {
            return EngineResult.BUSY
        }

        stateRef.set(EngineState.STARTING)
        val rc = LiteP2PNative.nativeStart()
        val mapped = EngineResult.fromCode(rc)
        if (mapped != EngineResult.OK) {
            // Native refused; don't leave callers stuck in STARTING.
            stateRef.set(EngineState.STOPPED)
        }
        return mapped
    }

    /**
     * Requests asynchronous engine shutdown.
     *
     * Completion is reported via [LiteP2PListener.onEngineStopped]. Returns
     * [EngineResult.OK] if the stop was accepted.
     */
    @Synchronized
    fun stop(): EngineResult {
        val s = stateRef.get()
        if (s == EngineState.STOPPED || s == EngineState.STOPPING) {
            return EngineResult.OK
        }
        stateRef.set(EngineState.STOPPING)
        LiteP2PNative.nativeStop()
        return EngineResult.OK
    }

    /**
     * Stops the engine (if running) and releases wrapper state. Idempotent. After
     * this call [init] may be invoked again.
     */
    @Synchronized
    fun shutdown(): EngineResult {
        val s = stateRef.get()
        if (s == EngineState.RUNNING || s == EngineState.STARTING) {
            stop()
        }
        // Release native engine state so a later init() starts clean.
        LiteP2PNative.nativeShutdown()
        initialized = false
        config = null
        stateRef.set(EngineState.STOPPED)
        return EngineResult.OK
    }

    /* ------------------------------------------------------------------ */
    /* Listeners                                                           */
    /* ------------------------------------------------------------------ */

    fun addListener(listener: LiteP2PListener) {
        if (!listeners.contains(listener)) listeners.add(listener)
    }

    fun removeListener(listener: LiteP2PListener) {
        listeners.remove(listener)
    }

    /* ------------------------------------------------------------------ */
    /* Peer operations                                                     */
    /* ------------------------------------------------------------------ */

    /** Initiates a connection to a discovered peer. */
    fun connect(peerId: String): EngineResult {
        if (peerId.isBlank()) return EngineResult.INVALID_ARG
        return EngineResult.fromCode(LiteP2PNative.connect(peerId))
    }

    /** Registers a peer for rendezvous. */
    fun addPeer(peerId: String, networkId: String): EngineResult {
        if (peerId.isBlank()) return EngineResult.INVALID_ARG
        return EngineResult.fromCode(LiteP2PNative.addPeer(peerId, networkId))
    }

    /**
     * Disconnects a specific peer.
     *
     * Returns [EngineResult.UNSUPPORTED]: the engine has no per-peer disconnect
     * API yet (litep2p_c_api.cpp tracks this gap). The call is routed through the
     * C ABI so it will start working once the engine grows the capability.
     */
    fun disconnect(peerId: String): EngineResult {
        if (peerId.isBlank()) return EngineResult.INVALID_ARG
        return EngineResult.fromCode(LiteP2PNative.disconnect(peerId))
    }

    /** Whether a peer session is fully established. */
    fun isPeerConnected(peerId: String): Boolean {
        if (peerId.isBlank()) return false
        return LiteP2PNative.isPeerConnected(peerId)
    }

    /* ------------------------------------------------------------------ */
    /* Messaging                                                           */
    /* ------------------------------------------------------------------ */

    /**
     * Fire-and-forget send: [EngineResult.OK] means the message was accepted into
     * the send path, not that it was delivered (api-spec.md §3.8).
     */
    fun send(peerId: String, data: ByteArray): EngineResult {
        if (peerId.isBlank()) return EngineResult.INVALID_ARG
        if (data.isEmpty()) return EngineResult.INVALID_ARG
        return EngineResult.fromCode(LiteP2PNative.sendMessage(peerId, data))
    }

    /* ------------------------------------------------------------------ */
    /* Security (Noise NK)                                                 */
    /* ------------------------------------------------------------------ */

    /** Local static public key, hex-encoded, or "" when unavailable. */
    fun localPublicKeyHex(): String = LiteP2PNative.localPublicKeyHex()

    /** Registers a peer's Noise NK static public key (hex). */
    fun registerPeerKey(peerId: String, publicKeyHex: String): EngineResult {
        if (peerId.isBlank() || publicKeyHex.isBlank()) return EngineResult.INVALID_ARG
        return EngineResult.fromCode(LiteP2PNative.registerPeerKey(peerId, publicKeyHex))
    }

    /* ------------------------------------------------------------------ */
    /* Proxy / relay                                                       */
    /* ------------------------------------------------------------------ */

    /**
     * Applies proxy roles. Safe to call while running, so roles can change live.
     *
     * Maps the boolean toggles onto the C ABI string-role model
     * (`litep2p_set_proxy_role`): both -> "both", gateway only -> "gateway",
     * client only -> "client", neither -> "off".
     */
    fun configureProxy(enableGateway: Boolean, enableClient: Boolean): EngineResult =
        EngineResult.fromCode(LiteP2PNative.nativeConfigureProxy(enableGateway, enableClient))

    /* ------------------------------------------------------------------ */
    /* Overlay / multi-hop routing (censorship-resistance layer)            */
    /* ------------------------------------------------------------------ */

    /**
     * Sends [data] through the onion-lite overlay (multi-hop sealed relays) to
     * [peerId]. Register the peer's Noise NK static key first
     * ([registerPeerKey]) and at least one relay
     * ([registerRelay] or `overlay.relay_peers` in config.json).
     *
     * @param wantAck request bounded reliable delivery — completion arrives via
     *   [LiteP2PListener.onOverlayDelivery] with the returned frame id.
     * @param viaMailbox hold the message at the terminal relay until the peer
     *   collects it (offline delivery).
     * @return the 32-char frame id, or `null` on failure.
     */
    fun sendOverlay(
        peerId: String,
        data: ByteArray,
        wantAck: Boolean = false,
        viaMailbox: Boolean = false
    ): String? {
        if (peerId.isBlank() || data.isEmpty()) return null
        return LiteP2PNative.sendOverlay(peerId, data, wantAck, viaMailbox).ifEmpty { null }
    }

    /** Collect any mailboxes [relayPeerId] is holding for this device. */
    fun pickupMailbox(relayPeerId: String): EngineResult {
        if (relayPeerId.isBlank()) return EngineResult.INVALID_ARG
        return EngineResult.fromCode(LiteP2PNative.pickupMailbox(relayPeerId))
    }

    /**
     * Adds a relay candidate (from a bootstrap list, QR code, etc.).
     * [persistent] keeps it in the table regardless of advertisement freshness.
     */
    fun registerRelay(
        peerId: String,
        capacity: Int = 32,
        maxHops: Int = 4,
        persistent: Boolean = true
    ): EngineResult {
        if (peerId.isBlank()) return EngineResult.INVALID_ARG
        return EngineResult.fromCode(LiteP2PNative.registerRelay(peerId, capacity, maxHops, persistent))
    }

    /**
     * Registers a peer's Ed25519 signing public key (hex) as the trust anchor
     * for origin authentication. After this, overlay messages claiming to come
     * from [peerId] must be signed by this exact key or they are dropped.
     */
    fun registerPeerSigningKey(peerId: String, publicKeyHex: String): EngineResult {
        if (peerId.isBlank() || publicKeyHex.isBlank()) return EngineResult.INVALID_ARG
        return EngineResult.fromCode(LiteP2PNative.registerPeerSigningKey(peerId, publicKeyHex))
    }

    /** Opt in/out of forwarding frames and holding mailboxes for other peers. */
    fun setOverlayRelayEnabled(enabled: Boolean): EngineResult =
        EngineResult.fromCode(LiteP2PNative.nativeSetOverlayRelayEnabled(enabled))

    /** Overlay counters as single-line JSON, or "" when unavailable. */
    fun overlayStats(): String = LiteP2PNative.overlayStats()

    /* ------------------------------------------------------------------ */
    /* Environment hints                                                   */
    /* ------------------------------------------------------------------ */

    /** Environment hint: drives signaling/NAT recovery in the native engine. */
    fun setNetworkInfo(isWifi: Boolean, networkAvailable: Boolean): EngineResult =
        EngineResult.fromCode(LiteP2PNative.setSystemNetworkInfo(isWifi, networkAvailable))

    /** Battery hint: drives reconnect/keepalive aggressiveness. */
    fun setBatteryLevel(percent: Int, isCharging: Boolean): EngineResult =
        EngineResult.fromCode(LiteP2PNative.setBatteryLevel(percent, isCharging))

    /** Reconnect aggressiveness. */
    fun setReconnectMode(mode: ReconnectMode): EngineResult =
        EngineResult.fromCode(LiteP2PNative.setReconnectMode(mode.wire))

    /** Logging level: 0=DEBUG 1=INFO 2=WARN 3=ERROR. */
    fun setLogLevel(level: LogLevel): EngineResult =
        EngineResult.fromCode(LiteP2PNative.setLogLevel(level.level))

    /* ------------------------------------------------------------------ */
    /* Diagnostics                                                         */
    /* ------------------------------------------------------------------ */

    /**
     * Telemetry snapshot as single-line JSON (api-spec.md §6). Pull-based; the
     * engine also pushes periodic snapshots via [LiteP2PListener.onTelemetry].
     * Returns "" when telemetry is disabled or the engine is not initialized.
     */
    fun telemetrySnapshot(): String = LiteP2PNative.telemetrySnapshot()

    /* ------------------------------------------------------------------ */
    /* Event dispatch (called by NativeEvents from engine threads)         */
    /* ------------------------------------------------------------------ */

    internal fun dispatchEngineStarted() {
        stateRef.set(EngineState.RUNNING)
        for (l in listeners) runCatching { l.onEngineStarted() }
    }

    internal fun dispatchEngineStopped() {
        stateRef.set(EngineState.STOPPED)
        for (l in listeners) runCatching { l.onEngineStopped() }
    }

    internal fun dispatchPeersChanged(peers: List<PeerInfo>) {
        for (l in listeners) runCatching { l.onPeersChanged(peers) }
    }

    internal fun dispatchMessageReceived(peerId: String, data: ByteArray) {
        for (l in listeners) runCatching { l.onMessageReceived(peerId, data) }
    }

    internal fun dispatchLog(level: LogLevel, line: String) {
        for (l in listeners) runCatching { l.onLog(level, line) }
    }

    internal fun dispatchTelemetry(json: String) {
        for (l in listeners) runCatching { l.onTelemetry(json) }
    }

    internal fun dispatchMessageAcked(messageId: String, sentTsMs: Long, recvTsMs: Long) {
        for (l in listeners) runCatching { l.onMessageAcked(messageId, sentTsMs, recvTsMs) }
    }

    internal fun dispatchOverlayDelivery(frameId: String, delivered: Boolean) {
        for (l in listeners) runCatching { l.onOverlayDelivery(frameId, delivered) }
    }
}
