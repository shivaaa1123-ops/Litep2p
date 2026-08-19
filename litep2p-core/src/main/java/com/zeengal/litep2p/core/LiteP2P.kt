package com.zeengal.litep2p.core

import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * LiteP2P engine — the public Kotlin API for Android (api-spec.md §5).
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
 * Reactive usage (requires the coroutines/Flow adapters):
 * ```
 * launch {
 *     LiteP2P.messagesFlow.collect { println("${it.peerId}: ${it.data}") }
 * }
 * LiteP2P.startAndAwait()       // suspends until RUNNING or failure
 * ```
 *
 * Threading: safe to call from any thread. Listener callbacks are dispatched on
 * an internal engine thread and are NOT posted to the main thread (api-spec.md §11).
 *
 * Phase 3 status: the JNI bridge is re-pointed onto the public C ABI
 * (litep2p.h). Every method here maps to a `litep2p_*` function; the engine is
 * owned by the C ABI layer, not the binding. File transfer, overlay, proxy,
 * telemetry, and environment hints are all exposed on the Kotlin surface.
 */
object LiteP2P {

    private const val TAG = "LiteP2P"

    /**
     * SDK version, e.g. "0.3.0". Single-sourced from `gradle.properties`
     * (`LITEP2P_VERSION`) via [BuildConfig] and matches the C ABI
     * `litep2p_version_string()`.
     */
    val version: String = BuildConfig.LITEP2P_VERSION

    private val listeners = CopyOnWriteArrayList<LiteP2PListener>()
    private val _stateFlow = MutableStateFlow(EngineState.STOPPED)
    private val stateFlowView: StateFlow<EngineState> = _stateFlow.asStateFlow()

    @Volatile
    private var config: LiteP2PConfig? = null

    @Volatile
    private var initialized: Boolean = false

    /** Current engine lifecycle state. */
    val state: EngineState get() = _stateFlow.value

    /**
     * Observable engine lifecycle state.
     *
     * A [StateFlow]: collects the current value immediately and emits every
     * subsequent transition (`STOPPED → STARTING → RUNNING → STOPPING → STOPPED`).
     * Transitions are emitted from the engine thread that performs them; collect
     * from any dispatcher. Useful with [startAndAwait] / [stopAndAwait].
     */
    val stateFlow: StateFlow<EngineState> get() = stateFlowView

    /** Compile-time capabilities of the native build. Safe to query before [init]. */
    val capabilities: LiteP2PCapabilities
        get() {
            val flags = runCatching { LiteP2PNative.nativeGetFeatureFlags() }
                .getOrDefault(0)
            return LiteP2PCapabilities.fromFlags(flags)
        }

    /** True when the file-transfer module is compiled into this build. */
    fun supportsFileTransfer(): Boolean = capabilities.fileTransfer

    /** True when the realtime voice-call module is compiled into this build. */
    fun supportsVoiceCall(): Boolean = capabilities.voiceCall

    /** True when the multi-hop overlay module is compiled into this build. */
    fun supportsOverlay(): Boolean = capabilities.overlay

    /** True when the proxy/relay module is compiled into this build. */
    fun supportsProxy(): Boolean = capabilities.proxy

    /** True when Noise NK encryption is compiled into this build. */
    fun supportsEncryption(): Boolean = capabilities.encryption

    /**
     * Pushes platform device info (JSON object string: brand/model/os/abi/sdk)
     * into the engine's AnomalyReporter so incident files identify the device
     * that experienced the anomaly (field-data collection). [LiteP2PRuntime] /
     * [LiteP2PService] call this automatically; integrators using [init] directly
     * should call it once with their device facts. Idempotent, safe any time.
     */
    fun setAnomalyDeviceInfo(json: String) {
        runCatching { LiteP2PNative.nativeSetAnomalyDeviceInfo(json) }
    }

    /**
     * Absolute path of the incident-log directory ("" while disabled) — inspect
     * it from a terminal or `adb shell run-as <pkg> ls files/anomalies`.
     */
    fun anomaliesDirectory(): String =
        runCatching { LiteP2PNative.nativeGetAnomalyDirectory() }.getOrDefault("")

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
        val s = _stateFlow.value
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
        val s = _stateFlow.value
        if (s != EngineState.STOPPED) {
            return EngineResult.BUSY
        }

        _stateFlow.value = EngineState.STARTING
        val rc = LiteP2PNative.nativeStart()
        val mapped = EngineResult.fromCode(rc)
        if (mapped != EngineResult.OK) {
            // Native refused; don't leave callers stuck in STARTING.
            _stateFlow.value = EngineState.STOPPED
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
        val s = _stateFlow.value
        if (s == EngineState.STOPPED || s == EngineState.STOPPING) {
            return EngineResult.OK
        }
        _stateFlow.value = EngineState.STOPPING
        LiteP2PNative.nativeStop()
        return EngineResult.OK
    }

    /**
     * Stops the engine (if running) and releases wrapper state. Idempotent. After
     * this call [init] may be invoked again.
     */
    @Synchronized
    fun shutdown(): EngineResult {
        val s = _stateFlow.value
        if (s == EngineState.RUNNING || s == EngineState.STARTING) {
            stop()
        }
        // Release native engine state so a later init() starts clean.
        LiteP2PNative.nativeShutdown()
        initialized = false
        config = null
        _stateFlow.value = EngineState.STOPPED
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
     * Requests the engine to tear down the session with [peerId]: transport
     * connections are closed best-effort, the peer FSM is driven to
     * DISCONNECTED, and automatic reconnection for that peer is suppressed
     * until it is explicitly re-connected via [connect] or it establishes an
     * inbound connection. The peer's updated state is reported asynchronously
     * through [LiteP2PListener.onPeersChanged].
     *
     * Wired through the C ABI (`litep2p_disconnect`).
     *
     * @param peerId the stable peer id to disconnect.
     * @return [EngineResult.OK] when the peer is known to the engine and the
     *         disconnect was accepted; [EngineResult.NOT_FOUND] when the peer
     *         is not known to the engine; [EngineResult.INVALID_ARG] when
     *         [peerId] is blank; [EngineResult.INVALID_STATE] when the engine
     *         is not initialized or not running.
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
     *
     * Failure reasons (v0.4):
     *  - [EngineResult.INVALID_ARG] — blank peer id or empty payload
     *  - [EngineResult.INVALID_STATE] — engine not initialized / not running
     *  - [EngineResult.NOT_FOUND] — peer unknown (never discovered/added)
     *  - [EngineResult.QUEUE_FULL] — engine send queue at capacity; back off
     *    and retry, or use [sendReliable] which persists into the durable
     *    outbox instead. Check [pendingSendCount] to gauge backpressure.
     */
    fun send(peerId: String, data: ByteArray): EngineResult {
        if (peerId.isBlank()) return EngineResult.INVALID_ARG
        if (data.isEmpty()) return EngineResult.INVALID_ARG
        return EngineResult.fromCode(LiteP2PNative.sendMessage(peerId, data))
    }

    /* ------------------------------------------------------------------ */
    /* Reliable messaging (v0.4)                                            */
    /* ------------------------------------------------------------------ */

    /**
     * At-least-once send with engine receipts.
     *
     * The engine persists [data] into a durable outbox under `filesDir`,
     * retries every [retryTimeoutMs] until the peer ACKs or [maxRetries] is
     * exhausted, and — when the offline queue is enabled and the peer has no
     * session — stores the message on the signaling server for delivery on the
     * peer's next connect. The receiver dedupes on [msgId].
     *
     * Lifecycle is reported via [LiteP2PListener.onDeliveryStatus]:
     * `QUEUED -> SENT -> DELIVERED | FAILED(reason)`.
     *
     * @param peerId Destination peer id.
     * @param msgId Caller-supplied unique message id (UUID recommended).
     * @param data Payload (non-empty).
     * @param maxRetries Retry budget before FAILED(TIMEOUT). Defaults to 3.
     * @param retryTimeoutMs Retry interval in ms. Defaults to 10 000.
     * @return [EngineResult.OK] when accepted into the persistent outbox.
     */
    fun sendReliable(
        peerId: String,
        msgId: String,
        data: ByteArray,
        maxRetries: Int = 3,
        retryTimeoutMs: Int = 10_000
    ): EngineResult {
        if (peerId.isBlank() || msgId.isBlank() || data.isEmpty()) return EngineResult.INVALID_ARG
        return EngineResult.fromCode(
            LiteP2PNative.sendReliable(peerId, msgId, data, maxRetries, retryTimeoutMs)
        )
    }

    /**
     * Cancels a pending reliable send (no further retries / offline store).
     * Fires [LiteP2PListener.onDeliveryStatus] with FAILED/"CANCELLED" when the
     * id was known.
     */
    fun cancelReliable(msgId: String): EngineResult {
        if (msgId.isBlank()) return EngineResult.INVALID_ARG
        return EngineResult.fromCode(LiteP2PNative.cancelReliable(msgId))
    }

    /* ------------------------------------------------------------------ */
    /* Presence & reachability (v0.4)                                       */
    /* ------------------------------------------------------------------ */

    /**
     * Cheap liveness probe that does not require holding a full session open.
     * The result arrives asynchronously via [LiteP2PListener.onPingResult]:
     * `rttMs >= 0` on success, `-1` when the peer is unreachable within
     * [timeoutMs].
     */
    fun ping(peerId: String, timeoutMs: Int = 5_000): EngineResult {
        if (peerId.isBlank()) return EngineResult.INVALID_ARG
        return EngineResult.fromCode(LiteP2PNative.ping(peerId, timeoutMs))
    }

    /**
     * Subscribes to server-assisted presence for [peerIds]. The engine asks the
     * signaling server for current state and then delivers transition updates
     * via [LiteP2PListener.onPresence]. Works without holding an open session.
     */
    fun subscribePresence(peerIds: List<String>): EngineResult {
        val ids = peerIds.filter { it.isNotBlank() }
        if (ids.isEmpty()) return EngineResult.INVALID_ARG
        return EngineResult.fromCode(LiteP2PNative.subscribePresence(ids.toTypedArray()))
    }

    /* ------------------------------------------------------------------ */
    /* Identity directory & invites (v0.4)                                  */
    /* ------------------------------------------------------------------ */

    /**
     * Registers a stable lookup alias for this peer on the signaling server.
     *
     * Alias values are expected to be opaque hashes (e.g. SHA-256 of a
     * normalized phone number) — the server never sees raw identifiers. The
     * registration is persisted server-side so other devices can resolve it
     * with [lookupPeer] even while this device is offline.
     */
    fun registerAlias(aliasHash: String): EngineResult {
        if (aliasHash.isBlank()) return EngineResult.INVALID_ARG
        return EngineResult.fromCode(LiteP2PNative.registerAlias(aliasHash))
    }

    /**
     * Resolves an alias hash to a peer id (+ presence). The result arrives
     * asynchronously via [LiteP2PListener.onLookupResult]; resolves even when
     * the target peer is offline.
     */
    fun lookupPeer(aliasHash: String): EngineResult {
        if (aliasHash.isBlank()) return EngineResult.INVALID_ARG
        return EngineResult.fromCode(LiteP2PNative.lookupPeer(aliasHash))
    }

    /**
     * Nudges a remote/offline peer to connect via a signaling push. The target
     * receives [LiteP2PListener.onInviteReceived] and typically responds with
     * [connect].
     */
    fun invitePeer(peerId: String): EngineResult {
        if (peerId.isBlank()) return EngineResult.INVALID_ARG
        return EngineResult.fromCode(LiteP2PNative.invitePeer(peerId))
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
    /* File transfer (offer/accept model)                                  */
    /* ------------------------------------------------------------------ */

    /**
     * Sends a file to a connected peer.
     *
     * The receiver is notified via [LiteP2PListener.onFileTransferOffered] and
     * nothing is written to disk until it calls [acceptFileTransfer]. Sender
     * and receiver both receive progress/completion through
     * [LiteP2PListener.onTransferProgress] / [LiteP2PListener.onTransferCompleted].
     *
     * Requires the file-transfer module (see [supportsFileTransfer]) and an
     * established session with [peerId].
     *
     * @param peerId the connected peer to send to.
     * @param filePath absolute path of the file to send (must be readable).
     * @param priority scheduling priority of the transfer.
     * @return the transfer id on success, or null when the request was refused
     *   (blank args, unknown/not-connected peer, or module unavailable). The
     *   detailed result code is available in the engine log.
     */
    fun sendFile(
        peerId: String,
        filePath: String,
        priority: FileTransferPriority = FileTransferPriority.NORMAL
    ): String? {
        if (peerId.isBlank() || filePath.isBlank()) return null
        val id = LiteP2PNative.sendFile(peerId, filePath, priority.wire)
        return id.ifEmpty { null }
    }

    /**
     * Accepts an incoming [FileTransferOffer] and writes the received file to
     * [savePath]. Until this is called, nothing is written to disk.
     *
     * @return [EngineResult.OK] when accepted, [EngineResult.NOT_FOUND] for an
     *   unknown/expired transfer id, [EngineResult.INVALID_ARG] for blank args.
     */
    fun acceptFileTransfer(transferId: String, savePath: String): EngineResult {
        if (transferId.isBlank() || savePath.isBlank()) return EngineResult.INVALID_ARG
        return EngineResult.fromCode(LiteP2PNative.acceptFileTransfer(transferId, savePath))
    }

    /** Declines an incoming [FileTransferOffer]. */
    fun declineFileTransfer(transferId: String): EngineResult {
        if (transferId.isBlank()) return EngineResult.INVALID_ARG
        return EngineResult.fromCode(LiteP2PNative.declineFileTransfer(transferId))
    }

    /** Pauses an active transfer. */
    fun pauseTransfer(transferId: String): EngineResult {
        if (transferId.isBlank()) return EngineResult.INVALID_ARG
        return EngineResult.fromCode(LiteP2PNative.pauseTransfer(transferId))
    }

    /** Resumes a paused transfer. */
    fun resumeTransfer(transferId: String): EngineResult {
        if (transferId.isBlank()) return EngineResult.INVALID_ARG
        return EngineResult.fromCode(LiteP2PNative.resumeTransfer(transferId))
    }

    /** Cancels a transfer (sender or receiver side). */
    fun cancelTransfer(transferId: String): EngineResult {
        if (transferId.isBlank()) return EngineResult.INVALID_ARG
        return EngineResult.fromCode(LiteP2PNative.cancelTransfer(transferId))
    }

    /* ------------------------------------------------------------------ */
    /* Voice calls (realtime audio)                                        */
    /* ------------------------------------------------------------------ */

    /**
     * Offers a realtime voice call to a connected peer.
     *
     * The engine is codec-agnostic: [codec] is opaque. The Android app uses
     * "PCM_S16LE" (16 kHz mono, 16-bit signed little-endian) with
     * [sampleRate]=16000, [channels]=1, [frameMs]=20. Frames are sent
     * fire-and-forget — late/lost frames are dropped, never retransmitted.
     *
     * @return the call id on success, or null when the request was refused
     *   (blank args, unknown/not-connected peer, module unavailable, or an
     *   active call already exists with the peer).
     */
    fun startVoiceCall(
        peerId: String,
        codec: String = "PCM_S16LE",
        sampleRate: Int = 16000,
        channels: Int = 1,
        frameMs: Int = 20
    ): String? {
        if (peerId.isBlank() || codec.isBlank() || sampleRate <= 0 ||
            channels !in 1..2 || frameMs <= 0) return null
        val id = LiteP2PNative.startVoiceCall(peerId, codec, sampleRate, channels, frameMs)
        return id.ifEmpty { null }
    }

    /** Accepts an incoming [VoiceCallOffer]; the call goes IN_CALL and audio flows. */
    fun acceptVoiceCall(callId: String): EngineResult {
        if (callId.isBlank()) return EngineResult.INVALID_ARG
        return EngineResult.fromCode(LiteP2PNative.acceptVoiceCall(callId))
    }

    /** Declines an incoming [VoiceCallOffer]. */
    fun declineVoiceCall(callId: String): EngineResult {
        if (callId.isBlank()) return EngineResult.INVALID_ARG
        return EngineResult.fromCode(LiteP2PNative.declineVoiceCall(callId))
    }

    /** Ends a call (either side; caller/callee/connected). */
    fun endVoiceCall(callId: String): EngineResult {
        if (callId.isBlank()) return EngineResult.INVALID_ARG
        return EngineResult.fromCode(LiteP2PNative.endVoiceCall(callId))
    }

    /**
     * Sends one audio frame for an active call (fire-and-forget).
     *
     * @param data codec bytes; PCM S16LE 16 kHz mono gives 640 bytes per 20 ms
     *   frame. Frames must stay small (≤ ~8 KB) so each rides one UDP datagram
     *   without IP fragmentation.
     */
    fun sendVoiceFrame(callId: String, data: ByteArray): EngineResult {
        if (callId.isBlank() || data.isEmpty()) return EngineResult.INVALID_ARG
        return EngineResult.fromCode(LiteP2PNative.sendVoiceFrame(callId, data))
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
    /* Backpressure metrics (v0.4)                                          */
    /* ------------------------------------------------------------------ */

    /**
     * Number of plain-send events currently queued in the engine event loop
     * (accepted by [send] but not yet handed to the transport). Use to gauge
     * backpressure before sending bursts: [send] starts returning
     * [EngineResult.QUEUE_FULL] once the internal limit is reached. Returns 0
     * when the engine is not initialized.
     */
    fun pendingSendCount(): Int = runCatching { LiteP2PNative.pendingSendCount() }.getOrDefault(0)

    /**
     * Number of reliable sends currently in the durable outbox (QUEUED or
     * SENT, i.e. not yet DELIVERED/FAILED). Bounded by
     * `offline_queue.max_messages`; [sendReliable] returns
     * [EngineResult.QUEUE_FULL] once the outbox is full. Returns 0 when the
     * engine is not initialized.
     */
    fun reliablePendingCount(): Int =
        runCatching { LiteP2PNative.reliablePendingCount() }.getOrDefault(0)

    /* ------------------------------------------------------------------ */
    /* Event dispatch (called by NativeEvents from engine threads)         */
    /* ------------------------------------------------------------------ */

    internal fun dispatchEngineStarted() {
        _stateFlow.value = EngineState.RUNNING
        for (l in listeners) runCatching { l.onEngineStarted() }
    }

    internal fun dispatchEngineStopped() {
        _stateFlow.value = EngineState.STOPPED
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

    internal fun dispatchFileTransferOffered(offer: FileTransferOffer) {
        for (l in listeners) runCatching { l.onFileTransferOffered(offer) }
    }

    internal fun dispatchTransferProgress(transferId: String, progressPercent: Float, bytesPerSec: Float) {
        for (l in listeners) runCatching { l.onTransferProgress(transferId, progressPercent, bytesPerSec) }
    }

    internal fun dispatchTransferCompleted(transferId: String, success: Boolean, error: String?) {
        for (l in listeners) runCatching { l.onTransferCompleted(transferId, success, error) }
    }

    internal fun dispatchVoiceCallOffered(offer: VoiceCallOffer) {
        for (l in listeners) runCatching { l.onVoiceCallOffered(offer) }
    }

    internal fun dispatchVoiceCallStateChanged(
        callId: String,
        peerId: String,
        state: VoiceCallState,
        detail: String?
    ) {
        for (l in listeners) runCatching { l.onVoiceCallStateChanged(callId, peerId, state, detail) }
    }

    internal fun dispatchVoiceFrameReceived(callId: String, peerId: String, data: ByteArray) {
        for (l in listeners) runCatching { l.onVoiceFrameReceived(callId, peerId, data) }
    }

    internal fun dispatchDeliveryStatus(messageId: String, status: Int, reason: String) {
        val typed = DeliveryStatus.fromCode(status)
        for (l in listeners) runCatching { l.onDeliveryStatus(messageId, typed, reason) }
    }

    internal fun dispatchPresence(peerId: String, online: Boolean, lastSeenMs: Long) {
        for (l in listeners) runCatching { l.onPresence(peerId, online, lastSeenMs) }
    }

    internal fun dispatchPingResult(peerId: String, rttMs: Long) {
        for (l in listeners) runCatching { l.onPingResult(peerId, rttMs) }
    }

    internal fun dispatchLookupResult(alias: String, peerId: String, online: Boolean, lastSeenMs: Long) {
        for (l in listeners) runCatching { l.onLookupResult(alias, peerId, online, lastSeenMs) }
    }

    internal fun dispatchInviteReceived(fromPeerId: String) {
        for (l in listeners) runCatching { l.onInviteReceived(fromPeerId) }
    }
}
