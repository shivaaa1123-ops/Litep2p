package com.zeengal.litep2p.core

/**
 * JNI → Kotlin callback surface (internal to :litep2p-core).
 *
 * The native bridge (cpp/src/jni_bridge.cpp) looks up this class by name
 * ("com/zeengal/litep2p/core/NativeEvents") and invokes its static methods from
 * engine threads. This is the single callback target for all native→Java events,
 * which keeps the JNI layer decoupled from any consumer (app) classes.
 *
 * All methods are @JvmStatic so JNI sees plain static methods, and they forward
 * into [LiteP2P]'s listener dispatch. Callbacks arrive on engine threads; they are
 * forwarded synchronously to listeners (api-spec.md §4.1: no main-thread posting).
 */
object NativeEvents {

    /** Engine startup finished. Called from a native thread. */
    @JvmStatic
    fun onEngineStartComplete() {
        LiteP2P.dispatchEngineStarted()
    }

    /** Engine shutdown finished. Called from a native thread. */
    @JvmStatic
    fun onEngineStopComplete() {
        LiteP2P.dispatchEngineStopped()
    }

    /** Full peer snapshot. Called from a native thread. */
    @JvmStatic
    fun onPeersUpdated(peers: Array<PeerInfo>) {
        LiteP2P.dispatchPeersChanged(peers.toList())
    }

    /** A message arrived. [messageBytes] is valid only for the call duration. */
    @JvmStatic
    fun onMessageReceived(peerId: String, messageBytes: ByteArray) {
        LiteP2P.dispatchMessageReceived(peerId, messageBytes)
    }

    /** Engine log line with its real level (0=DEBUG 1=INFO 2=WARN 3=ERROR). */
    @JvmStatic
    fun addLog(level: Int, message: String) {
        LiteP2P.dispatchLog(LogLevel.fromLevel(level), message)
    }

    /** Telemetry snapshot JSON (no "TELEMETRY" prefix). */
    @JvmStatic
    fun addTelemetryJson(json: String) {
        LiteP2P.dispatchTelemetry(json)
    }

    /** Application-level ACK received (LP_APP_ACK envelope). */
    @JvmStatic
    fun onAckReceived(messageId: String, sentTsMs: Long, recvTsMs: Long) {
        LiteP2P.dispatchMessageAcked(messageId, sentTsMs, recvTsMs)
    }

    /** Overlay reliable-send completion (frame_id + delivered true/false). */
    @JvmStatic
    fun onOverlayDelivery(frameId: String, delivered: Boolean) {
        LiteP2P.dispatchOverlayDelivery(frameId, delivered)
    }

    /** File-transfer offer arrived (transfer_id, peer_id, file_name, size_bytes). */
    @JvmStatic
    fun onFileTransferOffered(transferId: String, peerId: String, fileName: String, sizeBytes: Long) {
        LiteP2P.dispatchFileTransferOffered(
            FileTransferOffer(transferId, peerId, fileName, sizeBytes)
        )
    }

    /** File-transfer progress (transfer_id, progress 0..100, bytes_per_sec). */
    @JvmStatic
    fun onTransferProgress(transferId: String, progressPercent: Float, bytesPerSec: Float) {
        LiteP2P.dispatchTransferProgress(transferId, progressPercent, bytesPerSec)
    }

    /** File-transfer completion (transfer_id, success, error). */
    @JvmStatic
    fun onTransferCompleted(transferId: String, success: Boolean, error: String?) {
        LiteP2P.dispatchTransferCompleted(transferId, success, error)
    }

    /** Voice-call offer arrived (call_id, peer_id, codec, sample_rate, channels, frame_ms). */
    @JvmStatic
    fun onVoiceCallOffered(callId: String, peerId: String, codec: String,
                           sampleRate: Int, channels: Int, frameMs: Int) {
        LiteP2P.dispatchVoiceCallOffered(
            VoiceCallOffer(callId, peerId, codec, sampleRate, channels, frameMs)
        )
    }

    /** Voice-call state change (call_id, peer_id, state wire value, detail). */
    @JvmStatic
    fun onVoiceCallStateChanged(callId: String, peerId: String, state: Int, detail: String?) {
        LiteP2P.dispatchVoiceCallStateChanged(callId, peerId, VoiceCallState.fromWire(state), detail)
    }

    /** Incoming voice audio frame (call_id, peer_id, codec bytes). */
    @JvmStatic
    fun onVoiceFrameReceived(callId: String, peerId: String, data: ByteArray) {
        LiteP2P.dispatchVoiceFrameReceived(callId, peerId, data)
    }

    /* ------------------------------------------------------------------ */
    /* v0.4: reliable messaging / presence / directory / invites            */
    /* ------------------------------------------------------------------ */

    /**
     * Reliable-send delivery receipt (msg_id, status, reason).
     * status: 0=QUEUED 1=SENT 2=DELIVERED 3=FAILED.
     * reason: "OK" | "NO_ROUTE" | "PEER_OFFLINE" | "QUEUE_FULL" | "TIMEOUT"
     *         | "TTL_EXPIRED" | "CANCELLED".
     */
    @JvmStatic
    fun onDeliveryStatus(msgId: String, status: Int, reason: String) {
        LiteP2P.dispatchDeliveryStatus(msgId, status, reason)
    }

    /** Presence update for a subscribed peer (peer_id, online, last_seen_ms). */
    @JvmStatic
    fun onPresence(peerId: String, online: Boolean, lastSeenMs: Long) {
        LiteP2P.dispatchPresence(peerId, online, lastSeenMs)
    }

    /** Ping result (peer_id, rtt_ms >= 0 on success, -1 on timeout/unreachable). */
    @JvmStatic
    fun onPingResult(peerId: String, rttMs: Long) {
        LiteP2P.dispatchPingResult(peerId, rttMs)
    }

    /** Alias lookup result (alias, peer_id — "" when unregistered, online, last_seen_ms). */
    @JvmStatic
    fun onLookupResult(alias: String, peerId: String, online: Boolean, lastSeenMs: Long) {
        LiteP2P.dispatchLookupResult(alias, peerId, online, lastSeenMs)
    }

    /** Invite received from [fromPeerId] (signaling push; typically followed by connect). */
    @JvmStatic
    fun onInviteReceived(fromPeerId: String) {
        LiteP2P.dispatchInviteReceived(fromPeerId)
    }

    /**
     * Phase 12 — Network OS delivery/diagnostic event (flat JSON line).
     * Forwarded into [NetworkOs.deliveryEvents]. Called from a native thread.
     */
    @JvmStatic
    fun onNosDeliveryEvent(json: String) {
        NetworkOs.dispatchDeliveryEvent(json)
    }

    /**
     * Phase 8 lifecycle bridge — the native central scheduler asked for
     * deferred work to run in [delayMs] ms. Forwarded into
     * [EngineWakeupScheduler], which schedules a durable WorkManager job
     * (survives process death + Doze). Called from a native thread.
     */
    @JvmStatic
    fun onWakeupRequested(reason: String, delayMs: Long) {
        EngineWakeupScheduler.onEngineWakeupRequested(reason, delayMs)
    }

    /**
     * Phase 13 push trigger — the engine asked the app to deliver an FCM data
     * message to [peerId] carrying [candidatesJson] (NAT candidate exchange).
     * Forwarded to [LiteP2PPush.triggerListener]. Called from a native thread.
     */
    @JvmStatic
    fun onPushTriggerRequested(peerId: String, candidatesJson: String) {
        LiteP2PPush.dispatchTrigger(peerId, candidatesJson)
    }
}
