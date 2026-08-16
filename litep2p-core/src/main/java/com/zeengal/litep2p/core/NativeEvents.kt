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
}
