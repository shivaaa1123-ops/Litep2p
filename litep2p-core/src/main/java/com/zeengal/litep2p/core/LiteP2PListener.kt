package com.zeengal.litep2p.core

/**
 * Observer of engine events (api-spec.md §4).
 *
 * Callbacks are dispatched on an internal engine thread — implementations must
 * not block. Posting to the main thread is the consumer's responsibility.
 *
 * All methods have default no-op implementations so consumers override only
 * what they need.
 */
interface LiteP2PListener {

    /** Engine startup completed (asynchronous result of [LiteP2P.start]). */
    fun onEngineStarted() {}

    /** Engine shutdown completed (asynchronous result of [LiteP2P.stop]). */
    fun onEngineStopped() {}

    /** Full peer snapshot; replaces any previous list. */
    fun onPeersChanged(peers: List<PeerInfo>) {}

    /** A message arrived from [peerId]. [data] is valid only for the call duration. */
    fun onMessageReceived(peerId: String, data: ByteArray) {}

    /** Engine log line. [level] is best-effort (INFO unless the engine supplies one). */
    fun onLog(level: LogLevel, line: String) {}

    /** Telemetry snapshot as single-line JSON (api-spec.md §6). */
    fun onTelemetry(json: String) {}

    /**
     * Application-level ACK received for a previously sent message.
     *
     * This supports the harness ACK-envelope protocol (LP_APP / LP_APP_ACK,
     * api-spec.md §4.2): the sender embeds a `msg_id` and the receiver echoes it
     * back, letting the sender measure delivery latency. Engines that do not run
     * the envelope protocol simply never fire this callback.
     *
     * @param messageId The original message id.
     * @param sentTsMs Sender-provided send timestamp (epoch ms), or 0 if absent.
     * @param recvTsMs Receiver-provided receive timestamp (epoch ms), or 0 if absent.
     */
    fun onMessageAcked(messageId: String, sentTsMs: Long, recvTsMs: Long) {}

    /**
     * Overlay reliable-send completion (censorship-resistance layer).
     *
     * Fires for overlay sends requested with `wantAck = true`: [delivered] is
     * true when the destination ACKed the message, false when the bounded
     * retry budget was exhausted. [frameId] matches the value returned by
     * [LiteP2P.sendOverlay].
     */
    fun onOverlayDelivery(frameId: String, delivered: Boolean) {}
}
