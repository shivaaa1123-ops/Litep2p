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

    /* ------------------------------------------------------------------ */
    /* File transfer (offer/accept model)                                  */
    /* ------------------------------------------------------------------ */

    /**
     * An incoming file-transfer offer arrived. Nothing is written to disk
     * until the receiver explicitly calls [LiteP2P.acceptFileTransfer] with a
     * save path, or [LiteP2P.declineFileTransfer] to refuse it.
     */
    fun onFileTransferOffered(offer: FileTransferOffer) {}

    /**
     * Progress update for a transfer (sender side of an outgoing transfer, and
     * receiver side of an accepted incoming transfer).
     *
     * @param transferId The transfer id returned by [LiteP2P.sendFile] or from
     *   the original [FileTransferOffer].
     * @param progressPercent 0..100 completed.
     * @param bytesPerSec Current throughput in bytes per second.
     */
    fun onTransferProgress(transferId: String, progressPercent: Float, bytesPerSec: Float) {}

    /**
     * A transfer finished.
     *
     * @param transferId The transfer id.
     * @param success True when the transfer completed, false when it failed or
     *   was cancelled.
     * @param error Human-readable error message when [success] is false, or null.
     */
    fun onTransferCompleted(transferId: String, success: Boolean, error: String?) {}

    /* ------------------------------------------------------------------ */
    /* Voice calls (realtime audio)                                        */
    /* ------------------------------------------------------------------ */

    /**
     * An incoming voice-call offer arrived. Nothing is captured or played
     * until the callee explicitly calls [LiteP2P.acceptVoiceCall], or
     * [LiteP2P.declineVoiceCall] to refuse.
     */
    fun onVoiceCallOffered(offer: VoiceCallOffer) {}

    /**
     * A call state change (both sides).
     *
     * @param callId The call id (from [LiteP2P.startVoiceCall] or the original
     *   [VoiceCallOffer]).
     * @param peerId The peer on the other end.
     * @param state One of [VoiceCallState].
     * @param detail Human-readable detail: "connected", "declined by peer",
     *   "ended", "ring timeout", ...
     */
    fun onVoiceCallStateChanged(callId: String, peerId: String, state: VoiceCallState, detail: String?) {}

    /**
     * An incoming audio frame for an active call.
     *
     * @param callId The active call id.
     * @param peerId The peer sending this frame.
     * @param data Codec bytes (PCM S16LE with the default profile). Valid only
     *   for the duration of this callback.
     */
    fun onVoiceFrameReceived(callId: String, peerId: String, data: ByteArray) {}

    /* ------------------------------------------------------------------ */
    /* v0.4: reliable messaging / presence / directory / invites            */
    /* ------------------------------------------------------------------ */

    /**
     * Reliable-send delivery receipt for a message sent with [LiteP2P.sendReliable].
     *
     * @param messageId The caller-supplied message id.
     * @param status [DeliveryStatus] of the message.
     * @param reason Machine-readable detail: "OK" | "NO_ROUTE" | "PEER_OFFLINE"
     *   | "QUEUE_FULL" | "TIMEOUT" | "TTL_EXPIRED" | "CANCELLED".
     */
    fun onDeliveryStatus(messageId: String, status: DeliveryStatus, reason: String) {}

    /**
     * Presence update for a peer subscribed via [LiteP2P.subscribePresence].
     *
     * @param peerId The peer.
     * @param online Current online state.
     * @param lastSeenMs Epoch ms when the peer was last observed online, or 0
     *   when unknown.
     */
    fun onPresence(peerId: String, online: Boolean, lastSeenMs: Long) {}

    /**
     * Result of a [LiteP2P.ping] probe.
     *
     * @param peerId The probed peer.
     * @param rttMs Round-trip time in ms (>= 0), or -1 when the peer was
     *   unreachable within the timeout.
     */
    fun onPingResult(peerId: String, rttMs: Long) {}

    /**
     * Result of a [LiteP2P.lookupPeer] alias resolution.
     *
     * @param alias The requested alias hash.
     * @param peerId The resolved peer id, or "" when the alias is unregistered.
     * @param online Server-side presence knowledge for the resolved peer.
     * @param lastSeenMs Epoch ms when the peer was last observed online, or 0
     *   when unknown.
     */
    fun onLookupResult(alias: String, peerId: String, online: Boolean, lastSeenMs: Long) {}

    /**
     * An invite arrived: [fromPeerId] wants this device to connect (sent via
     * [LiteP2P.invitePeer] on the other side). Typical response is
     * [LiteP2P.connect].
     */
    fun onInviteReceived(fromPeerId: String) {}
}
