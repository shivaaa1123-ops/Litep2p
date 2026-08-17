package com.zeengal.litep2p.core

/**
 * Snapshot of a single peer as reported by the engine.
 *
 * The constructor signature is part of the JNI contract: the native bridge
 * constructs this class reflectively via
 * `(Ljava/lang/String;Ljava/lang/String;IIZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;J)V`.
 * Do not reorder or change the primary constructor parameters.
 *
 * @property id Stable peer identity.
 * @property ip Latest advertised/active endpoint IP.
 * @property port Endpoint port.
 * @property latency Measured round-trip latency in ms, or -1 when unknown.
 * @property connected True when the session is fully established.
 * @property networkId LAN identity used for rendezvous ("0"/empty when unknown).
 * @property fsmState Best-effort peer FSM state (DISCOVERED/CONNECTING/CONNECTED/HANDSHAKING/READY).
 * @property connectionType Raw connection-path string from the engine
 *           ("LAN"/"WAN_DIRECT"/"TURN"/"SIGNALING"/"UNKNOWN" or canonical ABI names).
 * @property lastSeenMs v0.4: epoch ms when the peer was last observed online
 *           (session, discovery, or signaling), or 0 when never seen.
 */
data class PeerInfo(
    val id: String,
    val ip: String,
    val port: Int,
    val latency: Int,
    val connected: Boolean,
    val networkId: String,
    val fsmState: String,
    val connectionType: String,
    val lastSeenMs: Long = 0
) {
    /** Typed connection path derived from [connectionType] (api-spec.md §3.6). */
    val connectionPath: ConnectionPath
        get() = ConnectionPath.fromWire(connectionType)
}