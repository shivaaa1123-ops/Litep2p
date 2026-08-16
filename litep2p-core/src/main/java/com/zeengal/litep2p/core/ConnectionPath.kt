package com.zeengal.litep2p.core

/**
 * How a peer connection was established, mirroring the C ABI
 * `litep2p_peer_info.connection_path` (litep2p.h §3.6).
 */
enum class ConnectionPath {
    LAN_DIRECT,
    WAN_HOLE_PUNCH,
    TURN_RELAY,
    SIGNALING_RELAY,
    UNKNOWN;

    companion object {
        /** Parses the canonical ABI path string; unknown values map to [UNKNOWN]. */
        @JvmStatic
        fun fromWire(wire: String?): ConnectionPath = when (wire) {
            "LAN_DIRECT", "LAN" -> LAN_DIRECT
            "WAN_HOLE_PUNCH", "WAN_DIRECT" -> WAN_HOLE_PUNCH
            "TURN_RELAY", "TURN" -> TURN_RELAY
            "SIGNALING_RELAY", "SIGNALING" -> SIGNALING_RELAY
            else -> UNKNOWN
        }
    }
}