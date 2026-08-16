package com.zeengal.litep2p.core

/**
 * Transport selection for the engine listeners, mirroring the C ABI
 * `litep2p_config.comms_mode` (litep2p.h §3.4).
 *
 * [wire] is the exact string handed to the native engine. [ALL] listens on
 * TCP + UDP + QUIC simultaneously (the harness exposes this as "Heterogeneous").
 */
enum class CommsMode(val wire: String) {
    TCP("TCP"),
    UDP("UDP"),
    QUIC("QUIC"),
    ALL("ALL"),
    AUTO("AUTO");

    companion object {
        /** Parses a UI / wire string; unknown values fall back to [UDP]. */
        @JvmStatic
        fun fromWire(wire: String?): CommsMode = when (wire?.uppercase()) {
            "TCP" -> TCP
            "UDP" -> UDP
            "QUIC" -> QUIC
            "ALL", "HETEROGENEOUS" -> ALL
            "AUTO" -> AUTO
            else -> UDP
        }
    }
}