package com.zeengal.litep2p.core

/**
 * Reconnect aggressiveness, mirroring the C ABI `litep2p_set_reconnect_mode`
 * (litep2p.h §3.12).
 */
enum class ReconnectMode(val wire: String) {
    AUTO("auto"),
    AGGRESSIVE("aggressive"),
    BALANCED("balanced"),
    POWER_SAVER("power_saver");
}