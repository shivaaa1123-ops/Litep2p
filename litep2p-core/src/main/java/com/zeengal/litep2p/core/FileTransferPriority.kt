package com.zeengal.litep2p.core

/**
 * Priority of an outgoing file transfer, passed to [LiteP2P.sendFile].
 *
 * The [wire] value is the integer accepted by the C ABI `litep2p_send_file`;
 * the native engine maps `<= 0` to LOW, `1` to NORMAL and `>= 2` to HIGH.
 */
enum class FileTransferPriority(val wire: Int) {
    LOW(0),
    NORMAL(1),
    HIGH(2);

    companion object {
        /** Maps a native priority integer back to this enum (default NORMAL). */
        @JvmStatic
        fun fromWire(value: Int): FileTransferPriority = when {
            value <= 0 -> LOW
            value >= 2 -> HIGH
            else -> NORMAL
        }
    }
}
