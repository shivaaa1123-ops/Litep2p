package com.zeengal.litep2p.core

/**
 * Lifecycle state of a reliable send (v0.4), mirroring the C ABI
 * `on_delivery_status` status codes (litep2p.h §3.6).
 *
 * The [code] matches the native integer value so statuses can round-trip
 * across the JNI boundary without loss.
 */
enum class DeliveryStatus(val code: Int) {
    /** Accepted into the persistent outbox; not yet transmitted. */
    QUEUED(0),

    /** Transmitted at least once; awaiting the receiver's ACK. */
    SENT(1),

    /** The receiver ACKed the message (terminal success). */
    DELIVERED(2),

    /** Delivery failed after retries / cancel / TTL (terminal failure). */
    FAILED(3);

    companion object {
        /** Maps a native status integer to a [DeliveryStatus]. */
        @JvmStatic
        fun fromCode(code: Int): DeliveryStatus =
            values().firstOrNull { it.code == code } ?: FAILED
    }
}
