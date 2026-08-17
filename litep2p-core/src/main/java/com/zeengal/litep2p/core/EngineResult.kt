package com.zeengal.litep2p.core

/**
 * Result codes returned by the LiteP2P engine, mirroring the C ABI
 * `litep2p_result_t` (litep2p.h §3.2 / api-spec.md §3.2).
 *
 * The [code] matches the native integer value so results can round-trip across
 * the JNI boundary without loss.
 */
enum class EngineResult(val code: Int) {
    OK(0),
    INVALID_ARG(-1),
    INVALID_STATE(-2),
    BUSY(-3),
    NOT_FOUND(-4),
    IO(-5),
    TIMEOUT(-6),
    UNSUPPORTED(-7),
    NO_ROUTE(-8),
    QUEUE_FULL(-10),
    INTERNAL(-99);

    companion object {
        /** Maps a native `litep2p_result_t` integer to an [EngineResult]. */
        @JvmStatic
        fun fromCode(code: Int): EngineResult =
            values().firstOrNull { it.code == code } ?: INTERNAL
    }
}