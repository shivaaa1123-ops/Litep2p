package com.zeengal.litep2p.core

/**
 * Engine lifecycle state, mirroring the C ABI `litep2p_state_t` (litep2p.h §3.5).
 */
enum class EngineState(val code: Int) {
    STOPPED(0),
    STARTING(1),
    RUNNING(2),
    STOPPING(3);

    companion object {
        @JvmStatic
        fun fromCode(code: Int): EngineState =
            values().firstOrNull { it.code == code } ?: STOPPED
    }
}