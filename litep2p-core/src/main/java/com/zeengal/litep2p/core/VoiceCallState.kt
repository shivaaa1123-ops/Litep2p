package com.zeengal.litep2p.core

/**
 * Voice-call state machine, mirroring the engine's [VoiceCallManager].
 */
enum class VoiceCallState(val wire: Int) {
    /** No active call. */
    IDLE(0),

    /** Caller: offer sent, awaiting accept/decline. */
    OUTGOING(1),

    /** Callee: offer received, awaiting user decision. */
    RINGING(2),

    /** Connected; audio frames flow in both directions. */
    IN_CALL(3),

    /** Terminal: ended, declined, or ring timeout. */
    ENDED(4);

    companion object {
        /** Maps a native wire value back to the enum (IDLE for unknown). */
        fun fromWire(value: Int): VoiceCallState =
            entries.firstOrNull { it.wire == value } ?: IDLE
    }
}
