package com.zeengal.litep2p.core

/**
 * Compile-time feature availability of the native engine build
 * (litep2p.h `litep2p_get_feature_flags`).
 *
 * These flags reflect the **build configuration** (whether a module was
 * compiled in), not the runtime configuration. They are fixed for the lifetime
 * of the process and safe to query at any time — including before
 * [LiteP2P.init]. Use them to degrade gracefully when a subsystem is not
 * available instead of relying on [EngineResult.UNSUPPORTED] at call time.
 *
 * @property fileTransfer file-transfer module compiled in (offer/accept model).
 * @property voiceCall realtime voice-call module compiled in.
 * @property overlay multi-hop overlay module compiled in (censorship-resistance).
 * @property proxy proxy/relay module compiled in.
 * @property encryption Noise NK protocol compiled in.
 * @property discovery LAN discovery module compiled in.
 * @property telemetry telemetry subsystem available.
 */
data class LiteP2PCapabilities(
    val fileTransfer: Boolean,
    val voiceCall: Boolean,
    val overlay: Boolean,
    val proxy: Boolean,
    val encryption: Boolean,
    val discovery: Boolean,
    val telemetry: Boolean
) {
    companion object {
        const val FLAG_FILE_TRANSFER: Int = 1 shl 0
        const val FLAG_OVERLAY: Int = 1 shl 1
        const val FLAG_PROXY: Int = 1 shl 2
        const val FLAG_ENCRYPTION: Int = 1 shl 3
        const val FLAG_DISCOVERY: Int = 1 shl 4
        const val FLAG_TELEMETRY: Int = 1 shl 5
        const val FLAG_VOICE_CALL: Int = 1 shl 6

        /** Decodes the `LITEP2P_FEATURE_*` bitmask returned by the native engine. */
        @JvmStatic
        fun fromFlags(flags: Int): LiteP2PCapabilities = LiteP2PCapabilities(
            fileTransfer = flags and FLAG_FILE_TRANSFER != 0,
            voiceCall = flags and FLAG_VOICE_CALL != 0,
            overlay = flags and FLAG_OVERLAY != 0,
            proxy = flags and FLAG_PROXY != 0,
            encryption = flags and FLAG_ENCRYPTION != 0,
            discovery = flags and FLAG_DISCOVERY != 0,
            telemetry = flags and FLAG_TELEMETRY != 0
        )
    }
}
