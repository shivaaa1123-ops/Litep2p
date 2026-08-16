package com.zeengal.litep2p.core

/**
 * Immutable engine configuration (api-spec.md §4, mirrors `litep2p_config_t`).
 *
 * Construct via [Builder]. On Android [filesDir] is required: the engine uses it
 * for config.json discovery, the Noise keystore and the peer DB.
 */
class LiteP2PConfig private constructor(
    val peerId: String?,
    val commsMode: CommsMode,
    val listenPort: Int,
    val filesDir: String,
    val configPath: String?,
    val encryptionEnabled: Boolean,
    val discoveryEnabled: Boolean,
    val fileTransferEnabled: Boolean,
    val telemetryEnabled: Boolean,
    val telemetryIntervalMs: Int,
    val singleThreadMode: Boolean
) {

    class Builder {
        private var peerId: String? = null
        private var commsMode: CommsMode = CommsMode.UDP
        private var listenPort: Int = 0
        private var filesDir: String = ""
        private var configPath: String? = null
        private var encryptionEnabled: Boolean = true
        private var discoveryEnabled: Boolean = true
        private var fileTransferEnabled: Boolean = true
        private var telemetryEnabled: Boolean = true
        private var telemetryIntervalMs: Int = 30_000
        private var singleThreadMode: Boolean = false

        /** Stable identity; null lets the engine generate one. */
        fun peerId(id: String?): Builder = apply { this.peerId = id }

        fun commsMode(mode: CommsMode): Builder = apply { this.commsMode = mode }

        /** 0 = engine default. */
        fun listenPort(port: Int): Builder = apply { this.listenPort = port }

        /** Required on Android: Context.getFilesDir().absolutePath. */
        fun filesDir(path: String): Builder = apply { this.filesDir = path }

        /** Optional explicit config.json path; null = auto-discover under filesDir. */
        fun configPath(path: String?): Builder = apply { this.configPath = path }

        fun encryptionEnabled(enabled: Boolean): Builder = apply { this.encryptionEnabled = enabled }

        fun discoveryEnabled(enabled: Boolean): Builder = apply { this.discoveryEnabled = enabled }

        fun fileTransferEnabled(enabled: Boolean): Builder = apply { this.fileTransferEnabled = enabled }

        fun telemetryEnabled(enabled: Boolean): Builder = apply { this.telemetryEnabled = enabled }

        fun telemetryIntervalMs(intervalMs: Int): Builder = apply { this.telemetryIntervalMs = intervalMs }

        /**
         * Compile-time hint only in Phase 2: the actual thread mode is selected by the
         * `singleThread`/`multiThread` build flavor (SINGLE_THREAD_MODE CMake toggle).
         */
        fun singleThreadMode(enabled: Boolean): Builder = apply { this.singleThreadMode = enabled }

        fun build(): LiteP2PConfig {
            require(filesDir.isNotBlank()) {
                "LiteP2PConfig.filesDir is required on Android (Context.getFilesDir())"
            }
            return LiteP2PConfig(
                peerId = peerId,
                commsMode = commsMode,
                listenPort = listenPort,
                filesDir = filesDir,
                configPath = configPath,
                encryptionEnabled = encryptionEnabled,
                discoveryEnabled = discoveryEnabled,
                fileTransferEnabled = fileTransferEnabled,
                telemetryEnabled = telemetryEnabled,
                telemetryIntervalMs = telemetryIntervalMs,
                singleThreadMode = singleThreadMode
            )
        }
    }

    override fun toString(): String =
        "LiteP2PConfig(peerId=$peerId, commsMode=$commsMode, listenPort=$listenPort, " +
            "filesDir=$filesDir, configPath=$configPath)"
}