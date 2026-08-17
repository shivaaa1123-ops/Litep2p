package com.zeengal.litep2p.core

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.flow.StateFlow

/**
 * Turnkey engine runtime (ask.md §4, Feature 4).
 *
 * One call boots the whole stack in an SDK-owned foreground service:
 *
 * ```kotlin
 * LiteP2PRuntime.start(context)                    // sane defaults
 * // or
 * LiteP2PRuntime.start(context, myLiteP2PConfig)   // explicit config
 * ```
 *
 * The runtime owns, so integrators don't have to:
 *  - [LiteP2PService] — a `START_STICKY` foreground service with partial
 *    wakelock + Wi-Fi/multicast locks, so Doze doesn't suspend delivery and
 *    the engine survives background kills (restarting automatically).
 *  - Environment hints — network/battery/Doze state is pushed into the engine
 *    (see [EnvironmentHints]) so reconnect behavior adapts to the platform.
 *  - Defaults — a stable per-device peer id and a bundled `config.json` are
 *    created on first run (see [LiteP2PDefaults]).
 *  - Manifest-merger contributions — permissions and the service declaration
 *    ship with the AAR.
 *
 * Interacting with the engine afterwards happens through the ordinary
 * [LiteP2P] API (`LiteP2P.send`, `LiteP2P.addListener`, …); this object only
 * manages process lifetime plus notification customization.
 *
 * Notification customization (set before [start]):
 * ```kotlin
 * LiteP2PRuntime.notificationSmallIconResId = R.drawable.my_icon
 * LiteP2PRuntime.notificationTitle = "My App"
 * LiteP2PRuntime.notificationCustomizer = { it.setColor(0xFF2E7D32.toInt()) }
 * ```
 */
object LiteP2PRuntime {

    private const val TAG = "LiteP2P_Runtime"

    /** Intent action understood by [LiteP2PService]: boot the engine. */
    const val ACTION_START = "com.zeengal.litep2p.core.action.START_ENGINE"

    /** Intent action understood by [LiteP2PService]: stop engine + service. */
    const val ACTION_STOP = "com.zeengal.litep2p.core.action.STOP_ENGINE"

    /**
     * Config handed to the service in-process. Null after process death; the
     * service then reconstructs the last config from SharedPreferences.
     */
    @Volatile
    internal var pendingConfig: LiteP2PConfig? = null

    /* ------------------------------------------------------------------ */
    /* Notification customization (set any time before [start])             */
    /* ------------------------------------------------------------------ */

    /** Small notification icon; defaults to the SDK's bundled mesh glyph. */
    @Volatile
    var notificationSmallIconResId: Int = R.drawable.ic_litep2p_service

    /** Notification title; null = SDK default ("LiteP2P engine"). */
    @Volatile
    var notificationTitle: CharSequence? = null

    /** Static body text; null = SDK default per-state text (Starting/Running/…). */
    @Volatile
    var notificationText: CharSequence? = null

    /** Activity opened when the notification is tapped; null = no content intent. */
    @Volatile
    var launchActivity: Class<*>? = null

    /**
     * Last-chance hook applied to the notification builder (color, actions,
     * subtext, …). Runs on the service's engine thread before posting.
     */
    @Volatile
    var notificationCustomizer: ((NotificationCompat.Builder) -> Unit)? = null

    /**
     * Whether [start] automatically asks the user (once per install) to put the
     * app on the battery-optimization allowlist, so Doze doesn't defer the
     * engine's sockets while the device is idle. The request is always
     * user-granted; set this to `false` to never surface it (and use
     * [LiteP2PBatteryOptimization.requestExemption] from your own UI instead).
     */
    @Volatile
    var autoRequestBatteryExemption: Boolean = true

    /* ------------------------------------------------------------------ */
    /* Lifecycle                                                            */
    /* ------------------------------------------------------------------ */

    /**
     * Builds the zero-configuration default: the app's [Context.getFilesDir],
     * a stable persisted peer id, and the bundled default `config.json`
     * (extracted on first run).
     */
    fun defaultConfig(context: Context): LiteP2PConfig =
        LiteP2PConfig.Builder()
            .filesDir(context.filesDir.absolutePath)
            .peerId(LiteP2PDefaults.getOrCreatePeerId(context))
            .configPath(LiteP2PDefaults.resolveConfigPath(context, null))
            .build()

    /**
     * Starts the engine inside [LiteP2PService] (foreground). Safe to call
     * repeatedly; a second call while running with a *null* [config] is a
     * no-op, and with a non-null config it restarts the engine under it.
     *
     * Must be called while the app is in the foreground (Android restricts
     * background foreground-service starts on API 31+).
     *
     * @param activity optional Activity used to present the one-shot battery-
     *        optimization exemption dialog (see [autoRequestBatteryExemption]).
     */
    fun start(context: Context, config: LiteP2PConfig? = null, activity: Activity? = null) {
        val app = context.applicationContext
        if (config == null && desiredRunning(app) &&
            (LiteP2P.state == EngineState.RUNNING || LiteP2P.state == EngineState.STARTING)
        ) {
            Log.i(TAG, "start(): engine already running with persisted config; ignoring")
            return
        }
        val effective = config ?: defaultConfig(app)
        persistConfig(app, effective)
        setDesired(app, true)
        pendingConfig = effective
        ContextCompat.startForegroundService(app, Intent(app, LiteP2PService::class.java).apply {
            action = ACTION_START
        })

        // Doze defers the engine's sockets while idle even with the foreground
        // service. Ask the user once per install to exempt the app (never if
        // already exempt, never a second time, and never when the integrator
        // disabled autoRequestBatteryExemption).
        if (autoRequestBatteryExemption) {
            LiteP2PBatteryOptimization.requestExemptionIfNeeded(app, activity)
        }
    }

    /* ------------------------------------------------------------------ */
    /* State passthrough                                                   */
    /* ------------------------------------------------------------------ */

    /** Current engine lifecycle state (see [LiteP2P.state]). */
    val state: EngineState get() = LiteP2P.state

    /** Observable engine lifecycle state (see [LiteP2P.stateFlow]). */
    val stateFlow: StateFlow<EngineState> get() = LiteP2P.stateFlow

    /** True while the engine is starting or running. */
    val isRunning: Boolean
        get() = LiteP2P.state == EngineState.RUNNING || LiteP2P.state == EngineState.STARTING

    /** True if the last thing requested via [start] is still in effect. */
    fun isDesiredRunning(context: Context): Boolean = desiredRunning(context.applicationContext)

    /**
     * The stable per-device peer id the runtime would use (generating and
     * persisting one on first call). Once the engine is running prefer
     * [LiteP2P.peerId], which returns the resolved id.
     */
    fun peerId(context: Context): String = LiteP2PDefaults.getOrCreatePeerId(context.applicationContext)

    /* ------------------------------------------------------------------ */
    /* Persistence (survives process death → START_STICKY restore)         */
    /* ------------------------------------------------------------------ */

    private const val PREFS = "litep2p_sdk_prefs"
    private const val K_DESIRED = "runtime_desired_running"
    private const val K_PEER_ID = "cfg_peer_id"
    private const val K_COMMS = "cfg_comms_mode"
    private const val K_PORT = "cfg_listen_port"
    private const val K_FILES_DIR = "cfg_files_dir"
    private const val K_CONFIG_PATH = "cfg_config_path"
    private const val K_ENC = "cfg_encryption"
    private const val K_DISCOVERY = "cfg_discovery"
    private const val K_FILE_XFER = "cfg_file_transfer"
    private const val K_TELEMETRY = "cfg_telemetry"
    private const val K_TELEMETRY_MS = "cfg_telemetry_ms"
    private const val K_SINGLE_THREAD = "cfg_single_thread"

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    internal fun setDesired(context: Context, value: Boolean) {
        prefs(context).edit().putBoolean(K_DESIRED, value).apply()
    }

    internal fun desiredRunning(context: Context): Boolean =
        prefs(context).getBoolean(K_DESIRED, false)

    private fun persistConfig(context: Context, config: LiteP2PConfig) {
        prefs(context).edit()
            .putString(K_PEER_ID, config.peerId)
            .putString(K_COMMS, config.commsMode.wire)
            .putInt(K_PORT, config.listenPort)
            .putString(K_FILES_DIR, config.filesDir)
            .putString(K_CONFIG_PATH, config.configPath)
            .putBoolean(K_ENC, config.encryptionEnabled)
            .putBoolean(K_DISCOVERY, config.discoveryEnabled)
            .putBoolean(K_FILE_XFER, config.fileTransferEnabled)
            .putBoolean(K_TELEMETRY, config.telemetryEnabled)
            .putInt(K_TELEMETRY_MS, config.telemetryIntervalMs)
            .putBoolean(K_SINGLE_THREAD, config.singleThreadMode)
            .apply()
    }

    /**
     * Rebuilds the last-started config from SharedPreferences, or null when
     * the runtime never started (or the prefs were wiped).
     */
    internal fun reconstructConfig(context: Context): LiteP2PConfig? {
        val filesDir = prefs(context).getString(K_FILES_DIR, null)?.takeIf { it.isNotBlank() }
            ?: return null
        val p = prefs(context)
        return try {
            LiteP2PConfig.Builder()
                .filesDir(filesDir)
                .peerId(
                    p.getString(K_PEER_ID, null)
                        ?: LiteP2PDefaults.getOrCreatePeerId(context)
                )
                .commsMode(CommsMode.fromWire(p.getString(K_COMMS, null)))
                .listenPort(p.getInt(K_PORT, 0))
                .configPath(p.getString(K_CONFIG_PATH, null))
                .encryptionEnabled(p.getBoolean(K_ENC, true))
                .discoveryEnabled(p.getBoolean(K_DISCOVERY, true))
                .fileTransferEnabled(p.getBoolean(K_FILE_XFER, true))
                .telemetryEnabled(p.getBoolean(K_TELEMETRY, true))
                .telemetryIntervalMs(p.getInt(K_TELEMETRY_MS, 30_000))
                .singleThreadMode(p.getBoolean(K_SINGLE_THREAD, false))
                .build()
        } catch (t: Throwable) {
            Log.w(TAG, "Failed to reconstruct persisted config: ${t.message}")
            null
        }
    }

    /**
     * Stops the engine and the foreground service. Idempotent. Engine
     * completion is reported via [LiteP2PListener.onEngineStopped].
     */
    fun stop(context: Context) {
        val app = context.applicationContext
        setDesired(app, false)
        ContextCompat.startForegroundService(app, Intent(app, LiteP2PService::class.java).apply {
            action = ACTION_STOP
        })
    }
}
