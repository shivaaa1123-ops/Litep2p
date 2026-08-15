package com.zeengal.litep2p

import android.content.Context

/**
 * Persistent record of what the engine is *supposed* to be doing.
 *
 * The service can be killed by the OS and recreated later (START_STICKY), and the device
 * can reboot. In both cases there is no Activity and no in-memory state to consult, so
 * the intended configuration is written here whenever the user starts or stops the
 * engine. [BootReceiver] and [EngineWatchdogWorker] read it to decide whether a restart
 * is warranted.
 *
 * Only the user's explicit Start/Stop changes [isEngineDesiredRunning]; crashes and OS
 * kills deliberately leave it set so recovery is automatic.
 */
object EnginePrefs {

    private const val PREFS = "litep2p_engine_prefs"

    private const val KEY_DESIRED_RUNNING = "desired_running"
    private const val KEY_COMMS_MODE = "comms_mode"
    private const val KEY_PEER_ID = "peer_id"
    private const val KEY_PROXY_GATEWAY = "proxy_gateway"
    private const val KEY_PROXY_CLIENT = "proxy_client"

    const val DEFAULT_COMMS_MODE = "UDP"

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** True when the user asked for the engine to run and has not since stopped it. */
    fun isEngineDesiredRunning(context: Context): Boolean =
        prefs(context).getBoolean(KEY_DESIRED_RUNNING, false)

    fun setEngineDesiredRunning(context: Context, desired: Boolean) {
        prefs(context).edit().putBoolean(KEY_DESIRED_RUNNING, desired).apply()
    }

    fun getCommsMode(context: Context): String =
        prefs(context).getString(KEY_COMMS_MODE, DEFAULT_COMMS_MODE) ?: DEFAULT_COMMS_MODE

    fun getPeerId(context: Context): String? =
        prefs(context).getString(KEY_PEER_ID, null)

    fun getProxyGateway(context: Context): Boolean =
        prefs(context).getBoolean(KEY_PROXY_GATEWAY, false)

    fun getProxyClient(context: Context): Boolean =
        prefs(context).getBoolean(KEY_PROXY_CLIENT, false)

    /** Records the full configuration of a start request so it can be replayed verbatim. */
    fun saveStartConfig(
        context: Context,
        commsMode: String,
        peerId: String,
        proxyGateway: Boolean,
        proxyClient: Boolean
    ) {
        prefs(context).edit()
            .putBoolean(KEY_DESIRED_RUNNING, true)
            .putString(KEY_COMMS_MODE, commsMode)
            .putString(KEY_PEER_ID, peerId)
            .putBoolean(KEY_PROXY_GATEWAY, proxyGateway)
            .putBoolean(KEY_PROXY_CLIENT, proxyClient)
            .apply()
    }

    /**
     * Proxy roles can be toggled while the engine runs, so they are persisted
     * independently of a start request.
     */
    fun saveProxySettings(context: Context, proxyGateway: Boolean, proxyClient: Boolean) {
        prefs(context).edit()
            .putBoolean(KEY_PROXY_GATEWAY, proxyGateway)
            .putBoolean(KEY_PROXY_CLIENT, proxyClient)
            .apply()
    }
}
