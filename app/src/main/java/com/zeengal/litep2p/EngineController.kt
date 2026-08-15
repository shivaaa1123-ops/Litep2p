package com.zeengal.litep2p

import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData

/**
 * Process-wide authority for engine lifecycle state.
 *
 * Engine state cannot live in an Activity: the engine keeps running while the app is
 * backgrounded, so a freshly created Activity must be able to discover that the engine
 * is already RUNNING rather than defaulting to IDLE and offering a second Start.
 *
 * This object holds that state, exposes it as [LiveData] for the UI, and translates
 * start/stop requests into commands for [LiteP2PService]. It performs no native calls
 * itself; the service does that on a background thread.
 *
 * State transitions are driven by two sources:
 *  - requests   (start/stop) move us into the transitional STARTING / STOPPING states
 *  - native callbacks ([onEngineStartComplete] / [onEngineStopComplete]) confirm arrival
 *    at RUNNING / IDLE
 *
 * Only the native callbacks may declare a terminal state, so the UI can never show
 * "Running" before the engine has actually finished coming up.
 */
object EngineController {

    private const val TAG = "LiteP2P_EngineController"

    enum class State { IDLE, STARTING, RUNNING, STOPPING }

    private val _state = MutableLiveData(State.IDLE)
    val state: LiveData<State> get() = _state

    @Volatile
    var currentState: State = State.IDLE
        private set

    /**
     * The comms mode the engine was last started with.
     *
     * The UI compares against this to detect that the user picked a different transport
     * while the engine is already running, which requires a stop/start cycle because the
     * listeners are bound at startup.
     */
    @Volatile
    var lastCommsMode: String? = null
        private set

    @Volatile
    private var proxyGateway: Boolean = false

    @Volatile
    private var proxyClient: Boolean = false

    private fun setState(next: State) {
        currentState = next
        _state.postValue(next)
        Log.d(TAG, "Engine state -> $next")
    }

    /**
     * Requests engine startup.
     *
     * Ignored unless we are IDLE; without this guard a double tap (or an autostart intent
     * racing the user) could issue two starts and leave native in a BUSY state with the
     * UI showing the wrong thing.
     */
    fun start(
        context: Context,
        commsMode: String,
        peerId: String,
        proxyGateway: Boolean,
        proxyClient: Boolean
    ) {
        if (currentState != State.IDLE) {
            Log.w(TAG, "start() ignored; state is $currentState")
            return
        }

        this.proxyGateway = proxyGateway
        this.proxyClient = proxyClient
        lastCommsMode = commsMode

        // Persist before starting so a crash or OS kill between here and RUNNING still
        // leaves enough information for the watchdog to restore the engine.
        EnginePrefs.saveStartConfig(context, commsMode, peerId, proxyGateway, proxyClient)

        setState(State.STARTING)

        val intent = Intent(context, LiteP2PService::class.java).apply {
            action = LiteP2PService.ACTION_START
            putExtra(LiteP2PService.EXTRA_COMMS_MODE, commsMode)
            putExtra(LiteP2PService.EXTRA_PEER_ID, peerId)
            putExtra(LiteP2PService.EXTRA_PROXY_GATEWAY, proxyGateway)
            putExtra(LiteP2PService.EXTRA_PROXY_CLIENT, proxyClient)
        }
        startService(context, intent)

        EngineWatchdogWorker.schedule(context)
    }

    /** Requests shutdown. Ignored unless the engine is RUNNING or still STARTING. */
    fun stop(context: Context) {
        if (currentState == State.IDLE || currentState == State.STOPPING) {
            Log.w(TAG, "stop() ignored; state is $currentState")
            return
        }

        // This is a deliberate user stop, so cancel the automatic recovery machinery;
        // otherwise the watchdog would helpfully restart what the user just stopped.
        EnginePrefs.setEngineDesiredRunning(context, false)
        EngineWatchdogWorker.cancel(context)

        setState(State.STOPPING)

        val intent = Intent(context, LiteP2PService::class.java).apply {
            action = LiteP2PService.ACTION_STOP
        }
        startService(context, intent)
    }

    /**
     * Records proxy roles toggled while the engine is running.
     *
     * The native call is made by the caller; this only keeps the persisted copy in sync
     * so a later restart restores the same roles.
     */
    fun rememberProxySettings(gateway: Boolean, client: Boolean) {
        proxyGateway = gateway
        proxyClient = client
        appContext?.let { EnginePrefs.saveProxySettings(it, gateway, client) }
    }

    /** Called from native (via MainActivity) when startup has actually completed. */
    fun onEngineStartComplete() {
        setState(State.RUNNING)
        LiteP2PService.onEngineRunning()
    }

    /** Called from native (via MainActivity) when shutdown has actually completed. */
    fun onEngineStopComplete() {
        setState(State.IDLE)
        LiteP2PService.onEngineStopped()
    }

    /**
     * Reconciles state after the service process was recreated without us.
     *
     * If the service is gone but state still claims RUNNING, the engine died with it.
     */
    fun markIdleAfterProcessDeath() {
        if (currentState != State.IDLE) {
            Log.w(TAG, "Reconciling stale state $currentState -> IDLE after process death")
            setState(State.IDLE)
        }
    }

    @Volatile
    private var appContext: Context? = null

    fun attachContext(context: Context) {
        appContext = context.applicationContext
    }

    private fun startService(context: Context, intent: Intent) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        } catch (t: Throwable) {
            // Starting a foreground service is disallowed from the background on newer
            // Android versions. Surface it rather than leaving the UI stuck mid-transition.
            Log.e(TAG, "Failed to start LiteP2PService: ${t.message}", t)
            setState(State.IDLE)
        }
    }
}
