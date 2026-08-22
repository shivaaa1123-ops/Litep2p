package com.zeengal.litep2p.core

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.BatteryManager
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.PowerManager
import android.util.Log
import androidx.core.content.ContextCompat

/**
 * Bridges Android system state into the engine's environment-hint API
 * (api-spec.md §13.5): network availability/transport, battery level and
 * Doze/power-save constraints.
 *
 *  - [ConnectivityManager.NetworkCallback] → [LiteP2P.setNetworkInfo]
 *  - battery (sticky [Intent.ACTION_BATTERY_CHANGED] + charge events) →
 *    [LiteP2P.setBatteryLevel]
 *  - Doze / power-save ([PowerManager.isDeviceIdleMode] /
 *    [PowerManager.isPowerSaveMode]) → [LiteP2P.setReconnectMode]
 *    (`POWER_SAVER` while constrained, `AUTO` otherwise)
 *
 * Owned by [LiteP2PService]; started after the engine is up, stopped before
 * shutdown. All pushes are idempotent one-shot JNI calls, safe from any thread.
 */
internal class EnvironmentHints(context: Context) {

    private val appContext: Context = context.applicationContext
    private var callbackThread: HandlerThread? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private val receivers = ArrayList<BroadcastReceiver>()
    private var registered = false

    /** Networks currently tracked as available. Guarded by itself. */
    private val availableNetworks = LinkedHashSet<Network>()

    fun start() {
        if (registered) return
        registered = true
        startNetworkMonitoring()
        startBatteryMonitoring()
        startPowerMonitoring()
        // Seed the engine with the current state immediately; callbacks keep
        // it fresh afterwards.
        pushNetworkHint()
        pushBatteryHint(readBattery())
        pushReconnectHint()
        Log.i(TAG, "Environment hints active")
    }

    fun stop() {
        if (!registered) return
        registered = false
        networkCallback?.let { cb ->
            runCatching {
                (appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager)
                    ?.unregisterNetworkCallback(cb)
            }
        }
        networkCallback = null
        for (receiver in receivers) runCatching { appContext.unregisterReceiver(receiver) }
        receivers.clear()
        callbackThread?.quitSafely()
        callbackThread = null
        Log.i(TAG, "Environment hints released")
    }

    /* ------------------------------------------------------------------ */
    /* Network availability + transport                                    */
    /* ------------------------------------------------------------------ */

    private fun startNetworkMonitoring() {
        val cm = appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return
        val thread = HandlerThread("litep2p-env").also { it.start() }
        callbackThread = thread

        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                synchronized(availableNetworks) { availableNetworks.add(network) }
                pushNetworkHint()
            }

            override fun onLost(network: Network) {
                synchronized(availableNetworks) { availableNetworks.remove(network) }
                pushNetworkHint()
            }
        }
        networkCallback = callback

        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        cm.registerNetworkCallback(request, callback, Handler(thread.looper))
    }

    private fun pushNetworkHint() {
        val cm = appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return
        val tracked = synchronized(availableNetworks) { availableNetworks.toList() }

        // Prefer tracked networks (callback truth); fall back to the active
        // network for devices where the callback misses e.g. VPNs.
        val available = tracked.isNotEmpty() || cm.activeNetwork != null
        var isWifi = false
        var metered = false
        for (network in tracked) {
            val caps = cm.getNetworkCapabilities(network) ?: continue
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) isWifi = true
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)) metered = true
        }
        if (tracked.isEmpty()) {
            cm.getNetworkCapabilities(cm.activeNetwork)?.let { caps ->
                isWifi = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)) metered = true
            }
        }
        LiteP2P.setNetworkInfo(isWifi, available)
        // Phase 8 lifecycle bridge: feed the NOS ResourceManager so budgets
        // (replication fan-out, discovery intensity, storage acceptance)
        // react to transport/metering changes immediately.
        pushNosSignal("connectivity", if (!available) "none" else if (isWifi) "wifi" else "cellular")
        pushNosSignal("metered", if (metered) "1" else "0")
    }


    /* ------------------------------------------------------------------ */
    /* Battery level + charging state                                      */
    /* ------------------------------------------------------------------ */

    private fun startBatteryMonitoring() {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) =
                pushBatteryHint(readBattery())
        }
        register(receiver, IntentFilter(Intent.ACTION_BATTERY_CHANGED).apply {
            addAction(Intent.ACTION_POWER_CONNECTED)
            addAction(Intent.ACTION_POWER_DISCONNECTED)
        })
    }

    private fun readBattery(): Pair<Int, Boolean>? {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val bm = appContext.getSystemService(Context.BATTERY_SERVICE) as? BatteryManager
            val pct = bm?.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY) ?: Int.MIN_VALUE
            if (pct in 0..100) return pct to (bm?.isCharging == true)
        }
        // Sticky broadcast fallback for API < M or property-less batteries.
        val sticky =
            appContext.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
                ?: return null
        val level = sticky.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
        val scale = sticky.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
        if (level < 0 || scale <= 0) return null
        val status = sticky.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
        val charging = status == BatteryManager.BATTERY_STATUS_CHARGING ||
            status == BatteryManager.BATTERY_STATUS_FULL
        return ((level * 100) / scale) to charging
    }

    private fun pushBatteryHint(battery: Pair<Int, Boolean>?) {
        battery ?: return
        LiteP2P.setBatteryLevel(battery.first, battery.second)
    }

    /* ------------------------------------------------------------------ */
    /* Doze / power-save → reconnect mode                                  */
    /* ------------------------------------------------------------------ */

    private fun startPowerMonitoring() {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) = pushReconnectHint()
        }
        register(receiver, IntentFilter(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED).apply {
            addAction(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED)
        })
    }

    private fun pushReconnectHint() {
        val pm = appContext.getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return
        val constrained = pm.isDeviceIdleMode || pm.isPowerSaveMode
        LiteP2P.setReconnectMode(
            if (constrained) ReconnectMode.POWER_SAVER else ReconnectMode.AUTO
        )
        // Doze entering means this process may be frozen at any moment: tell
        // the NOS runtime it is no longer foreground so budgets go dormant.
        if (pm.isDeviceIdleMode) pushNosSignal("foreground", "0")
    }

    /** One-shot NOS platform-signal push; never throws into system callbacks. */
    private fun pushNosSignal(signal: String, value: String) {
        runCatching { LiteP2PNative.nativeNosPlatformSignal(signal, value) }
    }

    /* ------------------------------------------------------------------ */

    private fun register(receiver: BroadcastReceiver, filter: IntentFilter) {
        ContextCompat.registerReceiver(
            appContext, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED
        )
        receivers.add(receiver)
    }

    private companion object {
        const val TAG = "LiteP2P_EnvHints"
    }
}
