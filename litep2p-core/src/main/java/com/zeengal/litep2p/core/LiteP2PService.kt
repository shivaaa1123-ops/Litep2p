package com.zeengal.litep2p.core

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import java.util.concurrent.Executors

/**
 * SDK-owned foreground service that hosts the native engine (ask.md §4).
 *
 * Normally started indirectly via [LiteP2PRuntime.start]; the service then:
 *
 *  - performs native `init`/`start`/`shutdown` off the main thread (all can
 *    block for seconds) on a dedicated engine thread,
 *  - holds the partial wakelock + Wi-Fi/multicast locks needed to keep
 *    receiving packets through Doze and Wi-Fi power saving,
 *  - pushes system network/battery/power state into the engine
 *    ([EnvironmentHints]),
 *  - returns [START_STICKY] so the OS recreates it (and the engine) after a
 *    low-memory kill, restoring the last-requested configuration.
 *
 * The notification is customizable via [LiteP2PRuntime] (icon, title, text,
 * launch activity, builder hook) or by subclassing and overriding
 * [onBuildNotification].
 */
open class LiteP2PService : Service() {

    // Native start/stop are blocking and must never run on the main thread. A
    // single thread also serializes them, so a stop can't overlap a start.
    private val engineExecutor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "litep2p-engine").apply { isDaemon = false }
    }

    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null
    private var multicastLock: WifiManager.MulticastLock? = null
    private var hints: EnvironmentHints? = null

    /** Keeps the notification in sync with engine state transitions. */
    private val engineListener = object : LiteP2PListener {
        override fun onEngineStarted() = updateNotification()
        override fun onEngineStopped() = updateNotification()
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        instance = this
        Log.i(TAG, "SDK service created")
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Android requires startForeground() promptly after
        // startForegroundService(), regardless of which action we are
        // handling, or the app is killed with an ANR.
        startForegroundCompat(buildNotification(statusText()))

        when (intent?.action) {
            LiteP2PRuntime.ACTION_START -> {
                val config = LiteP2PRuntime.pendingConfig
                    ?: LiteP2PRuntime.reconstructConfig(this)
                    ?: LiteP2PRuntime.defaultConfig(this)
                requestStart(config)
            }

            LiteP2PRuntime.ACTION_STOP -> requestStop()

            else -> {
                // Null intent = the OS recreated us (START_STICKY). Restore
                // whatever the integrator last asked for.
                if (intent == null && LiteP2PRuntime.desiredRunning(this)) {
                    Log.i(TAG, "Recreated by system; restoring engine")
                    val config = LiteP2PRuntime.reconstructConfig(this)
                    if (config != null) {
                        requestStart(config)
                    } else {
                        finishService()
                    }
                } else {
                    finishService()
                }
            }
        }

        // Sticky so the OS brings the service (and engine) back after a kill.
        return START_STICKY
    }


    /* ------------------------------------------------------------------ */
    /* Engine lifecycle (engine thread)                                    */
    /* ------------------------------------------------------------------ */

    private fun requestStart(config: LiteP2PConfig) {
        engineExecutor.execute {
            try {
                acquireLocks()
                Log.i(TAG, "Starting engine (${config.commsMode})")

                // init() refuses while RUNNING/STARTING — e.g. a sticky
                // restart racing a still-alive engine. Clear and retry once.
                if (LiteP2P.init(config) == EngineResult.INVALID_STATE) {
                    Log.w(TAG, "Engine not clean; shutting down before start")
                    LiteP2P.shutdown()
                    LiteP2P.init(config)
                }

                val result = LiteP2P.start()
                if (result == EngineResult.OK) {
                    LiteP2P.addListener(engineListener)
                    hints = EnvironmentHints(applicationContext).also { it.start() }
                    LiteP2PRuntime.setDesired(applicationContext, true)
                    Log.i(TAG, "Engine started")
                } else {
                    Log.w(TAG, "Native engine refused start ($result); aborting")
                    LiteP2PRuntime.setDesired(applicationContext, false)
                    releaseLocks()
                    finishService()
                }
                updateNotification()
            } catch (t: Throwable) {
                Log.e(TAG, "Engine start failed: ${t.message}", t)
                LiteP2PRuntime.setDesired(applicationContext, false)
                releaseLocks()
                finishService()
            }
        }
    }

    private fun requestStop() {
        engineExecutor.execute {
            try {
                Log.i(TAG, "Stopping engine")
                hints?.stop()
                hints = null
                LiteP2P.removeListener(engineListener)
                LiteP2P.shutdown()
            } catch (t: Throwable) {
                Log.e(TAG, "Engine stop failed: ${t.message}", t)
            } finally {
                LiteP2PRuntime.setDesired(applicationContext, false)
                releaseLocks()
                finishService()
            }
        }
    }

    /** Removes the foreground notification and stops the service. */
    private fun finishService() {
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }


    /* ------------------------------------------------------------------ */
    /* Power locks                                                          */
    /* ------------------------------------------------------------------ */

    /**
     * Keeps the CPU and Wi-Fi radio available while the engine is running.
     *
     * Without these, Doze and Wi-Fi power saving suspend packet delivery,
     * which shows up as peers silently going stale. The multicast lock is
     * required specifically for the UDP broadcast discovery beacons.
     */
    private fun acquireLocks() {
        try {
            if (wakeLock == null) {
                val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
                wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "litep2p:runtime").apply {
                    setReferenceCounted(false)
                    acquire()
                }
            }

            val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            if (wifiLock == null) {
                val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    WifiManager.WIFI_MODE_FULL_LOW_LATENCY
                } else {
                    @Suppress("DEPRECATION")
                    WifiManager.WIFI_MODE_FULL_HIGH_PERF
                }
                wifiLock = wm.createWifiLock(mode, "litep2p:runtime").apply {
                    setReferenceCounted(false)
                    acquire()
                }
            }
            if (multicastLock == null) {
                multicastLock = wm.createMulticastLock("litep2p:runtime").apply {
                    setReferenceCounted(false)
                    acquire()
                }
            }
            Log.i(TAG, "Locks acquired")
        } catch (t: Throwable) {
            Log.w(TAG, "Failed to acquire locks: ${t.message}")
        }
    }

    private fun releaseLocks() {
        runCatching { wakeLock?.takeIf { it.isHeld }?.release() }
        runCatching { wifiLock?.takeIf { it.isHeld }?.release() }
        runCatching { multicastLock?.takeIf { it.isHeld }?.release() }
        wakeLock = null
        wifiLock = null
        multicastLock = null
    }


    /* ------------------------------------------------------------------ */
    /* Notification                                                         */
    /* ------------------------------------------------------------------ */

    private fun statusText(): String = when (LiteP2P.state) {
        EngineState.STARTING -> getString(R.string.litep2p_notification_text_starting)
        EngineState.RUNNING -> getString(R.string.litep2p_notification_text_running)
        EngineState.STOPPING -> getString(R.string.litep2p_notification_text_stopping)
        EngineState.STOPPED -> getString(R.string.litep2p_notification_text_stopped)
    }

    /**
     * Builds the foreground notification from [LiteP2PRuntime] customization.
     * Override to fully replace it (or use
     * [LiteP2PRuntime.notificationCustomizer] for tweaks).
     */
    protected open fun onBuildNotification(text: String): Notification {
        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(LiteP2PRuntime.notificationSmallIconResId)
            .setContentTitle(
                LiteP2PRuntime.notificationTitle
                    ?: getString(R.string.litep2p_notification_title)
            )
            .setContentText(LiteP2PRuntime.notificationText ?: text)
            .setOngoing(true)
            .setSilent(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)

        LiteP2PRuntime.launchActivity?.let { activity ->
            val open = PendingIntent.getActivity(
                this,
                0,
                Intent(this, activity).apply {
                    flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
                },
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
            builder.setContentIntent(open)
        }


        val stop = PendingIntent.getService(
            this,
            1,
            Intent(this, LiteP2PService::class.java).apply { action = LiteP2PRuntime.ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        builder.addAction(0, getString(R.string.litep2p_notification_action_stop), stop)

        LiteP2PRuntime.notificationCustomizer?.invoke(builder)
        return builder.build()
    }

    private fun buildNotification(text: String): Notification = onBuildNotification(text)

    private fun startForegroundCompat(notification: Notification) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
                )
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        } catch (t: Throwable) {
            Log.e(TAG, "startForeground failed: ${t.message}", t)
        }
    }

    private fun updateNotification() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        runCatching { nm.notify(NOTIFICATION_ID, buildNotification(statusText())) }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CHANNEL_ID) != null) return

        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.litep2p_notification_channel_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = getString(R.string.litep2p_notification_channel_description)
            setShowBadge(false)
        }
        nm.createNotificationChannel(channel)
    }

    /* ------------------------------------------------------------------ */

    override fun onDestroy() {
        Log.i(TAG, "SDK service destroyed")
        hints?.stop()
        hints = null
        releaseLocks()
        engineExecutor.shutdown()
        if (instance === this) instance = null
        super.onDestroy()
    }

    companion object {
        private const val TAG = "LiteP2P_Service"

        private const val CHANNEL_ID = "litep2p_runtime"
        private const val NOTIFICATION_ID = 0x1C50

        @Volatile
        private var instance: LiteP2PService? = null

        /** True while the SDK service instance is alive. */
        val isRunning: Boolean get() = instance != null
    }
}
