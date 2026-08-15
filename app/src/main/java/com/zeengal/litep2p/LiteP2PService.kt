package com.zeengal.litep2p

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
import java.util.concurrent.Executors

/**
 * Owns the native P2P engine for the lifetime of the process.
 *
 * Running the engine inside an Activity meant it was torn down whenever the user left
 * the app, so peers dropped and messages were missed. A foreground service keeps the
 * process alive and visible to the user, which is also what Android requires for
 * sustained background networking.
 *
 * Responsibilities:
 *  - perform native start/stop off the main thread (both can block for seconds)
 *  - hold the wake / wifi / multicast locks the engine needs to keep receiving packets
 *  - stay sticky so the OS recreates it after a low-memory kill
 *
 * The service intentionally does not own *state*: [EngineController] does, so the UI can
 * observe it whether or not this service is currently alive.
 */
class LiteP2PService : Service() {

    // Native start/stop are blocking and must never run on the main thread. A single
    // thread also serialises them, so a stop can't overlap a start.
    private val engineExecutor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "litep2p-engine").apply { isDaemon = false }
    }

    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null
    private var multicastLock: WifiManager.MulticastLock? = null

    override fun onCreate() {
        super.onCreate()
        EngineController.attachContext(this)
        createNotificationChannel()
        instance = this
        Log.i(TAG, "Service created")
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Android requires startForeground() promptly after startForegroundService(),
        // regardless of which action we are handling, or the app is killed with an ANR.
        startForegroundCompat(buildNotification(statusLine()))

        when (intent?.action) {
            ACTION_START -> {
                val commsMode = intent.getStringExtra(EXTRA_COMMS_MODE) ?: EnginePrefs.DEFAULT_COMMS_MODE
                val peerId = intent.getStringExtra(EXTRA_PEER_ID) ?: PeerIdManager.getPeerId(this)
                val gateway = intent.getBooleanExtra(EXTRA_PROXY_GATEWAY, false)
                val client = intent.getBooleanExtra(EXTRA_PROXY_CLIENT, false)
                requestStart(commsMode, peerId, gateway, client)
            }

            ACTION_STOP -> requestStop()

            else -> {
                // Null intent means the OS recreated us after a kill (START_STICKY).
                // Restore whatever the user last asked for.
                if (intent == null && EnginePrefs.isEngineDesiredRunning(this)) {
                    Log.i(TAG, "Recreated by system; restoring engine from saved config")
                    EngineController.markIdleAfterProcessDeath()
                    EngineController.start(
                        this,
                        EnginePrefs.getCommsMode(this),
                        EnginePrefs.getPeerId(this) ?: PeerIdManager.getPeerId(this),
                        EnginePrefs.getProxyGateway(this),
                        EnginePrefs.getProxyClient(this)
                    )
                }
            }
        }

        // Sticky so the OS brings the service back after reclaiming memory.
        return START_STICKY
    }

    private fun requestStart(
        commsMode: String,
        peerId: String,
        proxyGateway: Boolean,
        proxyClient: Boolean
    ) {
        engineExecutor.execute {
            try {
                acquireLocks()
                Log.i(TAG, "Starting engine mode=$commsMode peer=$peerId")

                // The native engine is started through the plain EngineNative object (not a
                // Context), so it cannot call getFilesDir() itself. Supply the real files
                // directory up front; the native bridge uses it for config.json, the Noise
                // keystore and the peer DB (and to avoid a JNI NoSuchMethodError crash).
                EngineNative.nativeSetFilesDir(filesDir.absolutePath)

                val result = EngineNative.nativeStartLiteP2PWithPeerId(commsMode, peerId)
                Log.i(TAG, "Native start returned: $result")

                if (!result.startsWith("BUSY")) {
                    // Proxy roles are applied after start so they survive a restart.
                    EngineNative.nativeConfigureProxy(proxyGateway, proxyClient)
                } else {
                    // Native refused; don't leave the UI stuck in STARTING forever.
                    Log.w(TAG, "Native engine busy; aborting start")
                    releaseLocks()
                    EngineController.onEngineStopComplete()
                }
            } catch (t: Throwable) {
                Log.e(TAG, "Engine start failed: ${t.message}", t)
                releaseLocks()
                EngineController.onEngineStopComplete()
            }
        }
    }

    private fun requestStop() {
        engineExecutor.execute {
            try {
                Log.i(TAG, "Stopping engine")
                EngineNative.nativeStopLiteP2P()
            } catch (t: Throwable) {
                Log.e(TAG, "Engine stop failed: ${t.message}", t)
                // Force the state machine back to IDLE so the UI is usable again.
                EngineController.onEngineStopComplete()
            }
        }
    }

    /**
     * Keeps the CPU and Wi-Fi radio available while the engine is running.
     *
     * Without these, Doze and Wi-Fi power saving suspend packet delivery, which shows up
     * as peers silently going stale. The multicast lock is required specifically for the
     * UDP broadcast discovery beacons.
     */
    private fun acquireLocks() {
        try {
            if (wakeLock == null) {
                val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
                wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "litep2p:engine").apply {
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
                wifiLock = wm.createWifiLock(mode, "litep2p:wifi").apply {
                    setReferenceCounted(false)
                    acquire()
                }
            }
            if (multicastLock == null) {
                multicastLock = wm.createMulticastLock("litep2p:multicast").apply {
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

    private fun statusLine(): String = when (EngineController.currentState) {
        EngineController.State.IDLE -> "Idle"
        EngineController.State.STARTING -> "Starting…"
        EngineController.State.RUNNING -> "Running · ${EngineController.lastCommsMode ?: "?"}"
        EngineController.State.STOPPING -> "Stopping…"
    }

    private fun buildNotification(text: String): Notification {
        val openApp = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, LiteP2PService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("LiteP2P engine")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_service_notification)
            .setContentIntent(openApp)
            .addAction(0, "Stop", stopIntent)
            .setOngoing(true)
            .setSilent(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

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
        runCatching { nm.notify(NOTIFICATION_ID, buildNotification(statusLine())) }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CHANNEL_ID) != null) return

        val channel = NotificationChannel(
            CHANNEL_ID,
            "LiteP2P engine",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Shows whether the peer-to-peer engine is running."
            setShowBadge(false)
        }
        nm.createNotificationChannel(channel)
    }

    override fun onDestroy() {
        Log.i(TAG, "Service destroyed")
        releaseLocks()
        engineExecutor.shutdown()
        if (instance === this) instance = null
        super.onDestroy()
    }

    companion object {
        private const val TAG = "LiteP2P_Service"

        const val ACTION_START = "com.zeengal.litep2p.action.START_ENGINE"
        const val ACTION_STOP = "com.zeengal.litep2p.action.STOP_ENGINE"

        const val EXTRA_COMMS_MODE = "comms_mode"
        const val EXTRA_PEER_ID = "peer_id"
        const val EXTRA_PROXY_GATEWAY = "proxy_gateway"
        const val EXTRA_PROXY_CLIENT = "proxy_client"

        private const val CHANNEL_ID = "litep2p_engine"
        private const val NOTIFICATION_ID = 1337

        @Volatile
        private var instance: LiteP2PService? = null

        /** True while the service is alive; used by the watchdog to detect a dead engine. */
        val isRunning: Boolean get() = instance != null

        fun onEngineRunning() {
            instance?.updateNotification()
        }

        /**
         * Engine has fully stopped. Drop the locks and leave the foreground so the
         * notification does not linger claiming the engine is active.
         */
        fun onEngineStopped() {
            val svc = instance ?: return
            svc.releaseLocks()
            runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    svc.stopForeground(Service.STOP_FOREGROUND_REMOVE)
                } else {
                    @Suppress("DEPRECATION")
                    svc.stopForeground(true)
                }
            }
            svc.stopSelf()
        }
    }
}
