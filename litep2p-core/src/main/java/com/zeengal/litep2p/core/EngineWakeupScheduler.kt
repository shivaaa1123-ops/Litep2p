package com.zeengal.litep2p.core

import android.content.Context
import android.util.Log
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/**
 * Phase 8 lifecycle bridge (master doc §7 execution modes / §8 central
 * scheduling): maps the engine's central scheduler wakeup requests onto
 * **WorkManager** — the only Android mechanism that survives process death
 * and Doze batching.
 *
 * Doctrine ("process liveness is an optimization, durable state is the source
 * of truth"):
 *  - The engine asks for future work via `IPlatformAdapter::requestWakeup()`;
 *    JNI forwards it here and a durable one-shot job is enqueued.
 *  - A unique periodic heartbeat (WorkManager minimum: 15 minutes) opens a
 *    bounded maintenance window so a frozen/dead-then-restarted engine still
 *    reconciles (scheduler drain, lease sweep, replication retry).
 *  - Each burst grants the runtime [WINDOW_BUDGET_MS] of CPU; everything
 *    longer waits for the next opportunity. Idle cost stays near zero.
 *
 * All methods are safe to call from any thread; scheduling failures are
 * logged and swallowed (the engine keeps running without background help).
 */
internal object EngineWakeupScheduler {

    private const val TAG = "LiteP2P_WakeSched"
    private const val HEARTBEAT_WORK = "litep2p_maintenance_heartbeat"
    private const val WAKEUP_PREFIX = "litep2p_wakeup_"

    /** CPU budget granted per wakeup window (milliseconds). */
    const val WINDOW_BUDGET_MS: Long = 3_000L

    @Volatile
    private var appContext: Context? = null

    /** Capture the application context once (called from [LiteP2PRuntime.start]). */
    fun ensureInitialized(context: Context) {
        if (appContext == null) appContext = context.applicationContext
    }

    /**
     * Ensures the periodic maintenance heartbeat exists. UPDATE policy keeps
     * exactly one heartbeat across repeated start()/sticky restarts.
     */
    fun scheduleHeartbeat(context: Context) {
        ensureInitialized(context)
        val request = PeriodicWorkRequestBuilder<EngineHeartbeatWorker>(15, TimeUnit.MINUTES)
            .setConstraints(connectedNetwork())
            .build()
        runCatching {
            WorkManager.getInstance(context.applicationContext)
                .enqueueUniquePeriodicWork(HEARTBEAT_WORK, ExistingPeriodicWorkPolicy.UPDATE, request)
        }.onFailure { Log.w(TAG, "heartbeat scheduling failed: ${it.message}") }
    }

    /** Cancels the heartbeat (engine intentionally stopped by the user). */
    fun cancelAll(context: Context) {
        runCatching {
            WorkManager.getInstance(context.applicationContext)
                .cancelUniqueWork(HEARTBEAT_WORK)
        }
    }

    /**
     * Native engine requested a wakeup in [delayMs] ms → durable one-shot
     * job. Unique-per-reason REPLACE coalesces bursts of identical requests.
     * No-op before [ensureInitialized] (early-boot requests are flushed from
     * the native pending queue once the bridge registers).
     */
    fun onEngineWakeupRequested(reason: String, delayMs: Long) {
        val context = appContext ?: return
        val request = OneTimeWorkRequestBuilder<EngineWakeupWorker>()
            .setInitialDelay(delayMs.coerceIn(0L, TimeUnit.MINUTES.toMillis(15)), TimeUnit.MILLISECONDS)
            .setConstraints(connectedNetwork())
            .build()
        runCatching {
            WorkManager.getInstance(context).enqueueUniqueWork(
                WAKEUP_PREFIX + reason, ExistingWorkPolicy.REPLACE, request)
        }.onFailure { Log.w(TAG, "wakeup scheduling failed ($reason): ${it.message}") }
    }

    private fun connectedNetwork(): Constraints = Constraints.Builder()
        .setRequiredNetworkType(NetworkType.CONNECTED)
        .build()

    /** A reconcile burst only makes sense while the engine should be alive. */
    internal fun shouldRunBurst(context: Context): Boolean =
        LiteP2PRuntime.isDesiredRunning(context) &&
            (LiteP2P.state == EngineState.RUNNING || LiteP2P.state == EngineState.STARTING)

    /** Opens the bounded wakeup window inside the native runtime. */
    internal fun openWindow(reason: String) {
        runCatching {
            LiteP2PNative.nativeNosPlatformSignal("wakeup_window", WINDOW_BUDGET_MS.toString())
        }.onFailure { Log.w(TAG, "$reason burst skipped: ${it.message}") }
    }
}

/**
 * Runs one bounded scheduler reconcile burst inside the native runtime
 * (drain deferred scheduler work, sweep expired handoff leases, retry
 * backed-off replication). Deliberately succeeds even when it skips: durable
 * state remains the source of truth and the next window reconciles anyway.
 */
internal class EngineWakeupWorker(context: Context, params: WorkerParameters) :
    CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        if (EngineWakeupScheduler.shouldRunBurst(applicationContext)) {
            EngineWakeupScheduler.openWindow("delivery_wakeup")
        }
        return Result.success()
    }
}

/** Periodic opportunistic-background-mode window (>= every 15 minutes). */
internal class EngineHeartbeatWorker(context: Context, params: WorkerParameters) :
    CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        if (EngineWakeupScheduler.shouldRunBurst(applicationContext)) {
            EngineWakeupScheduler.openWindow("heartbeat")
        }
        return Result.success()
    }
}