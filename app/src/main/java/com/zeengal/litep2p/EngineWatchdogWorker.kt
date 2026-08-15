package com.zeengal.litep2p

import android.content.Context
import android.util.Log
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.Worker
import androidx.work.WorkerParameters
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit

/**
 * Periodic safety net that restarts the engine if it disappeared.
 *
 * A foreground service plus START_STICKY covers most cases, but aggressive OEM battery
 * managers still kill services outright and never restart them. WorkManager survives
 * those kills and reboots, so it is used purely as a liveness check: if the user wants
 * the engine running and the service is not alive, start it again.
 *
 * This never starts an engine the user has stopped, because [EnginePrefs] is cleared on
 * an explicit stop.
 */
class EngineWatchdogWorker(
    context: Context,
    params: WorkerParameters
) : Worker(context, params) {

    override fun doWork(): Result {
        val context = applicationContext

        if (!EnginePrefs.isEngineDesiredRunning(context)) {
            Log.d(TAG, "Engine not desired running; watchdog idle")
            return Result.success()
        }

        if (LiteP2PService.isRunning && EngineController.currentState != EngineController.State.IDLE) {
            Log.d(TAG, "Engine alive (${EngineController.currentState}); nothing to do")
            return Result.success()
        }

        Log.w(TAG, "Engine expected running but service is dead; restarting")

        // The service died with the process, so any remembered RUNNING state is stale.
        EngineController.attachContext(context)
        EngineController.markIdleAfterProcessDeath()
        EngineController.start(
            context,
            EnginePrefs.getCommsMode(context),
            EnginePrefs.getPeerId(context) ?: PeerIdManager.getPeerId(context),
            EnginePrefs.getProxyGateway(context),
            EnginePrefs.getProxyClient(context)
        )

        return Result.success()
    }

    companion object {
        private const val TAG = "LiteP2P_Watchdog"
        private const val WORK_NAME = "litep2p_engine_watchdog"

        /**
         * 15 minutes is WorkManager's minimum periodic interval; anything smaller is
         * silently clamped, so there is no point requesting less.
         */
        fun schedule(context: Context) {
            try {
                val request = PeriodicWorkRequestBuilder<EngineWatchdogWorker>(
                    15, TimeUnit.MINUTES
                ).setConstraints(
                    Constraints.Builder().build()
                ).build()

                WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                    WORK_NAME,
                    ExistingPeriodicWorkPolicy.KEEP,
                    request
                )
                Log.i(TAG, "Watchdog scheduled")
            } catch (t: Throwable) {
                Log.w(TAG, "Failed to schedule watchdog: ${t.message}")
            }
        }

        fun cancel(context: Context) {
            try {
                WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME)
                Log.i(TAG, "Watchdog cancelled")
            } catch (t: Throwable) {
                Log.w(TAG, "Failed to cancel watchdog: ${t.message}")
            }
        }
    }
}
