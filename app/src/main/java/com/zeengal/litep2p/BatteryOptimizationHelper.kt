package com.zeengal.litep2p

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import android.util.Log

/**
 * Helpers for escaping Doze / App Standby.
 *
 * A foreground service keeps the process alive but does *not* guarantee network access:
 * while the device is idle, Doze defers network traffic in batches, which shows up as
 * long message delays and peers timing out. Being on the battery optimization allowlist
 * is what actually keeps sockets responsive, so the app asks for it explicitly.
 *
 * The exemption is always user-granted; these helpers only surface the request.
 */
object BatteryOptimizationHelper {

    private const val TAG = "LiteP2P_Battery"

    /** True when the OS will not apply Doze restrictions to this app. */
    fun isIgnoringBatteryOptimizations(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return true
        return try {
            val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
            pm.isIgnoringBatteryOptimizations(context.packageName)
        } catch (t: Throwable) {
            Log.w(TAG, "Could not read battery optimization state: ${t.message}")
            false
        }
    }

    /**
     * Shows the system dialog asking for an exemption.
     *
     * @return false when the device has no such settings activity, so the caller can
     *         tell the user instead of appearing to do nothing.
     */
    @SuppressLint("BatteryLife")
    fun requestExemption(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return true
        return try {
            val intent = Intent(
                Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                Uri.parse("package:${context.packageName}")
            ).apply {
                if (context !is android.app.Activity) addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)
            true
        } catch (t: Throwable) {
            Log.w(TAG, "Exemption request failed: ${t.message}")
            // Fall back to the general list, which exists on more devices.
            openBatteryOptimizationSettings(context)
        }
    }

    /**
     * Opens the battery optimization list so an already-granted exemption can be reviewed
     * or revoked, and as a fallback when the direct request is unavailable.
     */
    fun openBatteryOptimizationSettings(context: Context): Boolean {
        return try {
            val intent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS).apply {
                if (context !is android.app.Activity) addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)
            true
        } catch (t: Throwable) {
            Log.w(TAG, "Could not open battery settings: ${t.message}")
            false
        }
    }
}
