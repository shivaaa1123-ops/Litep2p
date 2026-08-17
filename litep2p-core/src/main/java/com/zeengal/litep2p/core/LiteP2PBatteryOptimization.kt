package com.zeengal.litep2p.core

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import android.util.Log

/**
 * Doze / App-Standby exemption helpers for the LiteP2P runtime.
 *
 * A foreground service keeps the process alive but does *not* guarantee network
 * access: while the device is idle, Doze defers network traffic in batches,
 * which shows up as long message delays and peers timing out. Being on the
 * battery-optimization allowlist is what actually keeps sockets responsive.
 *
 * The exemption is always **user-granted**; these helpers only surface the
 * request. [requestExemptionIfNeeded] fires the system dialog at most once per
 * install (and never when the app is already exempt), so it respects the
 * user's choice. Integrators can re-ask any time from their own UI with
 * [requestExemption].
 */
object LiteP2PBatteryOptimization {

    private const val TAG = "LiteP2P_Battery"
    private const val PREFS = "litep2p_battery"
    private const val KEY_ASKED = "exemption_requested_once"

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
     * Shows the system "allow battery exemption" dialog. Safe to call from any
     * context ([FLAG_ACTIVITY_NEW_TASK] is added when no [activity] is given).
     *
     * @return true if the dialog was launched (or the device is < API 23 and no
     *         dialog exists), false if it could not be shown.
     */
    @SuppressLint("BatteryLife")
    fun requestExemption(context: Context, activity: Activity? = null): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return true
        return try {
            val intent = Intent(
                Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                Uri.parse("package:${context.packageName}")
            )
            if (activity != null) {
                activity.startActivity(intent)
            } else {
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(intent)
            }
            true
        } catch (t: Throwable) {
            Log.w(TAG, "Battery exemption request failed: ${t.message}")
            false
        }
    }

    /**
     * One-shot, user-respecting exemption request, intended to be called from
     * [LiteP2PRuntime.start]:
     *  - no-op below API 23,
     *  - no-op when the app is already exempt,
     *  - no-op if we already asked once this install (the user's choice is
     *    final; use [requestExemption] to re-ask from app UI).
     *
     * @param activity optional Activity; when provided the system dialog is
     *        launched from it (preferred), otherwise from the app context.
     */
    fun requestExemptionIfNeeded(context: Context, activity: Activity? = null) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return
        val app = context.applicationContext
        val prefs = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (prefs.getBoolean(KEY_ASKED, false)) return   // already asked; respect choice
        if (isIgnoringBatteryOptimizations(app)) return  // already exempt

        prefs.edit().putBoolean(KEY_ASKED, true).apply()
        if (requestExemption(app, activity)) {
            Log.i(TAG, "Battery-optimization exemption requested (user decides)")
        } else {
            Log.w(TAG, "Could not request battery exemption on this device")
        }
    }
}
