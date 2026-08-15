package com.zeengal.litep2p

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Restores the engine after a reboot.
 *
 * A peer that silently stops existing after every reboot is not usable as
 * always-on infrastructure, so if the user had the engine running when the device went
 * down we bring it back automatically. A reboot is not treated as an instruction to
 * stop, so [EnginePrefs.isEngineDesiredRunning] is still set here.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action
        if (action != Intent.ACTION_BOOT_COMPLETED &&
            action != Intent.ACTION_MY_PACKAGE_REPLACED &&
            action != Intent.ACTION_LOCKED_BOOT_COMPLETED
        ) {
            return
        }

        if (!EnginePrefs.isEngineDesiredRunning(context)) {
            Log.i(TAG, "Boot completed but engine was not desired running; nothing to do")
            return
        }

        Log.i(TAG, "Boot completed; restoring engine")

        // Go through EngineController rather than starting the service directly so the
        // in-memory state machine and the persisted config stay consistent.
        EngineController.attachContext(context)
        EngineController.start(
            context,
            EnginePrefs.getCommsMode(context),
            EnginePrefs.getPeerId(context) ?: PeerIdManager.getPeerId(context),
            EnginePrefs.getProxyGateway(context),
            EnginePrefs.getProxyClient(context)
        )
    }

    private companion object {
        const val TAG = "LiteP2P_BootReceiver"
    }
}
