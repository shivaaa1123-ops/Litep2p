package com.zeengal.litep2p

import android.content.Context
import java.util.UUID

object PeerIdManager {
    private const val PREFS_NAME = "litep2p_prefs"
    private const val PEER_ID_KEY = "peer_id"

    fun getPeerId(context: Context): String {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        var peerId = prefs.getString(PEER_ID_KEY, null)
        if (peerId == null) {
            peerId = UUID.randomUUID().toString()
            prefs.edit().putString(PEER_ID_KEY, peerId).apply()
        }
        return peerId
    }
}
