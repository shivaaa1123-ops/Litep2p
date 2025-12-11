package com.zeengal.litep2p.hook

import android.util.Log
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.zeengal.litep2p.PeerInfo

object P2P {
    private const val TAG = "LiteP2P_P2P_Hook"
    private val _peers = MutableLiveData<List<PeerInfo>>()
    val peers: LiveData<List<PeerInfo>> get() = _peers
    
    // Store the current connection type
    private var currentConnectionType: String = "TCP"

    @JvmStatic
    external fun connect(peerId: String)

    @JvmStatic
    external fun sendMessage(peerId: String, message: ByteArray)

    // Returns "TCP" or "UDP" based on current UI selection
    @JvmStatic
    fun getConnectionType(): String {
        return currentConnectionType
    }
    
    // Set the connection type from the UI
    @JvmStatic
    fun setConnectionType(type: String) {
        currentConnectionType = type
    }

    @JvmStatic
    fun onPeersUpdated(peers: Array<PeerInfo>) {
        // Log what we received from C++
        Log.d(TAG, "onPeersUpdated called with ${peers.size} peers.")
        for (peer in peers) {
            Log.d(TAG, "  - Peer: ${peer.id}, IP: ${peer.ip}, Connected: ${peer.connected}")
        }
        // This posts the updated list to any observers.
        _peers.postValue(peers.toList())
    }
}
