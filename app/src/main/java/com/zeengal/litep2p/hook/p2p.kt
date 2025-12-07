package com.zeengal.litep2p.hook

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.zeengal.litep2p.PeerInfo

object P2P {
    private val _peers = MutableLiveData<List<PeerInfo>>()
    val peers: LiveData<List<PeerInfo>> = _peers

    // --- THIS IS THE FIX ---
    // The connect method now takes the alphanumeric peer ID.
    @JvmStatic
    external fun connect(peerId: String)

    @JvmStatic
    external fun sendMessage(peerId: String, message: ByteArray)

    @JvmStatic
    fun onPeersUpdated(peers: Array<PeerInfo>) {
        _peers.postValue(peers.toList())
    }
}
