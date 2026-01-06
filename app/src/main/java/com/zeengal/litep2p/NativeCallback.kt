package com.zeengal.litep2p

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData

object NativeCallback {
    // LiveData that UI can observe
    private val _peers = MutableLiveData<List<PeerInfo>>(emptyList())
    val peers: LiveData<List<PeerInfo>> = _peers

    // Called from native (must be public & static)
    @JvmStatic
    fun onPeersUpdate(peersArray: Array<PeerInfo>) {
        // called from native threads — use postValue
        _peers.postValue(peersArray.toList())
    }
}