package com.zeengal.litep2p.hook

import android.util.Log
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.zeengal.litep2p.PeerInfo

object P2P {
    private const val TAG = "LiteP2P_P2P_Hook"
    private val _peers = MutableLiveData<List<PeerInfo>>()
    val peers: LiveData<List<PeerInfo>> get() = _peers
    
    // Message received callback - stores peer_id and message content
    data class ReceivedMessage(val peerId: String, val message: String, val timestamp: Long = System.currentTimeMillis())
    private val _receivedMessages = MutableLiveData<ReceivedMessage>()
    val receivedMessages: LiveData<ReceivedMessage> get() = _receivedMessages
    
    // Store the current connection type
    private var currentConnectionType: String = "UDP"

    @JvmStatic
    external fun connect(peerId: String)

    @JvmStatic
    external fun sendMessage(peerId: String, message: ByteArray)
    
    @JvmStatic
    external fun setLogLevel(level: Int)

    // System network state callbacks (drives signaling/NAT recovery in native engine)
    @JvmStatic
    external fun setSystemNetworkInfo(isWiFi: Boolean, isNetworkAvailable: Boolean)

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
    
    // Callbacks from native code for engine state changes
    @JvmStatic
    fun onEngineStartComplete() {
        Log.d(TAG, "Engine start complete callback received")
        // We could post to a LiveData here if we want to observe engine state in the UI
    }
    
    @JvmStatic
    fun onEngineStopComplete() {
        Log.d(TAG, "Engine stop complete callback received")
        // We could post to a LiveData here if we want to observe engine state in the UI
    }

    @JvmStatic
    fun onMessageReceived(peerId: String, messageBytes: ByteArray) {
        try {
            val messageContent = String(messageBytes, Charsets.UTF_8)
            Log.d(TAG, "Message received from peer $peerId: $messageContent")
            // Post the message to observers (UI will listen to this)
            val receivedMsg = ReceivedMessage(peerId = peerId, message = messageContent)
            _receivedMessages.postValue(receivedMsg)
        } catch (e: Exception) {
            Log.e(TAG, "Error processing received message: ${e.message}", e)
        }
    }
}
