package com.zeengal.litep2p.hook

import android.util.Log
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.zeengal.litep2p.MessageTraceStore
import com.zeengal.litep2p.PeerInfo
import org.json.JSONObject

object P2P {
    private const val TAG = "LiteP2P_P2P_Hook"
    private val _peers = MutableLiveData<List<PeerInfo>>()
    val peers: LiveData<List<PeerInfo>> get() = _peers
    
    // Message received callback - stores peer_id and message content
    data class ReceivedMessage(val peerId: String, val message: String, val timestamp: Long = System.currentTimeMillis())
    private val _receivedMessages = MutableLiveData<ReceivedMessage>()
    val receivedMessages: LiveData<ReceivedMessage> get() = _receivedMessages

    enum class MessageDirection { IN, OUT }

    data class MessageEvent(
        val direction: MessageDirection,
        val peerId: String,
        val preview: String,
        val timestampMs: Long = System.currentTimeMillis(),
        val messageId: String = MessageTraceStore.generateMessageId()
    )

    private const val MAX_MESSAGE_EVENTS = 200
    private val messageHistory = ArrayDeque<MessageEvent>(MAX_MESSAGE_EVENTS)
    private val _messageEvents = MutableLiveData<List<MessageEvent>>(emptyList())
    val messageEvents: LiveData<List<MessageEvent>> get() = _messageEvents
    
    // Store the current connection type
    private var currentConnectionType: String = "UDP"

    @JvmStatic
    external fun connect(peerId: String)

    @JvmStatic
    external fun sendMessage(peerId: String, message: ByteArray)

    /**
     * UI should call this instead of [sendMessage] so we can show outgoing messages in the Messages tab.
     */
    @JvmStatic
    fun sendMessageTracked(peerId: String, message: ByteArray) {
        val messageId = MessageTraceStore.generateMessageId()
        val preview: String
        try {
            val body = String(message, Charsets.UTF_8)
            preview = body.take(200)

            // Request an application-level ACK so we can measure delivery latency.
            val sentTsMs = System.currentTimeMillis()
            val envelope = JSONObject().apply {
                put("type", "LP_APP")
                put("msg_id", messageId)
                put("requires_ack", true)
                put("sent_ts_ms", sentTsMs)
                put("body", body)
            }.toString()

            addMessageEvent(MessageEvent(MessageDirection.OUT, peerId, preview, messageId = messageId))
            MessageTraceStore.trackOutgoing(messageId, peerId, currentConnectionType, message.size, preview)
            MessageTraceStore.recordEvent(messageId, MessageTraceStore.EventType.TX_SENT, "Sent (requires_ack=true)")

            sendMessage(peerId, envelope.toByteArray(Charsets.UTF_8))
            return
        } catch (_: Throwable) {
            val fallback = "<binary ${message.size} bytes>"
            addMessageEvent(MessageEvent(MessageDirection.OUT, peerId, fallback, messageId = messageId))
            MessageTraceStore.trackOutgoing(messageId, peerId, currentConnectionType, message.size, fallback)
            MessageTraceStore.recordEvent(messageId, MessageTraceStore.EventType.TX_SENT, "Sent (requires_ack=false; non-UTF8)")
            sendMessage(peerId, message)
            return
        }
    }
    
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
            Log.d(
                TAG,
                "  - Peer: ${peer.id}, IP: ${peer.ip}, Port: ${peer.port}, Connected: ${peer.connected}, NetworkID: ${peer.networkId}"
            )
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
        val messageId = MessageTraceStore.generateMessageId()
        try {
            val messageContent = String(messageBytes, Charsets.UTF_8)
            Log.d(TAG, "Message received from peer $peerId: $messageContent")
            // Post the message to observers (UI will listen to this)
            val receivedMsg = ReceivedMessage(peerId = peerId, message = messageContent)
            _receivedMessages.postValue(receivedMsg)

            val preview = messageContent.take(200)
            addMessageEvent(MessageEvent(MessageDirection.IN, peerId, preview, messageId = messageId))
            MessageTraceStore.trackIncoming(messageId, peerId, currentConnectionType, messageBytes.size, preview)
        } catch (e: Exception) {
            Log.e(TAG, "Error processing received message: ${e.message}", e)
            addMessageEvent(MessageEvent(MessageDirection.IN, peerId, "<decode error>", messageId = messageId))
            MessageTraceStore.trackIncoming(messageId, peerId, currentConnectionType, messageBytes.size, "<decode error>")
            MessageTraceStore.recordEvent(messageId, MessageTraceStore.EventType.ERROR, "Decode error: ${e.message}")
        }
    }

    private fun addMessageEvent(event: MessageEvent) {
        synchronized(messageHistory) {
            if (messageHistory.size >= MAX_MESSAGE_EVENTS) {
                messageHistory.removeLast()
            }
            messageHistory.addFirst(event)
            _messageEvents.postValue(messageHistory.toList())
        }
    }
}
