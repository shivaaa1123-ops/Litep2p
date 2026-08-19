package com.zeengal.litep2p.hook

import android.util.Log
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.zeengal.litep2p.MessageTraceStore
import com.zeengal.litep2p.core.CommsMode
import com.zeengal.litep2p.core.EngineResult
import com.zeengal.litep2p.core.FileTransferPriority
import com.zeengal.litep2p.core.LiteP2P
import com.zeengal.litep2p.core.LogLevel
import com.zeengal.litep2p.core.PeerInfo
import org.json.JSONObject

/**
 * Harness-side P2P facade (Phase 2 module split).
 *
 * After the split, the native engine is driven exclusively through the core
 * [LiteP2P] API (`:litep2p-core`). This object no longer declares JNI `external`
 * functions; it delegates engine calls to [LiteP2P] and keeps the harness-only
 * concerns that used to live here:
 *
 *  - LiveData streams the UI observes (peers, received messages, message events)
 *  - the ACK-envelope protocol ([sendMessageTracked]) used to measure delivery
 *  - the in-memory message history for the Messages tab
 *
 * Engine events (peers/messages) arrive via [EngineBridge], which forwards the
 * core [LiteP2P] listener callbacks into [onPeersUpdated] / [onMessageReceived].
 */
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

    /** Initiates a connection to a discovered peer (delegates to the core engine). */
    @JvmStatic
    fun connect(peerId: String) {
        LiteP2P.connect(peerId)
    }

    /** Fire-and-forget send (delegates to the core engine); returns the engine result. */
    @JvmStatic
    fun sendMessage(peerId: String, message: ByteArray): EngineResult {
        return LiteP2P.send(peerId, message)
    }

    // ------------------------------------------------------------------
    // File transfer (offer/accept model, see LiteP2P §file transfer)
    // ------------------------------------------------------------------

    /** Offers [filePath] to a connected peer. Returns the transfer id or null. */
    @JvmStatic
    fun sendFile(peerId: String, filePath: String, priority: FileTransferPriority = FileTransferPriority.NORMAL): String? {
        return LiteP2P.sendFile(peerId, filePath, priority)
    }

    /** Receiver accepts an incoming offer; the engine writes the file to [savePath]. */
    @JvmStatic
    fun acceptTransfer(transferId: String, savePath: String): EngineResult =
        LiteP2P.acceptFileTransfer(transferId, savePath)

    /** Receiver declines an incoming offer. */
    @JvmStatic
    fun declineTransfer(transferId: String): EngineResult =
        LiteP2P.declineFileTransfer(transferId)

    /** Cancels an active transfer (sender or receiver side). */
    @JvmStatic
    fun cancelTransfer(transferId: String): EngineResult =
        LiteP2P.cancelTransfer(transferId)

    /**
     * UI should call this instead of [sendMessage] so we can show outgoing messages
     * in the Messages tab.
     *
     * Returns the underlying engine result so burst senders can honor backpressure:
     * when the engine's send queue is at capacity this returns
     * [EngineResult.QUEUE_FULL] instead of silently dropping the message.
     */
    @JvmStatic
    fun sendMessageTracked(peerId: String, message: ByteArray): EngineResult {
        val messageId = MessageTraceStore.generateMessageId()
        val preview: String
        return try {
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
        } catch (_: Throwable) {
            val fallback = "<binary ${message.size} bytes>"
            addMessageEvent(MessageEvent(MessageDirection.OUT, peerId, fallback, messageId = messageId))
            MessageTraceStore.trackOutgoing(messageId, peerId, currentConnectionType, message.size, fallback)
            MessageTraceStore.recordEvent(messageId, MessageTraceStore.EventType.TX_SENT, "Sent (requires_ack=false; non-UTF8)")
            sendMessage(peerId, message)
        }
    }

    @JvmStatic
    fun setLogLevel(level: Int) {
        LiteP2P.setLogLevel(LogLevel.fromLevel(level))
    }

    /**
     * Sends [times] copies of [message] to [peerId] from a background thread,
     * pacing against the engine's send-queue headroom and backing off on
     * [EngineResult.QUEUE_FULL].
     *
     * This is the same paced-burst path the harness GUI "repeat" control uses.
     * It also gives adb/automation a dense-burst stress hook without tying up
     * the UI thread or overrunning the engine's single-threaded event loop.
     */
    @JvmStatic
    fun sendBurst(peerId: String, message: ByteArray, times: Int) {
        if (times <= 0) return
        val pacingLimit = 600 // headroom under the default 1000 in-flight cap
        Thread {
            var backoffMs = 5L
            var sent = 0
            var failed = 0
            repeat(times) {
                // Wait while the engine is backed up so we never overrun the queue.
                var spins = 0
                while (LiteP2P.pendingSendCount() >= pacingLimit && spins < 50_000) {
                    Thread.sleep(backoffMs)
                    spins++
                }
                var rc = sendMessageTracked(peerId, message)
                if (rc == EngineResult.QUEUE_FULL) {
                    backoffMs = (backoffMs * 2).coerceAtMost(250L)
                    Thread.sleep(backoffMs)
                    rc = sendMessageTracked(peerId, message)
                }
                if (rc == EngineResult.OK) sent++ else failed++
            }
            Log.i(TAG, "Burst done: $sent sent, $failed failed for peer $peerId (times=$times)")
        }.start()
    }

    // System network state callbacks (drives signaling/NAT recovery in native engine)
    @JvmStatic
    fun setSystemNetworkInfo(isWiFi: Boolean, isNetworkAvailable: Boolean) {
        LiteP2P.setNetworkInfo(isWiFi, isNetworkAvailable)
    }

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

    /** Maps a UI comms-mode label to the core [CommsMode] used at engine start. */
    @JvmStatic
    fun toCommsMode(selectedMode: String): CommsMode = CommsMode.fromWire(selectedMode)

    @JvmStatic
    fun onPeersUpdated(peers: Array<PeerInfo>) {
        // Log what we received from the engine
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

    /**
     * Clears the message event list and the associated traces (UI "clear" action).
     * In-flight messages are unaffected; only the recorded history is dropped.
     */
    @JvmStatic
    fun clearMessageEvents() {
        synchronized(messageHistory) {
            messageHistory.clear()
            _messageEvents.postValue(emptyList())
        }
        MessageTraceStore.clear()
    }
}