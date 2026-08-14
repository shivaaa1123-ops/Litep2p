package com.zeengal.litep2p

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Stores message trace events for debugging.
 * Each message is assigned a unique ID and its lifecycle events are recorded here.
 */
object MessageTraceStore {

    /** Represents a single event in a message's lifecycle. */
    data class TraceEvent(
        val timestampMs: Long,
        val eventType: EventType,
        val detail: String = ""
    )

    enum class EventType {
        TX_QUEUED,      // Message queued for sending
        TX_SENT,        // Message sent over network
        TX_ACK,         // Acknowledgement received
        TX_TIMEOUT,     // Timeout waiting for ACK
        TX_RETRY,       // Retrying send
        TX_FAILED,      // Send permanently failed
        RX_RECEIVED,    // Message received from peer
        RX_DECRYPTED,   // Decryption succeeded
        RX_DECRYPT_FAIL,// Decryption failed
        ROUTED,         // Proxied/relayed through another peer
        HANDSHAKE,      // Noise handshake event
        ERROR           // Generic error
    }

    enum class MessageStatus {
        PENDING,
        DELIVERED,
        FAILED,
        RECEIVED
    }

    /** Full trace info for a single message. */
    data class MessageTrace(
        val messageId: String,
        val direction: Direction,
        val peerId: String,
        val protocol: String,          // "UDP", "TCP", "QUIC"
        val sizeBytes: Int,
        val preview: String,
        val createdAtMs: Long,
        val events: MutableList<TraceEvent> = mutableListOf(),
        var status: MessageStatus = MessageStatus.PENDING,
        var latencyMs: Long? = null,
        var retryCount: Int = 0,
        var errorMessage: String? = null
    ) {
        fun addEvent(type: EventType, detail: String = "") {
            events.add(TraceEvent(System.currentTimeMillis(), type, detail))
        }
    }

    enum class Direction { OUT, IN }

    private const val MAX_TRACES = 500
    private val traces = ConcurrentHashMap<String, MessageTrace>()
    private val traceOrder = ArrayDeque<String>()
    private val lock = Any()

    // LiveData to notify UI of trace updates
    private val _traceUpdates = MutableLiveData<String>()
    val traceUpdates: LiveData<String> = _traceUpdates

    /**
     * Generate a new unique message ID.
     */
    fun generateMessageId(): String = UUID.randomUUID().toString().take(12)

    /**
     * Start tracking an outgoing message.
     */
    @JvmStatic
    fun trackOutgoing(
        messageId: String,
        peerId: String,
        protocol: String,
        sizeBytes: Int,
        preview: String
    ): MessageTrace {
        val trace = MessageTrace(
            messageId = messageId,
            direction = Direction.OUT,
            peerId = peerId,
            protocol = protocol,
            sizeBytes = sizeBytes,
            preview = preview.take(200),
            createdAtMs = System.currentTimeMillis()
        )
        trace.addEvent(EventType.TX_QUEUED, "Queued for sending via $protocol")
        addTrace(trace)
        return trace
    }

    /**
     * Start tracking an incoming message.
     */
    @JvmStatic
    fun trackIncoming(
        messageId: String,
        peerId: String,
        protocol: String,
        sizeBytes: Int,
        preview: String
    ): MessageTrace {
        val trace = MessageTrace(
            messageId = messageId,
            direction = Direction.IN,
            peerId = peerId,
            protocol = protocol,
            sizeBytes = sizeBytes,
            preview = preview.take(200),
            createdAtMs = System.currentTimeMillis(),
            status = MessageStatus.RECEIVED
        )
        trace.addEvent(EventType.RX_RECEIVED, "Received from $peerId via $protocol")
        addTrace(trace)
        return trace
    }

    /**
     * Record a lifecycle event for an existing message.
     */
    @JvmStatic
    fun recordEvent(messageId: String, eventType: EventType, detail: String = "") {
        val trace = traces[messageId] ?: return
        trace.addEvent(eventType, detail)

        // Update status based on event
        when (eventType) {
            EventType.TX_SENT -> { /* still pending */ }
            EventType.TX_ACK -> {
                trace.status = MessageStatus.DELIVERED
                trace.latencyMs = System.currentTimeMillis() - trace.createdAtMs
            }
            EventType.TX_TIMEOUT -> { /* still pending, may retry */ }
            EventType.TX_RETRY -> trace.retryCount++
            EventType.TX_FAILED -> {
                trace.status = MessageStatus.FAILED
                trace.errorMessage = detail.ifEmpty { "Send failed after retries" }
            }
            EventType.RX_DECRYPTED -> { /* successful receive */ }
            EventType.RX_DECRYPT_FAIL -> {
                trace.errorMessage = detail.ifEmpty { "Decryption failed" }
            }
            EventType.ERROR -> {
                trace.errorMessage = detail
            }
            else -> { /* no status change */ }
        }

        _traceUpdates.postValue(messageId)
    }

    /**
     * Mark a message as delivered (ACK received).
     */
    @JvmStatic
    fun markDelivered(messageId: String, latencyMs: Long) {
        val trace = traces[messageId] ?: return
        trace.status = MessageStatus.DELIVERED
        trace.latencyMs = latencyMs
        trace.addEvent(EventType.TX_ACK, "ACK received, latency=${latencyMs}ms")
        _traceUpdates.postValue(messageId)
    }

    /**
     * Called from native (JNI) when an application-level ACK is received.
     *
     * @param messageId The original message id
     * @param sentTsMs Sender-provided send timestamp (epoch ms), if present (else 0)
     * @param recvTsMs Receiver-provided receive timestamp (epoch ms), if present (else 0)
     */
    @JvmStatic
    fun onAckReceived(messageId: String, sentTsMs: Long, recvTsMs: Long) {
        val trace = traces[messageId] ?: return
        val now = System.currentTimeMillis()
        val latency = now - trace.createdAtMs

        trace.status = MessageStatus.DELIVERED
        trace.latencyMs = latency

        val extra = buildString {
            append("ACK received")
            append(", local_rtt=${latency}ms")
            if (sentTsMs > 0) append(", sent_ts_ms=$sentTsMs")
            if (recvTsMs > 0) append(", recv_ts_ms=$recvTsMs")
        }
        trace.addEvent(EventType.TX_ACK, extra)
        _traceUpdates.postValue(messageId)
    }

    /**
     * Mark a message as failed.
     */
    @JvmStatic
    fun markFailed(messageId: String, reason: String) {
        val trace = traces[messageId] ?: return
        trace.status = MessageStatus.FAILED
        trace.errorMessage = reason
        trace.addEvent(EventType.TX_FAILED, reason)
        _traceUpdates.postValue(messageId)
    }

    /**
     * Get a trace by message ID.
     */
    fun getTrace(messageId: String): MessageTrace? = traces[messageId]

    /**
     * Get all traces (most recent first).
     */
    fun getAllTraces(): List<MessageTrace> {
        synchronized(lock) {
            return traceOrder.mapNotNull { traces[it] }
        }
    }

    /**
     * Find trace for a message by approximate match (peer + timestamp + direction).
     */
    fun findTrace(peerId: String, timestampMs: Long, direction: Direction): MessageTrace? {
        val tolerance = 1000L // 1 second tolerance
        return traces.values.find { trace ->
            trace.peerId == peerId &&
            trace.direction == direction &&
            kotlin.math.abs(trace.createdAtMs - timestampMs) < tolerance
        }
    }

    private fun addTrace(trace: MessageTrace) {
        synchronized(lock) {
            traces[trace.messageId] = trace
            traceOrder.addFirst(trace.messageId)

            // Prune old traces
            while (traceOrder.size > MAX_TRACES) {
                val oldId = traceOrder.removeLast()
                traces.remove(oldId)
            }
        }
        _traceUpdates.postValue(trace.messageId)
    }

    /**
     * Clear all traces (for testing/reset).
     */
    fun clear() {
        synchronized(lock) {
            traces.clear()
            traceOrder.clear()
        }
    }
}
