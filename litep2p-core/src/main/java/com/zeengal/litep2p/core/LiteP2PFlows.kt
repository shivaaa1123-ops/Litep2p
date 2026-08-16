package com.zeengal.litep2p.core

import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/** A chat message received from a peer. [data] is a snapshot copy valid for the lifetime of the event. */
data class LiteP2PMessage(val peerId: String, val data: ByteArray)

/** Delivery confirmation for a message sent with the LP_APP envelope protocol (api-spec.md §6.2). */
data class LiteP2PMessageAck(val messageId: String, val sentTsMs: Long, val recvTsMs: Long)

/** Reliable-send completion for an overlay message sent with `wantAck = true`. */
data class LiteP2POverlayDelivery(val frameId: String, val delivered: Boolean)

/** A structured engine log line. */
data class LiteP2PLogLine(val level: LogLevel, val line: String)

/**
 * File-transfer events surfaced on [LiteP2P.transfersFlow].
 */
sealed interface LiteP2PTransferEvent {
    /** An incoming offer; accept with [LiteP2P.acceptFileTransfer]. */
    data class Offered(val offer: FileTransferOffer) : LiteP2PTransferEvent

    /** Progress update; [progressPercent] is 0..100, [bytesPerSec] the current throughput. */
    data class Progress(val transferId: String, val progressPercent: Float, val bytesPerSec: Float) : LiteP2PTransferEvent

    /** Terminal state of a transfer. */
    data class Completed(val transferId: String, val success: Boolean, val error: String?) : LiteP2PTransferEvent
}

/**
 * Internal hot event hub bridging [LiteP2P]'s listener callbacks onto reactive
 * streams. It is started lazily on first access (see the [LiteP2P.peersFlow]
 * family) and subscribes a single [LiteP2PListener].
 *
 * Hot-stream semantics: with no active collectors the flows buffer a bounded
 * number of the most recent events and drop the oldest under pressure
 * ([LiteP2P.peersFlow] and [LiteP2P.telemetryFlow] additionally replay their
 * latest value to new collectors). Subscribe **before** starting the engine to
 * avoid missing early events.
 */
internal object LiteP2PFlowHub {

    private val started = AtomicBoolean(false)

    private val _peers = MutableSharedFlow<List<PeerInfo>>(
        replay = 1,
        extraBufferCapacity = 8,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )
    val peers: SharedFlow<List<PeerInfo>> = _peers.asSharedFlow()

    private val _messages = MutableSharedFlow<LiteP2PMessage>(
        replay = 0,
        extraBufferCapacity = 64,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )
    val messages: SharedFlow<LiteP2PMessage> = _messages.asSharedFlow()

    private val _messageAcks = MutableSharedFlow<LiteP2PMessageAck>(
        replay = 0,
        extraBufferCapacity = 32,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )
    val messageAcks: SharedFlow<LiteP2PMessageAck> = _messageAcks.asSharedFlow()

    private val _overlayDeliveries = MutableSharedFlow<LiteP2POverlayDelivery>(
        replay = 0,
        extraBufferCapacity = 32,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )
    val overlayDeliveries: SharedFlow<LiteP2POverlayDelivery> = _overlayDeliveries.asSharedFlow()

    private val _telemetry = MutableSharedFlow<String>(
        replay = 1,
        extraBufferCapacity = 4,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )
    val telemetry: SharedFlow<String> = _telemetry.asSharedFlow()

    private val _logs = MutableSharedFlow<LiteP2PLogLine>(
        replay = 0,
        extraBufferCapacity = 256,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )
    val logs: SharedFlow<LiteP2PLogLine> = _logs.asSharedFlow()

    private val _transfers = MutableSharedFlow<LiteP2PTransferEvent>(
        replay = 0,
        extraBufferCapacity = 64,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )
    val transfers: SharedFlow<LiteP2PTransferEvent> = _transfers.asSharedFlow()

    private val listener = object : LiteP2PListener {
        override fun onPeersChanged(peers: List<PeerInfo>) {
            _peers.tryEmit(peers)
        }

        override fun onMessageReceived(peerId: String, data: ByteArray) {
            // Defensive copy: the listener contract only guarantees the buffer
            // is valid for the duration of the call.
            _messages.tryEmit(LiteP2PMessage(peerId, data.copyOf()))
        }

        override fun onLog(level: LogLevel, line: String) {
            _logs.tryEmit(LiteP2PLogLine(level, line))
        }

        override fun onTelemetry(json: String) {
            _telemetry.tryEmit(json)
        }

        override fun onMessageAcked(messageId: String, sentTsMs: Long, recvTsMs: Long) {
            _messageAcks.tryEmit(LiteP2PMessageAck(messageId, sentTsMs, recvTsMs))
        }

        override fun onOverlayDelivery(frameId: String, delivered: Boolean) {
            _overlayDeliveries.tryEmit(LiteP2POverlayDelivery(frameId, delivered))
        }

        override fun onFileTransferOffered(offer: FileTransferOffer) {
            _transfers.tryEmit(LiteP2PTransferEvent.Offered(offer))
        }

        override fun onTransferProgress(transferId: String, progressPercent: Float, bytesPerSec: Float) {
            _transfers.tryEmit(LiteP2PTransferEvent.Progress(transferId, progressPercent, bytesPerSec))
        }

        override fun onTransferCompleted(transferId: String, success: Boolean, error: String?) {
            _transfers.tryEmit(LiteP2PTransferEvent.Completed(transferId, success, error))
        }
    }

    /** Registers the hub listener exactly once. Safe to call from any thread. */
    fun ensureStarted() {
        if (started.compareAndSet(false, true)) {
            LiteP2P.addListener(listener)
        }
    }
}

/* ------------------------------------------------------------------ */
/* Reactive API — Flow extensions on LiteP2P                           */
/* ------------------------------------------------------------------ */

/** Hot stream of full peer snapshots (each emission replaces the previous list). */
val LiteP2P.peersFlow: Flow<List<PeerInfo>>
    get() {
        LiteP2PFlowHub.ensureStarted()
        return LiteP2PFlowHub.peers
    }

/** Hot stream of received messages ([LiteP2PMessage.data] is a snapshot copy). */
val LiteP2P.messagesFlow: Flow<LiteP2PMessage>
    get() {
        LiteP2PFlowHub.ensureStarted()
        return LiteP2PFlowHub.messages
    }

/** Hot stream of LP_APP delivery confirmations (see api-spec.md §6.2). */
val LiteP2P.messageAcksFlow: Flow<LiteP2PMessageAck>
    get() {
        LiteP2PFlowHub.ensureStarted()
        return LiteP2PFlowHub.messageAcks
    }

/** Hot stream of overlay reliable-send completions (`wantAck = true` sends). */
val LiteP2P.overlayDeliveriesFlow: Flow<LiteP2POverlayDelivery>
    get() {
        LiteP2PFlowHub.ensureStarted()
        return LiteP2PFlowHub.overlayDeliveries
    }

/** Hot stream of telemetry snapshots (replays the latest to new collectors). */
val LiteP2P.telemetryFlow: Flow<String>
    get() {
        LiteP2PFlowHub.ensureStarted()
        return LiteP2PFlowHub.telemetry
    }

/** Hot stream of engine log lines. */
val LiteP2P.logsFlow: Flow<LiteP2PLogLine>
    get() {
        LiteP2PFlowHub.ensureStarted()
        return LiteP2PFlowHub.logs
    }

/** Hot stream of file-transfer events ([LiteP2PTransferEvent]). */
val LiteP2P.transfersFlow: Flow<LiteP2PTransferEvent>
    get() {
        LiteP2PFlowHub.ensureStarted()
        return LiteP2PFlowHub.transfers
    }

/* ------------------------------------------------------------------ */
/* Reactive API — suspend helpers                                      */
/* ------------------------------------------------------------------ */

private const val DEFAULT_ENGINE_OP_TIMEOUT_MS = 15_000L

/**
 * Calls [LiteP2P.start] on [Dispatchers.IO] and suspends until the engine is
 * [EngineState.RUNNING].
 *
 * @param timeoutMs bound on how long to wait for startup after the request was
 *   accepted (default 15 s).
 * @return [EngineResult.OK] when the engine is running,
 *   [EngineResult.TIMEOUT] if startup did not complete in time, or the
 *   immediate [EngineResult] from [LiteP2P.start] otherwise.
 */
suspend fun LiteP2P.startAndAwait(timeoutMs: Long = DEFAULT_ENGINE_OP_TIMEOUT_MS): EngineResult {
    LiteP2PFlowHub.ensureStarted()
    val result = withContext(Dispatchers.IO) { start() }
    if (result != EngineResult.OK) return result
    if (state == EngineState.RUNNING) return EngineResult.OK
    return withTimeoutOrNull(timeoutMs) {
        stateFlow.first { it == EngineState.RUNNING }
    }?.let { EngineResult.OK } ?: EngineResult.TIMEOUT
}

/**
 * Calls [LiteP2P.stop] on [Dispatchers.IO] and suspends until the engine is
 * [EngineState.STOPPED].
 *
 * @param timeoutMs bound on how long to wait for shutdown after the request
 *   was accepted (default 15 s).
 * @return [EngineResult.OK] when the engine is stopped,
 *   [EngineResult.TIMEOUT] if shutdown did not complete in time, or the
 *   immediate [EngineResult] from [LiteP2P.stop] otherwise.
 */
suspend fun LiteP2P.stopAndAwait(timeoutMs: Long = DEFAULT_ENGINE_OP_TIMEOUT_MS): EngineResult {
    LiteP2PFlowHub.ensureStarted()
    val result = withContext(Dispatchers.IO) { stop() }
    if (result != EngineResult.OK) return result
    if (state == EngineState.STOPPED) return EngineResult.OK
    return withTimeoutOrNull(timeoutMs) {
        stateFlow.first { it == EngineState.STOPPED }
    }?.let { EngineResult.OK } ?: EngineResult.TIMEOUT
}

