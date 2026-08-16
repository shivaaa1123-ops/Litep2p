package com.zeengal.litep2p

import com.zeengal.litep2p.core.LiteP2P
import com.zeengal.litep2p.core.LiteP2PListener
import com.zeengal.litep2p.core.LogLevel
import com.zeengal.litep2p.core.PeerInfo
import com.zeengal.litep2p.hook.P2P

/**
 * Harness-side adapter between the core [LiteP2P] listener API and the app's
 * LiveData stores / [EngineController] state machine.
 *
 * After the Phase 2 module split, the native engine delivers all events through
 * [LiteP2PListener] callbacks (on engine threads). This bridge registers a single
 * listener that fans those events out to the harness-side consumers:
 *
 *  - engine start/stop completion → [EngineController] (drives UI state)
 *  - peer snapshots               → [P2P.onPeersUpdated] (LiveData for UI)
 *  - messages                     → [P2P.onMessageReceived] (LiveData + tracing)
 *  - log lines                    → [LiteP2PLogger] (Logs tab)
 *  - telemetry JSON               → [TelemetryStore] (Telemetry tab)
 *  - message ACKs                 → [MessageTraceStore] (trace dialog)
 *
 * [install] is idempotent and safe to call from any thread.
 */
object EngineBridge {

    @Volatile
    private var installed = false

    private val listener = object : LiteP2PListener {
        override fun onEngineStarted() {
            EngineController.onEngineStartComplete()
        }

        override fun onEngineStopped() {
            EngineController.onEngineStopComplete()
        }

        override fun onPeersChanged(peers: List<PeerInfo>) {
            P2P.onPeersUpdated(peers.toTypedArray())
        }

        override fun onMessageReceived(peerId: String, data: ByteArray) {
            P2P.onMessageReceived(peerId, data)
        }

        override fun onLog(level: LogLevel, line: String) {
            LiteP2PLogger.addLog(line)
        }

        override fun onTelemetry(json: String) {
            TelemetryStore.addTelemetryJson(json)
        }

        override fun onMessageAcked(messageId: String, sentTsMs: Long, recvTsMs: Long) {
            MessageTraceStore.onAckReceived(messageId, sentTsMs, recvTsMs)
        }
    }

    /**
     * Registers the bridge listener with [LiteP2P]. Must be called before the engine
     * is started so no events are missed. Idempotent.
     */
    @Synchronized
    fun install() {
        if (installed) return
        LiteP2P.addListener(listener)
        installed = true
    }
}