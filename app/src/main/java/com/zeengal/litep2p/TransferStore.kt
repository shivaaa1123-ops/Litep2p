package com.zeengal.litep2p

import android.content.Context
import android.util.Log
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.zeengal.litep2p.core.EngineResult
import com.zeengal.litep2p.core.FileTransferOffer
import com.zeengal.litep2p.core.LiteP2P
import java.io.File

/**
 * App-side state for the engine's file-transfer module (offer/accept model).
 *
 * The native engine delivers offer/progress/completion events on engine threads
 * via [EngineBridge]; this store keeps that state as thread-safe LiveData the UI
 * (Files tab + incoming-offer dialog) can observe. It performs no wire-format
 * work — it is pure bookkeeping standardised on [LiteP2P]'s file-transfer API
 * (sendFile / acceptFileTransfer / declineFileTransfer / cancelTransfer).
 */
object TransferStore {

    enum class TransferDirection { IN, OUT }

    enum class TransferStatus { OFFERED, RUNNING, COMPLETED, FAILED, DECLINED, CANCELLED }

    data class TransferEvent(
        val transferId: String,
        val direction: TransferDirection,
        val peerId: String,
        val fileName: String,
        val sizeBytes: Long,
        val status: TransferStatus,
        val progressPercent: Float = 0f,
        val bytesPerSec: Float = 0f,
        val error: String? = null,
        val savePath: String? = null,
        val timestampMs: Long = System.currentTimeMillis()
    )

    private const val TAG = "TransferStore"

    @Volatile
    private var appContext: Context? = null

    private val lock = Any()
    private val events = mutableListOf<TransferEvent>() // newest-first

    private val _transferEvents = MutableLiveData<List<TransferEvent>>(emptyList())
    val transferEvents: LiveData<List<TransferEvent>> get() = _transferEvents

    /** How many inbound offers are still awaiting an accept/decline decision. */
    private val _pendingOfferCount = MutableLiveData(0)
    val pendingOfferCount: LiveData<Int> get() = _pendingOfferCount

    /** One-shot trigger for the incoming-offer dialog (null once consumed). */
    private val _offerSignal = MutableLiveData<TransferEvent?>(null)
    val offerSignal: LiveData<TransferEvent?> get() = _offerSignal

    /** One-shot toast queue for completion highlights (null once consumed). */
    private val _toastSignal = MutableLiveData<String?>(null)
    val toastSignal: LiveData<String?> get() = _toastSignal

    /** When set, the next inbound offer is accepted automatically (harness/automation). */
    @Volatile
    var autoAcceptNext: Boolean = false

    fun attach(context: Context) {
        appContext = context.applicationContext
    }

    /** Directory received files are accepted into. Created on demand. */
    fun receivedDir(): File {
        val dir = File(appContext?.filesDir ?: File("."), "p2p_received")
        if (!dir.exists()) dir.mkdirs()
        return dir
    }
// ---------------- EngineBridge entry points (engine threads) ----------------

    /** Inbound offer from [FileTransferOffer]. Nothing is written until accepted. */
    fun onOfferReceived(offer: FileTransferOffer) {
        val ev = TransferEvent(
            transferId = offer.transferId,
            direction = TransferDirection.IN,
            peerId = offer.peerId,
            fileName = safeFileName(offer.fileName),
            sizeBytes = offer.sizeBytes,
            status = TransferStatus.OFFERED
        )
        synchronized(lock) {
            events.add(0, ev)
            publishLocked()
        }
        _offerSignal.postValue(ev)
        Log.i(TAG, "Incoming offer ${offer.transferId}: ${ev.fileName} (${ev.sizeBytes} B) from ${ev.peerId}")

        // Harness mode: accept immediately without UI (LITEP2P_AUTO_ACCEPT).
        if (autoAcceptNext) {
            autoAcceptNext = false
            val rc = acceptOffer(ev)
            Log.i(TAG, "auto-accepted ${offer.transferId} -> $rc")
        }
    }

    /** Records an outgoing transfer once [LiteP2P.sendFile] accepted it. */
    fun trackOutgoing(transferId: String, peerId: String, filePath: String) {
        val file = File(filePath)
        val ev = TransferEvent(
            transferId = transferId,
            direction = TransferDirection.OUT,
            peerId = peerId,
            fileName = file.name,
            sizeBytes = file.length(),
            status = TransferStatus.RUNNING
        )
        synchronized(lock) {
            events.add(0, ev)
            publishLocked()
        }
        Log.i(TAG, "Outgoing transfer $transferId: ${file.name} (${file.length()} B) to $peerId")
    }

    /** Progress update for a transfer (sender or receiver side). */
    fun onProgress(transferId: String, progressPercent: Float, bytesPerSec: Float) {
        synchronized(lock) {
            val idx = events.indexOfFirst { it.transferId == transferId }
            if (idx < 0) return
            val old = events[idx]
            val status =
                if (old.status == TransferStatus.OFFERED) TransferStatus.RUNNING else old.status
            events[idx] = old.copy(
                status = status,
                progressPercent = progressPercent,
                bytesPerSec = bytesPerSec
            )
            publishLocked()
        }
    }

    /** Transfer finished (success / failed / declined / cancelled). */
    fun onCompleted(transferId: String, success: Boolean, error: String?) {
        val ev = synchronized(lock) {
            val idx = events.indexOfFirst { it.transferId == transferId }
            if (idx < 0) return
            val old = events[idx]
            val status = when {
                success -> TransferStatus.COMPLETED
                error != null && error.contains("declin", ignoreCase = true) -> TransferStatus.DECLINED
                error != null && error.contains("canc", ignoreCase = true) -> TransferStatus.CANCELLED
                else -> TransferStatus.FAILED
            }
            events[idx] = old.copy(status = status, error = error?.take(160))
            publishLocked()
            events[idx]
        }
        Log.i(TAG, "Transfer $transferId completed success=$success error=$error")
        if (success && ev.direction == TransferDirection.IN) {
            _toastSignal.postValue("Received ${ev.fileName} from ${ev.peerId}")
        } else if (!success && ev.direction == TransferDirection.OUT) {
            val why = when (ev.status) {
                TransferStatus.DECLINED -> "declined by the peer"
                TransferStatus.CANCELLED -> "cancelled"
                else -> "failed (${error ?: "unknown error"})"
            }
            _toastSignal.postValue("Send ${ev.fileName} $why")
        }
    }
// ---------------- UI actions ----------------

    /** Receiver accepts an offer: the engine writes to [receivedDir]/<name>. */
    fun acceptOffer(event: TransferEvent): EngineResult {
        val savePath = File(receivedDir(), event.fileName).absolutePath
        val rc = LiteP2P.acceptFileTransfer(event.transferId, savePath)
        if (rc == EngineResult.OK) {
            synchronized(lock) {
                val idx = events.indexOfFirst { it.transferId == event.transferId }
                if (idx >= 0) {
                    events[idx] = events[idx].copy(status = TransferStatus.RUNNING, savePath = savePath)
                    publishLocked()
                }
            }
        } else {
            Log.w(TAG, "acceptFileTransfer(${event.transferId}) -> $rc")
        }
        return rc
    }

    /** Receiver declines an incoming offer. */
    fun declineOffer(event: TransferEvent): EngineResult {
        val rc = LiteP2P.declineFileTransfer(event.transferId)
        if (rc == EngineResult.OK) {
            synchronized(lock) {
                val idx = events.indexOfFirst { it.transferId == event.transferId }
                if (idx >= 0) {
                    events[idx] = events[idx].copy(status = TransferStatus.DECLINED)
                    publishLocked()
                }
            }
        }
        return rc
    }

    /** Cancels an active transfer (sender or receiver side). */
    fun cancelTransfer(event: TransferEvent): EngineResult = LiteP2P.cancelTransfer(event.transferId)

    fun clear() {
        synchronized(lock) {
            events.clear()
            publishLocked()
        }
    }

    /** Marks the newest-offer dialog as handled (rotation must not re-prompt). */
    fun consumeOfferSignal() {
        _offerSignal.postValue(null)
    }

    /** Clears the pending toast so rotation does not re-show it. */
    fun consumeToastSignal() {
        _toastSignal.postValue(null)
    }

    // ---------------- internals ----------------

    private fun publishLocked() {
        _transferEvents.postValue(events.toList())
        _pendingOfferCount.postValue(
            events.count {
                it.status == TransferStatus.OFFERED &&
                    it.direction == TransferDirection.IN
            }
        )
    }

    private fun safeFileName(raw: String): String {
        var name = raw.replace('\\', '/').substringAfterLast('/').trim()
        if (name.isEmpty() || name == "." || name == "..") name = "file.bin"
        // Strip control characters that could break the filesystem layer.
        name = name.replace(Regex("[\\x00-\\x1f]"), "_")
        return name
    }
}