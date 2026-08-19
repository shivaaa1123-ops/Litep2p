package com.zeengal.litep2p

import android.util.Log
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.zeengal.litep2p.core.EngineResult
import com.zeengal.litep2p.core.LiteP2P
import com.zeengal.litep2p.core.VoiceCallOffer
import com.zeengal.litep2p.core.VoiceCallState

/**
 * App-side state for the engine's voice-call module (offer/accept model).
 *
 * The native engine delivers offer/state events on engine threads via
 * [EngineBridge]; this store keeps that state as thread-safe LiveData the UI
 * (incoming-call dialog + active-call view) can observe. Audio frames are
 * routed straight to [VoiceCallEngine] for playback — they are realtime data,
 * not UI state.
 */
object VoiceCallStore {

    const val CODEC = "PCM_S16LE"
    const val SAMPLE_RATE = 16000
    const val CHANNELS = 1        // mono
    const val FRAME_MS = 20

    data class ActiveCall(
        val callId: String,
        val peerId: String,
        val state: VoiceCallState,
        val detail: String?,
        val startedAtMs: Long
    )

    private const val TAG = "VoiceCallStore"

    /** The live call, or null when idle. Drives the active-call overlay. */
    private val _activeCall = MutableLiveData<ActiveCall?>(null)
    val activeCall: LiveData<ActiveCall?> get() = _activeCall

    /** One-shot trigger for the incoming-call dialog (null once consumed). */
    private val _incomingSignal = MutableLiveData<VoiceCallOffer?>(null)
    val incomingSignal: LiveData<VoiceCallOffer?> get() = _incomingSignal

    /** One-shot toast queue (null once consumed). */
    private val _toastSignal = MutableLiveData<String?>(null)
    val toastSignal: LiveData<String?> get() = _toastSignal

    /** When set, the next inbound call offer is accepted automatically (harness). */
    @Volatile
    var autoAcceptNext: Boolean = false

    // ---------------- EngineBridge entry points (engine threads) ----------------

    /** Inbound offer from [VoiceCallOffer]. Nothing is captured until accepted. */
    fun onOffer(offer: VoiceCallOffer) {
        _incomingSignal.postValue(offer)
        Log.i(TAG, "Incoming call offer ${offer.callId} from ${offer.peerId} " +
            "codec=${offer.codec} ${offer.sampleRate}Hz/${offer.channels}ch/${offer.frameMs}ms")

        // Harness mode: accept immediately without UI.
        if (autoAcceptNext) {
            autoAcceptNext = false
            val rc = acceptOffer(offer)
            Log.i(TAG, "auto-accepted call ${offer.callId} -> $rc")
        }
    }

    /** Call state change from the engine (both sides). */
    fun onStateChanged(callId: String, peerId: String, state: VoiceCallState, detail: String?) {
        when (state) {
            VoiceCallState.OUTGOING -> {
                _activeCall.postValue(ActiveCall(callId, peerId, state, detail, System.currentTimeMillis()))
            }
            VoiceCallState.RINGING -> {
                // The incoming-call dialog drives this side; keep state for the overlay.
                _activeCall.postValue(ActiveCall(callId, peerId, state, detail, System.currentTimeMillis()))
            }
            VoiceCallState.IN_CALL -> {
                val cur = _activeCall.value
                val started = cur?.startedAtMs ?: System.currentTimeMillis()
                _activeCall.postValue(ActiveCall(callId, peerId, state, detail, started))
            }
            VoiceCallState.ENDED -> {
                val cur = _activeCall.value
                if (cur?.callId == callId) {
                    _activeCall.postValue(null)
                    VoiceCallEngine.stop()
                    _toastSignal.postValue("Call with ${shortId(peerId)} ${detail ?: "ended"}")
                }
            }
            VoiceCallState.IDLE -> { /* no-op */ }
        }
        Log.i(TAG, "Call $callId state=$state detail=${detail ?: ""}")
    }


    // ---------------- UI actions ----------------

    /** Callee accepts an offer: engine connects and [VoiceCallEngine] starts. */
    fun acceptOffer(offer: VoiceCallOffer): EngineResult {
        val rc = LiteP2P.acceptVoiceCall(offer.callId)
        if (rc == EngineResult.OK) {
            VoiceCallEngine.startCall(offer.callId)
            val cur = _activeCall.value
            _activeCall.postValue(
                ActiveCall(offer.callId, offer.peerId, VoiceCallState.IN_CALL, "connected",
                    cur?.startedAtMs ?: System.currentTimeMillis())
            )
        } else {
            Log.w(TAG, "acceptVoiceCall(${offer.callId}) -> $rc")
        }
        return rc
    }

    /** Callee declines an incoming offer. */
    fun declineOffer(offer: VoiceCallOffer): EngineResult {
        val rc = LiteP2P.declineVoiceCall(offer.callId)
        if (rc == EngineResult.OK) {
            _toastSignal.postValue("Declined call from ${shortId(offer.peerId)}")
        }
        return rc
    }

    /** Caller initiates a call: offer + local capture state. */
    fun startCall(peerId: String): String? {
        val callId = LiteP2P.startVoiceCall(
            peerId, CODEC, SAMPLE_RATE, CHANNELS, FRAME_MS
        ) ?: run {
            Log.w(TAG, "startVoiceCall refused for $peerId")
            return null
        }
        // Capture starts immediately; frames are only transmitted once IN_CALL.
        VoiceCallEngine.startCall(callId)
        return callId
    }

    /** Either side hangs up. */
    fun endActiveCall(): EngineResult {
        val cur = _activeCall.value ?: return EngineResult.INVALID_STATE
        val rc = LiteP2P.endVoiceCall(cur.callId)
        if (rc == EngineResult.OK) {
            VoiceCallEngine.stop()
            _activeCall.postValue(null)
        }
        return rc
    }

    /** Toggles local microphone capture. */
    fun setMuted(muted: Boolean) = VoiceCallEngine.setMuted(muted)

    /** Marks the incoming-call dialog as handled (rotation must not re-prompt). */
    fun consumeIncomingSignal() {
        _incomingSignal.postValue(null)
    }

    /** Clears the pending toast so rotation does not re-show it. */
    fun consumeToastSignal() {
        _toastSignal.postValue(null)
    }

    private fun shortId(id: String) = if (id.length > 12) id.take(12) + "…" else id
}

    var autoAcceptNext: Boolean = false
