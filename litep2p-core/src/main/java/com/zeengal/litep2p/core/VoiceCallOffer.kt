package com.zeengal.litep2p.core

/**
 * An incoming voice-call offer, reported via
 * [LiteP2PListener.onVoiceCallOffered].
 *
 * The offer/accept model mirrors file transfer: nothing is played back or
 * recorded until the callee explicitly calls [LiteP2P.acceptVoiceCall] (or
 * [LiteP2P.declineVoiceCall] to refuse).
 *
 * @property codec opaque codec name — the engine does not interpret it. The
 *   Android app uses "PCM_S16LE" (16 kHz mono, 16-bit signed little-endian).
 */
data class VoiceCallOffer(
    /** Stable id identifying the call on both caller and callee. */
    val callId: String,
    /** Peer id of the caller. */
    val peerId: String,
    /** Codec name advertised by the caller (opaque to the engine). */
    val codec: String,
    /** Sample rate in Hz (e.g. 16000). */
    val sampleRate: Int,
    /** Channel count (1 = mono, 2 = stereo). */
    val channels: Int,
    /** Audio frame period in milliseconds (e.g. 20). */
    val frameMs: Int
)
