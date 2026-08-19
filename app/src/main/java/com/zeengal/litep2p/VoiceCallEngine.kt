package com.zeengal.litep2p

import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.MediaRecorder
import android.util.Log

/**
 * Realtime audio I/O for voice calls.
 *
 * - Capture: [AudioRecord] PCM 16-bit mono @ 16 kHz, 20 ms frames (640 B)
 *   read on a dedicated thread and handed to the engine via
 *   [com.zeengal.litep2p.core.LiteP2P.sendVoiceFrame] (fire-and-forget).
 * - Playback: [AudioTrack] in streaming mode, driven by a paced playout
 *   thread fed from a [VoiceJitterBuffer]. The jitter buffer absorbs WAN
 *   arrival jitter so higher-latency/higher-jitter links do not stutter;
 *   frames arrive on engine threads and are only enqueued there (never
 *   blocking, never doing audio I/O).
 * - The engine is codec-agnostic; the app owns all audio hardware. Muting
 *   only silences the microphone (inbound playback keeps flowing).
 */
object VoiceCallEngine {

    private const val TAG = "VoiceCallEngine"

    private const val SAMPLE_RATE = VoiceCallStore.SAMPLE_RATE
    private const val CHANNEL_IN = AudioFormat.CHANNEL_IN_MONO
    private const val CHANNEL_OUT = AudioFormat.CHANNEL_OUT_MONO
    private const val ENCODING = AudioFormat.ENCODING_PCM_16BIT
    private const val FRAME_BYTES = SAMPLE_RATE * 2 / 50  // 20 ms @ 16 kHz mono 16-bit = 640 B
    private const val FRAME_MS = 20L

    // Jitter buffer tuning: hold ~5 frames (100 ms) before playback starts to
    // smooth WAN jitter; hard cap at 12 frames (240 ms) so a burst never
    // balloons latency. Oldest frames are dropped on overflow.
    private const val JITTER_TARGET = 5
    private const val JITTER_MAX = 12

    @Volatile
    private var running = false

    @Volatile
    var muted = false
        private set

    private var recorder: AudioRecord? = null
    private var player: AudioTrack? = null
    private var captureThread: Thread? = null
    private var playoutThread: Thread? = null
    private val jitter = VoiceJitterBuffer(FRAME_BYTES, JITTER_TARGET, JITTER_MAX)

    // Adaptive pacing: adjusts the frame period from buffer-depth error so the
    // playout tracks the remote peer's audio clock (see [PlayoutPacer]).
    private val pacer = PlayoutPacer(FRAME_MS * 1_000_000L)

    @Synchronized
    fun startCall(callId: String) {
        stopInternal()
        muted = false
        running = true

        // ---- playback (jitter-buffered, paced playout) ----
        try {
            val minBuf = AudioTrack.getMinBufferSize(SAMPLE_RATE, CHANNEL_OUT, ENCODING)
            player = AudioTrack(
                AudioManager.STREAM_VOICE_CALL, SAMPLE_RATE, CHANNEL_OUT, ENCODING,
                maxOf(minBuf, FRAME_BYTES * (JITTER_MAX + 4)), AudioTrack.MODE_STREAM
            ).apply { play() }
        } catch (t: Throwable) {
            Log.w(TAG, "AudioTrack init failed: ${t.message}")
            player = null
        }
        jitter.clear()
        startPlayout()

        // ---- capture ----
        try {
            val minRec = AudioRecord.getMinBufferSize(SAMPLE_RATE, CHANNEL_IN, ENCODING)
            recorder = AudioRecord(
                MediaRecorder.AudioSource.VOICE_COMMUNICATION, SAMPLE_RATE,
                CHANNEL_IN, ENCODING, maxOf(minRec, FRAME_BYTES * 8)
            )
        } catch (t: Throwable) {
            Log.w(TAG, "AudioRecord init failed: ${t.message}")
            recorder = null
        }

        val rec = recorder
        if (rec != null && rec.state == AudioRecord.STATE_INITIALIZED) {
            rec.startRecording()
            captureThread = Thread({
                val buf = ByteArray(FRAME_BYTES)
                while (running) {
                    val n = try {
                        rec.read(buf, 0, buf.size)
                    } catch (t: Throwable) {
                        Log.w(TAG, "Capture read failed: ${t.message}")
                        break
                    }
                    if (n > 0) {
                        if (!muted) {
                            val frame = if (n == buf.size) buf else buf.copyOf(n)
                            val rc = com.zeengal.litep2p.core.LiteP2P.sendVoiceFrame(callId, frame)
                            if (rc != com.zeengal.litep2p.core.EngineResult.OK) {
                                // Call likely ended; keep looping briefly in case it reconnects.
                            }
                        }
                    }
                }
                Log.i(TAG, "Capture thread exiting")
            }, "voice-capture").also { it.start() }
        } else {
            Log.w(TAG, "Recorder unavailable (missing RECORD_AUDIO permission?)")
        }
        Log.i(TAG, "Call media started for $callId")
    }

    /**
     * Called from engine threads for each inbound frame. Only enqueues into
     * the jitter buffer — never blocks and never does audio I/O here.
     */
    fun play(data: ByteArray) {
        if (!running || data.isEmpty()) return
        runCatching { jitter.add(data) }
    }

    /**
     * Paced playout: drains the jitter buffer one frame per (adaptively paced)
     * frame period and writes to [AudioTrack]. During the fill-up phase it
     * waits up to one nominal frame period for the buffer to reach the target
     * depth; right before an underrun it plays whatever has arrived, falling
     * back to a silence frame so the audio clock never stalls.
     */
    private fun startPlayout() {
        playoutThread = Thread({
            val silence = ByteArray(FRAME_BYTES)
            val nominalPeriodNs = FRAME_MS * 1_000_000L
            var underruns = 0L
            var played = 0L
            var lastStats = System.nanoTime()
            while (running) {
                var frame = jitter.takeIfReady()
                if (frame == null) {
                    // Fill-up phase (or a network gap): give the buffer up to
                    // one nominal frame period to accumulate, then play what we
                    // have (start latency is not stretched by adaptation).
                    val deadline = System.nanoTime() + nominalPeriodNs
                    while (System.nanoTime() < deadline) {
                        Thread.sleep(4)
                        frame = jitter.takeIfReady()
                        if (frame != null) break
                    }
                }
                if (frame == null) frame = jitter.takeNow()
                if (frame == null) {
                    underruns++
                    frame = silence
                }

                // Adaptive pacing: shrink the period when the buffer is deep
                // (remote clock fast), stretch it when shallow (remote slow).
                val periodNs = pacer.periodNs(jitter.depth, JITTER_TARGET)

                val track = player
                val t0 = System.nanoTime()
                if (track != null) {
                    try {
                        track.write(frame, 0, frame.size)
                        played++
                    } catch (t: Throwable) {
                        Log.w(TAG, "Playback write failed: ${t.message}")
                    }
                }
                // Pace to the adaptive period regardless of arrival burstiness.
                val remain = periodNs - (System.nanoTime() - t0)
                if (remain > 0) {
                    try {
                        Thread.sleep(remain / 1_000_000L, (remain % 1_000_000L).toInt())
                    } catch (_: InterruptedException) {
                        break
                    }
                }

                if (System.nanoTime() - lastStats > 5_000_000_000L) {
                    lastStats = System.nanoTime()
                    Log.i(
                        TAG,
                        "Playout stats: depth=${jitter.depth} drops=${jitter.drops} " +
                            "underruns=$underruns played=$played " +
                            "periodMs=${String.format(java.util.Locale.US, "%.2f", periodNs / 1_000_000.0)}"
                    )
                }
            }
            Log.i(TAG, "Playout thread exiting")
        }, "voice-playout").also { it.start() }
    }

    fun setMuted(m: Boolean) {
        muted = m
        Log.i(TAG, "Microphone ${if (m) "muted" else "unmuted"}")
    }

    @Synchronized
    fun stop() {
        stopInternal()
    }

    @Synchronized
    fun isActive(): Boolean = running

    private fun stopInternal() {
        running = false
        captureThread?.let {
            try { it.join(500) } catch (_: InterruptedException) { }
        }
        captureThread = null
        playoutThread?.let {
            try { it.join(500) } catch (_: InterruptedException) { }
        }
        playoutThread = null
        jitter.clear()
        runCatching { recorder?.stop() }
        runCatching { recorder?.release() }
        recorder = null
        runCatching { player?.stop() }
        runCatching { player?.release() }
        player = null
    }
}
