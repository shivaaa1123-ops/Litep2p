package com.zeengal.litep2p

import java.util.ArrayDeque

/**
 * Frame-based jitter buffer for voice-call playback.
 *
 * Realtime transports deliver frames with **jitter** (arrival-time variance)
 * that is far larger on WAN paths than on a LAN. Playing each frame the moment
 * it arrives makes audio stutter whenever a datagram is late. This buffer
 * absorbs that variance:
 *
 *  - Frames accumulate until [targetDepth] is reached, then playback drains
 *    one frame per frame period (start-up latency = targetDepth × frame
 *    period, typically ~100 ms — well inside the conversational budget).
 *  - If the remote end delivers faster than playback (overflow), the *oldest*
 *    frames are dropped first — for voice, freshness beats completeness.
 *  - [takeIfReady] returns null during the fill-up phase so the playout
 *    thread can wait before starting; [takeNow] is the fallback used right
 *    before an underrun so pacing degrades to "play what has arrived" instead
 *    of inserting silence.
 *
 * Thread-safe: [add] is called from engine threads (frame arrival), while
 * [takeIfReady]/[takeNow] are called from the playout thread.
 */
class VoiceJitterBuffer(
    private val frameBytes: Int,
    val targetDepth: Int = 5,
    val maxDepth: Int = 12
) {
    private val frames = ArrayDeque<ByteArray>()

    /** True once the buffer has filled to [targetDepth] (playback may start). */
    private var started = false

    /** Frames discarded because the buffer overflowed (oldest dropped first). */
    @Volatile
    var drops: Long = 0L
        private set

    /** Current number of buffered frames. */
    val depth: Int get() = synchronized(this) { frames.size }

    /**
     * Enqueue one inbound frame. Returns true when accepted; when the buffer
     * is full the oldest frame is discarded (counted in [drops]) and the new
     * frame is accepted, so the playout always sees the freshest audio.
     */
    fun add(frame: ByteArray): Boolean = synchronized(this) {
        require(frame.isNotEmpty() && frame.size <= frameBytes) {
            "frame must be 1..$frameBytes bytes, got ${frame.size}"
        }
        if (frames.size >= maxDepth) {
            frames.pollFirst()
            drops++
        }
        frames.addLast(frame)
        true
    }

    /**
     * Returns the next frame for playback. Before the buffer has filled to
     * [targetDepth] the playout must wait (returns null); afterwards it drains
     * continuously one frame per frame period until empty. Never blocks.
     */
    fun takeIfReady(): ByteArray? = synchronized(this) {
        if (started) {
            frames.pollFirst()
        } else if (frames.size >= targetDepth) {
            started = true
            frames.pollFirst()
        } else {
            null
        }
    }

    /**
     * Returns the next frame if any are buffered (used right before an
     * underrun). Never blocks.
     */
    fun takeNow(): ByteArray? = synchronized(this) { frames.pollFirst() }

    fun clear() = synchronized(this) {
        frames.clear()
        drops = 0L
        started = false
    }
}
