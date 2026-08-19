package com.zeengal.litep2p

/**
 * Adaptive playout pacing for voice-call playback.
 *
 * The remote peer's audio clock never runs at exactly the local rate, so a
 * fixed 20 ms-per-frame playout either overruns the jitter buffer (remote
 * clock fast → oldest-frame drops) or underruns it (remote clock slow →
 * silence gaps). This controller matches the remote clock by adjusting the
 * frame period from the buffer-depth error:
 *
 *   period = nominal − gain · (depth − target), clamped to ±[maxAdjustNs].
 *
 * - depth > target (buffer growing — remote clock fast) → shorter period,
 *   playout speeds up and drains toward the target.
 * - depth < target (buffer draining — remote clock slow) → longer period,
 *   playout slows down and lets the buffer refill.
 *
 * The clamp bounds the rate change to ±10% around nominal, so pitch is never
 * audibly affected. Jitter spikes move depth transiently; the modest gain
 * means only a sustained imbalance (clock drift) shifts the period, leaving a
 * small steady-state offset that doubles as jitter headroom.
 *
 * Pure arithmetic — no Android framework — so it is unit-testable on the JVM.
 */
class PlayoutPacer(
    private val nominalPeriodNs: Long,
    private val gainNsPerFrame: Long = 500_000L,   // 0.5 ms per frame of depth error
    private val maxAdjustNs: Long = 2_000_000L     // ±2 ms ≈ ±10% of a 20 ms frame
) {
    /** Returns the playout period (ns) to pace the next frame. */
    fun periodNs(depth: Int, targetDepth: Int): Long {
        val error = depth - targetDepth
        val adjust = (error * gainNsPerFrame).coerceIn(-maxAdjustNs, maxAdjustNs)
        return nominalPeriodNs - adjust
    }
}
