package com.zeengal.litep2p

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Hermetic tests for [PlayoutPacer] — the adaptive clock-matching layer of
 * voice-call playback. Pure arithmetic, so it runs on the JVM.
 */
class PlayoutPacerTest {

    private val nominal = 20_000_000L  // 20 ms
    private val gain = 500_000L        // 0.5 ms per frame of depth error
    private val maxAdj = 2_000_000L    // ±2 ms

    private fun pacer() = PlayoutPacer(nominal, gain, maxAdj)

    @Test
    fun nominalPeriodAtTargetDepth() {
        assertEquals(nominal, pacer().periodNs(5, targetDepth = 5))
    }

    @Test
    fun deepBufferSpeedsUpPlayout() {
        val p = pacer()
        val period = p.periodNs(7, targetDepth = 5)   // error +2 -> 1 ms shorter
        assertTrue("period should shrink when buffer is deep", period < nominal)
        assertEquals(nominal - 1_000_000L, period)
    }

    @Test
    fun shallowBufferSlowsDownPlayout() {
        val p = pacer()
        val period = p.periodNs(3, targetDepth = 5)   // error -2 -> 1 ms longer
        assertTrue("period should grow when buffer is shallow", period > nominal)
        assertEquals(nominal + 1_000_000L, period)
    }

    @Test
    fun clampsAtMaxAdjustment() {
        val p = pacer()
        // error +10 -> 5 ms requested, clamped to ±2 ms
        assertEquals(nominal - maxAdj, p.periodNs(15, targetDepth = 5))
        // error -10 -> clamped to +2 ms
        assertEquals(nominal + maxAdj, p.periodNs(0, targetDepth = 10))
    }

    @Test
    fun symmetricAdjustment() {
        val p = pacer()
        val fast = p.periodNs(8, targetDepth = 5)   // +3 -> -1.5 ms
        val slow = p.periodNs(2, targetDepth = 5)   // -3 -> +1.5 ms
        assertEquals(nominal - fast, slow - nominal)
    }

    @Test
    fun staysBoundedAcrossWideErrors() {
        val p = pacer()
        // Extremely deep buffer never exceeds the clamp.
        assertEquals(nominal - maxAdj, p.periodNs(10_000, targetDepth = 5))
        // Empty buffer (post-underrun) never exceeds the clamp.
        assertEquals(nominal + maxAdj, p.periodNs(0, targetDepth = 5))
    }

    @Test
    fun followsRemoteClockDrift() {
        val p = pacer()
        // A sustained 1.3 frame/s oversupply (remote clock ~2.6% fast) drives
        // depth up; the controller must pull the period below nominal to match.
        val periodAtDepth12 = p.periodNs(12, targetDepth = 5)
        assertTrue(periodAtDepth12 < nominal - gain)  // error +7 -> -3.5 ms, clamped
        // A sustained undersupply must stretch the period.
        val periodAtDepth2 = p.periodNs(2, targetDepth = 5)
        assertTrue(periodAtDepth2 > nominal + gain)
    }
}
