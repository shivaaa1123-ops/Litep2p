package com.zeengal.litep2p

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Hermetic tests for [VoiceJitterBuffer] — the WAN jitter-smoothing layer of
 * voice-call playback. No Android framework involved, so it runs on the JVM
 * as a plain unit test.
 */
class VoiceJitterBufferTest {

    private fun frame(id: Byte, size: Int = 640): ByteArray = ByteArray(size) { id }

    @Test
    fun orderIsPreserved() {
        val b = VoiceJitterBuffer(640, targetDepth = 2, maxDepth = 8)
        assertNull(b.takeIfReady())
        b.add(frame(1)); b.add(frame(2))
        assertEquals(1, b.takeIfReady()!![0].toInt())
        assertEquals(2, b.takeIfReady()!![0].toInt())
        assertNull(b.takeIfReady())
        b.add(frame(3))
        assertEquals(3, b.takeIfReady()!![0].toInt())
        assertEquals(0L, b.drops)
    }

    @Test
    fun targetDepthGatesPlaybackStart() {
        val b = VoiceJitterBuffer(640, targetDepth = 3, maxDepth = 8)
        b.add(frame(1)); b.add(frame(2))
        assertNull(b.takeIfReady())
        b.add(frame(3))
        assertNotNull(b.takeIfReady())
    }

    @Test
    fun overflowDropsOldestFrames() {
        val b = VoiceJitterBuffer(640, targetDepth = 2, maxDepth = 3)
        b.add(frame(1)); b.add(frame(2)); b.add(frame(3)); b.add(frame(4))
        assertEquals(3, b.depth)
        assertEquals(1L, b.drops)
        // Oldest (1) was discarded; 2, 3, 4 survive in order.
        assertEquals(2, b.takeNow()!![0].toInt())
        assertEquals(3, b.takeNow()!![0].toInt())
        assertEquals(4, b.takeNow()!![0].toInt())
        assertNull(b.takeNow())
    }

    @Test
    fun takeNowDrainsWithoutGating() {
        val b = VoiceJitterBuffer(640, targetDepth = 5, maxDepth = 8)
        b.add(frame(7))
        assertEquals(7, b.takeNow()!![0].toInt())
        assertNull(b.takeNow())
    }

    @Test
    fun clearResets() {
        val b = VoiceJitterBuffer(640, targetDepth = 1, maxDepth = 4)
        b.add(frame(1)); b.add(frame(2)); b.add(frame(3)); b.add(frame(4)); b.add(frame(5))
        assertEquals(1L, b.drops)
        b.clear()
        assertEquals(0, b.depth)
        assertEquals(0L, b.drops)
        assertNull(b.takeNow())
    }

    @Test
    fun drainsContinuouslyOnceStarted() {
        // Regression: the gate must latch after the first fill — playback
        // drains at one frame per period even when depth drops below target.
        val b = VoiceJitterBuffer(640, targetDepth = 3, maxDepth = 8)
        b.add(frame(1)); b.add(frame(2))
        assertNull(b.takeIfReady())          // below target -> wait
        b.add(frame(3))
        assertEquals(3, b.depth)
        assertEquals(1, b.takeIfReady()!![0].toInt())  // latch on first ready frame
        assertEquals(2, b.takeIfReady()!![0].toInt())  // below target now, but drains
        assertEquals(3, b.takeIfReady()!![0].toInt())
        assertNull(b.takeIfReady())          // empty
        b.add(frame(4))
        assertEquals(4, b.takeIfReady()!![0].toInt())  // restarted stream plays immediately
    }

    @Test
    fun rejectsFramesLargerThanFrameSize() {
        val b = VoiceJitterBuffer(640, targetDepth = 1, maxDepth = 4)
        try {
            b.add(ByteArray(1280))
            throw AssertionError("expected IllegalArgumentException for a 1280-byte frame")
        } catch (_: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun concurrentProduceConsumeKeepsOrder() {
        // maxDepth large enough that nothing is dropped, so all 500 frames are
        // observable in FIFO order.
        val b = VoiceJitterBuffer(640, targetDepth = 4, maxDepth = 600)
        val seen = java.util.Collections.synchronizedList(mutableListOf<Byte>())
        val producer = Thread {
            for (i in 1..500) b.add(frame(i.toByte()))
        }
        val consumer = Thread {
            while (true) {
                val f = b.takeIfReady() ?: b.takeNow()
                if (f != null) {
                    synchronized(seen) { seen.add(f[0]) }
                    if (seen.size == 500) break
                } else {
                    Thread.sleep(1)
                }
            }
        }
        producer.start(); consumer.start()
        producer.join(); consumer.join()
        assertEquals(500, seen.size)
        assertEquals(0L, b.drops)
        // Exact FIFO: every frame observed in producer order (Byte wraps at
        // 128, so compare against the true byte sequence, not 1..500).
        assertEquals((1..500).map { it.toByte() }, seen)
    }
}
