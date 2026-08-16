package com.zeengal.litep2p.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM unit tests for the pure Kotlin logic of :litep2p-core.
 *
 * These tests deliberately avoid [LiteP2P] / [LiteP2PNative], which load the
 * native library and can only run on a device/emulator or with the .so present.
 */
class LiteP2PCoreTest {

    /* ------------------------------------------------------------------ */
    /* EngineResult                                                        */
    /* ------------------------------------------------------------------ */

    @Test
    fun `fromCode maps every documented native code`() {
        assertEquals(EngineResult.OK, EngineResult.fromCode(0))
        assertEquals(EngineResult.INVALID_ARG, EngineResult.fromCode(-1))
        assertEquals(EngineResult.INVALID_STATE, EngineResult.fromCode(-2))
        assertEquals(EngineResult.BUSY, EngineResult.fromCode(-3))
        assertEquals(EngineResult.NOT_FOUND, EngineResult.fromCode(-4))
        assertEquals(EngineResult.IO, EngineResult.fromCode(-5))
        assertEquals(EngineResult.TIMEOUT, EngineResult.fromCode(-6))
        assertEquals(EngineResult.UNSUPPORTED, EngineResult.fromCode(-7))
        assertEquals(EngineResult.NO_ROUTE, EngineResult.fromCode(-8))
        assertEquals(EngineResult.INTERNAL, EngineResult.fromCode(-99))
    }

    @Test
    fun `fromCode falls back to INTERNAL for unknown codes`() {
        assertEquals(EngineResult.INTERNAL, EngineResult.fromCode(-42))
        assertEquals(EngineResult.INTERNAL, EngineResult.fromCode(123))
    }

    @Test
    fun `result codes round-trip through code property`() {
        for (value in EngineResult.values()) {
            assertEquals(value, EngineResult.fromCode(value.code))
        }
    }

    /* ------------------------------------------------------------------ */
    /* LiteP2PCapabilities                                                 */
    /* ------------------------------------------------------------------ */

    @Test
    fun `capabilities decode all-off flag mask`() {
        val caps = LiteP2PCapabilities.fromFlags(0)
        assertFalse(caps.fileTransfer)
        assertFalse(caps.overlay)
        assertFalse(caps.proxy)
        assertFalse(caps.encryption)
        assertFalse(caps.discovery)
        assertFalse(caps.telemetry)
    }

    @Test
    fun `capabilities decode all-on flag mask`() {
        val all = LiteP2PCapabilities.FLAG_FILE_TRANSFER or
            LiteP2PCapabilities.FLAG_OVERLAY or
            LiteP2PCapabilities.FLAG_PROXY or
            LiteP2PCapabilities.FLAG_ENCRYPTION or
            LiteP2PCapabilities.FLAG_DISCOVERY or
            LiteP2PCapabilities.FLAG_TELEMETRY
        val caps = LiteP2PCapabilities.fromFlags(all)
        assertTrue(caps.fileTransfer)
        assertTrue(caps.overlay)
        assertTrue(caps.proxy)
        assertTrue(caps.encryption)
        assertTrue(caps.discovery)
        assertTrue(caps.telemetry)
    }

    @Test
    fun `capabilities decode individual flags`() {
        assertTrue(LiteP2PCapabilities.fromFlags(LiteP2PCapabilities.FLAG_FILE_TRANSFER).fileTransfer)
        assertFalse(LiteP2PCapabilities.fromFlags(LiteP2PCapabilities.FLAG_FILE_TRANSFER).overlay)
        assertTrue(LiteP2PCapabilities.fromFlags(LiteP2PCapabilities.FLAG_OVERLAY).overlay)
        assertTrue(LiteP2PCapabilities.fromFlags(LiteP2PCapabilities.FLAG_PROXY).proxy)
        assertTrue(LiteP2PCapabilities.fromFlags(LiteP2PCapabilities.FLAG_ENCRYPTION).encryption)
        assertTrue(LiteP2PCapabilities.fromFlags(LiteP2PCapabilities.FLAG_DISCOVERY).discovery)
        assertTrue(LiteP2PCapabilities.fromFlags(LiteP2PCapabilities.FLAG_TELEMETRY).telemetry)
    }

    /* ------------------------------------------------------------------ */
    /* FileTransferPriority                                                */
    /* ------------------------------------------------------------------ */

    @Test
    fun `file transfer priority maps wire values`() {
        assertEquals(FileTransferPriority.LOW, FileTransferPriority.fromWire(0))
        assertEquals(FileTransferPriority.LOW, FileTransferPriority.fromWire(-5))
        assertEquals(FileTransferPriority.NORMAL, FileTransferPriority.fromWire(1))
        assertEquals(FileTransferPriority.HIGH, FileTransferPriority.fromWire(2))
        assertEquals(FileTransferPriority.HIGH, FileTransferPriority.fromWire(10))
    }

    /* ------------------------------------------------------------------ */
    /* CommsMode                                                           */
    /* ------------------------------------------------------------------ */

    @Test
    fun `comms mode parses wire strings`() {
        assertEquals(CommsMode.TCP, CommsMode.fromWire("TCP"))
        assertEquals(CommsMode.UDP, CommsMode.fromWire("UDP"))
        assertEquals(CommsMode.QUIC, CommsMode.fromWire("QUIC"))
        assertEquals(CommsMode.AUTO, CommsMode.fromWire("AUTO"))
        assertEquals(CommsMode.ALL, CommsMode.fromWire("ALL"))
        assertEquals(CommsMode.ALL, CommsMode.fromWire("HETEROGENEOUS"))
        assertEquals(CommsMode.UDP, CommsMode.fromWire("BOGUS"))
        assertEquals(CommsMode.UDP, CommsMode.fromWire(null))
    }

    /* ------------------------------------------------------------------ */
    /* ConnectionPath                                                      */
    /* ------------------------------------------------------------------ */

    @Test
    fun `connection path parses wire strings`() {
        assertEquals(ConnectionPath.LAN_DIRECT, ConnectionPath.fromWire("LAN_DIRECT"))
        assertEquals(ConnectionPath.LAN_DIRECT, ConnectionPath.fromWire("LAN"))
        assertEquals(ConnectionPath.WAN_HOLE_PUNCH, ConnectionPath.fromWire("WAN_HOLE_PUNCH"))
        assertEquals(ConnectionPath.WAN_HOLE_PUNCH, ConnectionPath.fromWire("WAN_DIRECT"))
        assertEquals(ConnectionPath.TURN_RELAY, ConnectionPath.fromWire("TURN_RELAY"))
        assertEquals(ConnectionPath.TURN_RELAY, ConnectionPath.fromWire("TURN"))
        assertEquals(ConnectionPath.SIGNALING_RELAY, ConnectionPath.fromWire("SIGNALING_RELAY"))
        assertEquals(ConnectionPath.SIGNALING_RELAY, ConnectionPath.fromWire("SIGNALING"))
        assertEquals(ConnectionPath.UNKNOWN, ConnectionPath.fromWire("SOMETHING_NEW"))
        assertEquals(ConnectionPath.UNKNOWN, ConnectionPath.fromWire(null))
    }

    /* ------------------------------------------------------------------ */
    /* LogLevel                                                            */
    /* ------------------------------------------------------------------ */

    @Test
    fun `log level maps ints`() {
        assertEquals(LogLevel.DEBUG, LogLevel.fromLevel(0))
        assertEquals(LogLevel.INFO, LogLevel.fromLevel(1))
        assertEquals(LogLevel.WARN, LogLevel.fromLevel(2))
        assertEquals(LogLevel.ERROR, LogLevel.fromLevel(3))
        assertEquals(LogLevel.INFO, LogLevel.fromLevel(99))
    }

    /* ------------------------------------------------------------------ */
    /* ReconnectMode                                                       */
    /* ------------------------------------------------------------------ */

    @Test
    fun `reconnect mode wire values match the C ABI`() {
        assertEquals("auto", ReconnectMode.AUTO.wire)
        assertEquals("aggressive", ReconnectMode.AGGRESSIVE.wire)
        assertEquals("balanced", ReconnectMode.BALANCED.wire)
        assertEquals("power_saver", ReconnectMode.POWER_SAVER.wire)
    }
}
