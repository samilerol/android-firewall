package org.suite.security

import org.junit.Assert.*
import org.junit.Test

class SecurityTest {
    private fun ipv4(protocol: Int = 6): ByteArray = ByteArray(24).apply {
        this[0] = 0x45; this[3] = 24; this[9] = protocol.toByte()
        this[16] = 1; this[17] = 2; this[18] = 3; this[19] = 4
        this[22] = 1; this[23] = -69 // port 443
    }
    @Test fun ipv4TcpMetadata() {
        val p = PacketParser.parse(ipv4(), 24)!!
        assertEquals("1.2.3.4", p.destination); assertEquals(443, p.port)
        assertEquals("TCP", p.protocol); assertEquals(24, p.bytes)
    }
    @Test fun fragmentsDoNotInventPorts() {
        val bytes = ipv4().apply { this[7] = 1 }
        assertNull(PacketParser.parse(bytes, bytes.size)!!.port)
    }
    @Test fun validatesLengthsAndHeaderSize() {
        assertNull(PacketParser.parse(byteArrayOf(), 0))
        assertNull(PacketParser.parse(ipv4(), 19))
        assertNull(PacketParser.parse(ipv4(), 25))
        assertNull(PacketParser.parse(ipv4().apply { this[0] = 0x4f }, 24))
        assertNull(PacketParser.parse(ipv4().apply { this[3] = 40 }, 24))
        assertNull(PacketParser.parse(ipv4().apply { this[0] = 0x75 }, 24))
    }
    @Test fun ipv6UdpMetadata() {
        val bytes = ByteArray(44).apply { this[0] = 0x60; this[5] = 4; this[6] = 17; this[39] = 1; this[43] = 53 }
        val p = PacketParser.parse(bytes, bytes.size)!!
        assertEquals(6, p.version); assertEquals("UDP", p.protocol); assertEquals(53, p.port)
        assertEquals("0:0:0:0:0:0:0:1", p.destination)
    }
    @Test fun ipv6ExtensionsDoNotInventTransportPorts() {
        val bytes = ByteArray(48).apply { this[0] = 0x60; this[5] = 8; this[6] = 44 }
        assertNull(PacketParser.parse(bytes, 48)!!.port)
    }
    @Test fun sensitivePermissionsAreSpecific() {
        assertEquals(listOf("android.permission.CAMERA"), SecurityPolicy.sensitivePermissions(listOf("android.permission.INTERNET", "android.permission.CAMERA")))
    }
    @Test fun manifestSignalsAreHeuristics() {
        assertEquals(4, SecurityPolicy.apkSignals(true, true, 27, listOf("android.permission.RECORD_AUDIO")).size)
        assertTrue(SecurityPolicy.apkSignals(false, false, 35, emptyList()).isEmpty())
    }
    @Test fun malformedPacketFuzzDoesNotCrash() {
        val random = java.util.Random(42)
        repeat(10000) {
            val bytes = ByteArray(random.nextInt(200)); random.nextBytes(bytes)
            PacketParser.parse(bytes, bytes.size)
        }
    }
}
