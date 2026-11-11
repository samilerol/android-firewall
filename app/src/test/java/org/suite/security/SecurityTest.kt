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
        val bytes = ByteArray(48).apply { this[0] = 0x60; this[5] = 8; this[6] = 44; this[40] = 17; this[43] = 8 }
        assertNull(PacketParser.parse(bytes, 48)!!.port)
    }
    @Test fun ipv4DnsAndOptionsUseActualTransportOffset() {
        val bytes = ByteArray(32).apply {
            this[0] = 0x47; this[3] = 32; this[9] = 17
            this[22] = 1; this[23] = -69 // options are not transport ports
            this[31] = 53
        }
        val packet = PacketParser.parse(bytes, bytes.size)!!
        assertEquals("UDP", packet.protocol)
        assertEquals(53, packet.port)
    }
    @Test fun trailingBytesOutsideDeclaredPacketDoNotBecomePorts() {
        val v4 = ipv4().apply { this[3] = 20 }
        assertNull(PacketParser.parse(v4, v4.size)!!.port)
        assertEquals(20, PacketParser.parse(v4, v4.size)!!.bytes)
        val v6 = ByteArray(44).apply { this[0] = 0x60; this[6] = 17; this[43] = 53 }
        assertNull(PacketParser.parse(v6, v6.size)!!.port)
        assertEquals(40, PacketParser.parse(v6, v6.size)!!.bytes)
    }
    @Test fun ipv6TruncationAndIcmpDoNotInventPorts() {
        val bytes = ByteArray(44).apply { this[0] = 0x60; this[5] = 8; this[6] = 17 }
        assertNull(PacketParser.parse(bytes, bytes.size))
        bytes[5] = 4; bytes[6] = 58
        assertEquals("ICMPv6", PacketParser.parse(bytes, bytes.size)!!.protocol)
        assertNull(PacketParser.parse(bytes, bytes.size)!!.port)
    }
    private fun ipv6(payload: Int, next: Int) = ByteArray(40 + payload).apply {
        this[0] = 0x60; this[4] = (payload ushr 8).toByte(); this[5] = payload.toByte(); this[6] = next.toByte()
    }
    @Test fun ipv6HopRoutingDestinationAndAuthenticationHeaders() {
        for (extension in listOf(0, 43, 60, 51)) {
            val bytes = ipv6(12, extension).apply { this[40] = 17; this[51] = 53 }
            val p = PacketParser.parse(bytes, bytes.size)!!
            assertEquals("UDP", p.protocol); assertEquals(53, p.port)
        }
    }
    @Test fun ipv6ExtensionChainAndInitialFragment() {
        val bytes = ipv6(28, 0).apply {
            this[40] = 60; this[48] = 44; this[56] = 6; this[59] = 1
            this[66] = 1; this[67] = -69
        }
        val p = PacketParser.parse(bytes, bytes.size)!!
        assertEquals("TCP", p.protocol); assertEquals(443, p.port)
    }
    @Test fun ipv6NoninitialFragmentNeverInterpretsPayloadAsHeaders() {
        val bytes = ipv6(20, 44).apply { this[40] = 60; this[43] = 8; this[48] = 17; this[59] = 53 }
        assertNull(PacketParser.parse(bytes, bytes.size)!!.port)
    }
    @Test fun ipv6TruncatedExtensionsAreRejected() {
        for (extension in listOf(0, 43, 44, 51, 60)) {
            val bytes = ipv6(7, extension).apply { this[40] = 17 }
            assertNull(PacketParser.parse(bytes, bytes.size))
        }
        val bytes = ipv6(12, 0).apply { this[41] = -1 }
        assertNull(PacketParser.parse(bytes, bytes.size))
    }
    @Test fun ipv6ExtensionWalkIsBounded() {
        val bytes = ipv6(84, 0)
        for (i in 0 until 10) bytes[40 + i * 8] = if (i == 9) 17 else 0
        bytes[123] = 53
        assertNull(PacketParser.parse(bytes, bytes.size)!!.port)
    }
    @Test fun ipv6EspAndNoNextHeaderStayOpaque() {
        for (next in listOf(50, 59)) {
            val bytes = ipv6(8, next).apply { this[43] = 53 }
            assertNull(PacketParser.parse(bytes, bytes.size)!!.port)
        }
    }
    @Test fun ipv4FragmentOffsetHighBitsAndSignedLengths() {
        val bytes = ipv4().apply { this[6] = 1 }
        assertNull(PacketParser.parse(bytes, bytes.size)!!.port)
        assertNull(PacketParser.parse(bytes, -1))
        bytes[2] = -1
        assertNull(PacketParser.parse(bytes, bytes.size))
    }
    @Test fun validPacketWithCorruptChecksumRemainsMetadataOnly() {
        val bytes = ipv4().apply { this[10] = -1; this[11] = -1 }
        assertEquals(443, PacketParser.parse(bytes, bytes.size)!!.port)
        // The sink drops packets independently of checksum and parse outcome.
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
