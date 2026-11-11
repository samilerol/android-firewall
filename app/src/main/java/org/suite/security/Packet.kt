package org.suite.security

/** Metadata only: never retains payloads or attempts TLS inspection. */
data class Packet(val version: Int, val protocol: String, val destination: String, val port: Int?, val bytes: Int)
object PacketParser {
    fun parse(data: ByteArray, length: Int): Packet? {
        if (length < 1 || length > data.size) return null
        fun u(i: Int) = data[i].toInt() and 255
        val version = u(0) ushr 4
        var offset: Int
        var protocol: Int
        val destination: String
        val total: Int
        when (version) {
            4 -> {
                if (length < 20) return null
                offset = (u(0) and 15) * 4
                total = (u(2) shl 8) or u(3)
                if (offset < 20 || offset > length || total < offset || total > length) return null
                protocol = u(9)
                destination = (16..19).joinToString(".") { u(it).toString() }
                // Noninitial fragments do not carry transport ports.
                val fragment = ((u(6) and 31) shl 8) or u(7)
                val port = if (fragment == 0 && (protocol == 6 || protocol == 17) && total >= offset + 4)
                    (u(offset + 2) shl 8) or u(offset + 3) else null
                return Packet(4, name(protocol), destination, port, total)
            }
            6 -> {
                if (length < 40) return null
                total = 40 + ((u(4) shl 8) or u(5))
                if (total > length) return null
                offset = 40
                protocol = u(6)
                destination = (24..38 step 2).joinToString(":") { ((u(it) shl 8) or u(it + 1)).toString(16) }
            }
            else -> return null
        }
        // Bounded metadata walk only. Parsing never grants network access.
        var headers = 0
        var extensionBytes = 0
        while (protocol == 0 || protocol == 43 || protocol == 44 || protocol == 51 || protocol == 60) {
            if (++headers > 8 || extensionBytes >= 2048) return Packet(version, name(protocol), destination, null, total)
            if (offset + 2 > total) return null
            val next = u(offset)
            val size = when (protocol) {
                44 -> 8
                51 -> (u(offset + 1) + 2) * 4
                else -> (u(offset + 1) + 1) * 8
            }
            if (offset + size > total) return null
            if (protocol == 44 && (((u(offset + 2) shl 8) or u(offset + 3)) and 0xfff8) != 0)
                return Packet(version, name(next), destination, null, total)
            offset += size
            extensionBytes += size
            if (extensionBytes > 2048) return Packet(version, name(next), destination, null, total)
            protocol = next
        }
        val port = if ((protocol == 6 || protocol == 17) && total >= offset + 4)
            (u(offset + 2) shl 8) or u(offset + 3) else null
        return Packet(version, name(protocol), destination, port, total)
    }
    private fun name(p: Int) = when (p) { 6 -> "TCP"; 17 -> "UDP"; 1 -> "ICMP"; 58 -> "ICMPv6"; else -> "IP/$p" }
}
