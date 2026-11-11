package org.suite.firewallprobe

import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException

/** Independent UID remains testable after the firewall process is force-stopped. */
@RunWith(AndroidJUnit4::class)
class IndependentNetworkTest {
    @Test fun tcpConnectivity() {
        val args = InstrumentationRegistry.getArguments()
        val expected = args.getString("expected") ?: "allowed"
        require(expected in setOf("allowed", "blocked"))
        val host = args.getString("host") ?: "10.0.2.2"
        require(host in setOf("10.0.2.2", "fec0::2"))
        val nonce = "${if (expected == "blocked") "blocked" else "control"}-independent-${SystemClock.elapsedRealtime()}".toByteArray(Charsets.US_ASCII)
        var connected = false
        try {
            Socket().use { socket ->
                socket.soTimeout = 3000
                socket.connect(InetSocketAddress(host, 18080), 3000)
                socket.getOutputStream().write(nonce)
                val response = ByteArray(nonce.size)
                java.io.DataInputStream(socket.getInputStream()).readFully(response)
                assertArrayEquals("Invalid endpoint response", nonce, response)
                connected = true
            }
        } catch (_: SocketTimeoutException) { }
        catch (_: SocketException) { }
        assertEquals("Independent UID connectivity mismatch", expected == "allowed", connected)
    }
}
