package org.suite.firewallprobe

import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.net.SocketException
import java.net.SocketTimeoutException

/** Remains testable after the firewall process is force-stopped; no VPN state is changed. */
@RunWith(AndroidJUnit4::class)
class IndependentNetworkTest {
    @Test fun protocolConnectivity() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val args = InstrumentationRegistry.getArguments()
        val expected = args.getString("expected") ?: "allowed"
        require(expected in setOf("allowed", "blocked"))
        val host = args.getString("host") ?: "10.0.2.2"
        require(host in setOf("10.0.2.2", "fec0::2"))
        val protocols = args.getString("protocols")?.split(',') ?: listOf("tcp")
        require(protocols.isNotEmpty() && protocols.all { it in setOf("tcp", "udp", "dns", "dns-tcp", "dot", "doh") })
        for (kind in protocols) {
            val port = when (kind) { "udp" -> 18081; "dns", "dns-tcp" -> 1053; "dot" -> 1853; "doh" -> 18443; else -> 18080 }
            val nonce = "${if (expected == "blocked") "blocked" else "control"}-independent-$kind-${SystemClock.elapsedRealtime()}"
            var connected = false
            try {
                ProbeReceiver().execute(instrumentation.targetContext, host, port, kind, nonce)
                connected = true
            } catch (_: SocketTimeoutException) { }
            catch (_: SocketException) { }
            assertEquals("Independent UID $host $kind connectivity mismatch", expected == "allowed", connected)
        }
    }
}
