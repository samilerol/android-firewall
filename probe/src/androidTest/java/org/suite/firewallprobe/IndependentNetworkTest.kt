package org.suite.firewallprobe

import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import android.os.Bundle
import android.system.ErrnoException
import android.system.OsConstants
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketException
import java.net.SocketTimeoutException

/** Remains testable after the firewall process is force-stopped; no VPN state is changed. */
@RunWith(AndroidJUnit4::class)
class IndependentNetworkTest {
    @Test fun protocolConnectivity() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val args = InstrumentationRegistry.getArguments()
        if (args.getString("mode") == "udp-canary") {
            udpCanary()
            return
        }
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
            var networkError: String? = null
            try {
                ProbeReceiver().execute(instrumentation.targetContext, host, port, kind, nonce)
                connected = true
            } catch (e: IOException) { if (!networkDenied(e)) throw e; networkError = e.toString() }
            assertEquals("Independent UID $host $kind connectivity mismatch: $networkError", expected == "allowed", connected)
        }
    }
    private fun networkDenied(error: IOException): Boolean {
        if (error is SocketException || error is SocketTimeoutException) return true
        val cause = error.cause as? ErrnoException ?: return false
        val call = cause.message?.substringBefore(" failed:")
        return call in setOf("sendto", "recvfrom", "connect", "socket", "bind") &&
            cause.errno in setOf(OsConstants.EACCES, OsConstants.EPERM, OsConstants.ENETUNREACH,
                OsConstants.EHOSTUNREACH, OsConstants.ENETDOWN)
    }
    private fun udpCanary() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val args = InstrumentationRegistry.getArguments()
        val duration = args.getString("duration")?.toLong() ?: 60000L
        require(duration in 1000L..120000L)
        val hosts = args.getString("hosts")?.split(',') ?: listOf("10.0.2.2")
        require(hosts.isNotEmpty() && hosts.all { it in setOf("10.0.2.2", "fec0::2") })
        val end = SystemClock.elapsedRealtime() + duration
        var attempted = 0
        var accepted = 0
        var rejected = 0
        var announced = false
        while (SystemClock.elapsedRealtime() < end) {
            for (host in hosts) {
                attempted++
                val bytes = "blocked-canary-${SystemClock.elapsedRealtime()}-$attempted".toByteArray(Charsets.US_ASCII)
                try {
                    DatagramSocket().use { socket ->
                        socket.send(DatagramPacket(bytes, bytes.size, InetAddress.getByName(host), 18081))
                        accepted++
                    }
                } catch (e: IOException) {
                    if (!networkDenied(e)) throw e
                    rejected++
                }
            }
            if (!announced && accepted > 0) {
                instrumentation.sendStatus(2, Bundle().apply { putString("stream", "CANARY_STARTED accepted=$accepted\n") })
                announced = true
            }
            SystemClock.sleep(50)
        }
        assertTrue("Canary did not exercise a live routed UID", attempted > 0 && accepted > 0)
        instrumentation.sendStatus(2, Bundle().apply { putString("stream", "CANARY_DONE attempted=$attempted accepted=$accepted rejected=$rejected\n") })
    }

}
