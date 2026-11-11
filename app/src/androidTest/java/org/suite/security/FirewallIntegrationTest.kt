package org.suite.security

import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Requires scripts/traffic-endpoint.py and the separately installed :probe APK. */
@RunWith(AndroidJUnit4::class)
class FirewallIntegrationTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private var saved = emptySet<String>()
    private var phase = "control"
    private val probePackage = "org.suite.firewallprobe"

    @Before fun prepare() {
        saved = Rules.blocked(context)
        shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        assertNull("VPN authorization could not be prepared", VpnService.prepare(context))
        stop()
    }
    @After fun restore() {
        try { probe("tcp-close", 18080) } finally { stop() }
        Rules.save(context, saved)
    }
    private fun shell(command: String) {
        ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(command)).use { it.readBytes() }
    }
    private fun await(message: String, timeoutMs: Long = 8000, condition: () -> Boolean) {
        val until = SystemClock.elapsedRealtime() + timeoutMs
        while (!condition() && SystemClock.elapsedRealtime() < until) SystemClock.sleep(50)
        if (!condition()) {
            Thread.getAllStackTraces().filterKeys { it.name == "main" || it.name == "firewall-packets" }.forEach { (thread, trace) ->
                android.util.Log.e("FirewallValidation", "${thread.name}: ${trace.joinToString("\n")}")
            }
        }
        assertTrue("$message: ${FirewallStatus.state.value}", condition())
    }
    private fun start(packages: Set<String>) {
        Rules.save(context, packages)
        context.startForegroundService(Intent(context, FirewallService::class.java))
        await("VPN did not become active", 60000) { FirewallStatus.state.value.active }
    }
    private fun stop() {
        // Android binds an established VpnService; stopService alone does not unbind it.
        context.startService(Intent(context, FirewallService::class.java).setAction(FirewallService.STOP))
        await("VPN did not stop") { !FirewallStatus.state.value.active && !FirewallStatus.state.value.starting }
        SystemClock.sleep(600) // let old reader release its duplicated descriptor
    }
    private fun probe(kind: String, port: Int, host: String = "10.0.2.2"): Pair<Int, String?> {
        val latch = CountDownLatch(1)
        var result = -1 to "No probe response"
        val intent = Intent().addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES or Intent.FLAG_RECEIVER_FOREGROUND).setComponent(ComponentName(probePackage, "$probePackage.ProbeReceiver"))
            .putExtra("kind", kind).putExtra("port", port).putExtra("host", host)
            .putExtra("nonce", "$phase-${if (host.contains(':')) "v6" else "v4"}-$kind-${SystemClock.elapsedRealtime()}")
        context.sendOrderedBroadcast(intent, null, object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                result = resultCode to resultData
                latch.countDown()
            }
        }, null, -1, null, null)
        assertTrue("Probe did not respond: install :probe and start endpoint", latch.await(30, TimeUnit.SECONDS))
        // An exception caught inside the fixture is 0; a missing receiver must never count as blocking.
        assertTrue("Missing/unauthorized test fixture: $result", result.first in 0..1)
        return result
    }
    private fun assertRecovery(host: String = "10.0.2.2") {
        val deadline = SystemClock.elapsedRealtime() + 30000
        var result = probe("tcp", 18080, host)
        while (result.first != 1 && SystemClock.elapsedRealtime() < deadline) {
            SystemClock.sleep(100)
            result = probe("tcp", 18080, host)
        }
        assertEquals("Underlying network did not recover within 30 seconds: $host $result", 1, result.first)
    }
    @Test fun selectedAndUnselectedUidTrafficWithRealProtocols() {
        val cases = listOf("tcp" to 18080, "udp" to 18081, "dns" to 1053, "dns-tcp" to 1053, "dot" to 1853, "doh" to 18443)
        val hosts = InstrumentationRegistry.getArguments().getString("hosts")?.split(',') ?: listOf("10.0.2.2")
        require(hosts.all { it in setOf("10.0.2.2", "fec0::2") })
        for (host in hosts) for ((kind, port) in cases) {
            val result = probe(kind, port, host)
            assertEquals("$kind baseline failed: $result", 1, result.first)
        }
        start(setOf(probePackage))
        assertFalse(FirewallStatus.state.value.quarantine)
        phase = "blocked"
        for (host in hosts) for ((kind, port) in cases) {
            val result = probe(kind, port, host)
            assertEquals("$kind escaped selected-UID sink", 0, result.first)
            assertTrue("Unexpected fixture failure: $result", result.second in setOf("SocketTimeoutException", "ConnectException", "SocketException"))
        }
        await("No captured selected traffic") { FirewallStatus.state.value.packets > 0 }
        phase = "control"
        // Switch the VPN to another installed UID. The probe should again reach endpoints.
        Rules.save(context, setOf("com.android.settings"))
        context.startForegroundService(Intent(context, FirewallService::class.java))
        await("Replacement rules did not become ready", 60000) {
            val state = FirewallStatus.state.value
            state.active && state.appliedPackages == setOf("com.android.settings")
        }
        for (host in hosts) for ((kind, port) in cases) assertEquals("$kind $host unselected probe failed", 1, probe(kind, port, host).first)
        stop()
        assertRecovery()
    }
    @Test fun emptyAndMissingSelectionsCaptureAllTraffic() {
        assertEquals("Endpoint baseline required", 1, probe("tcp", 18080).first)
        for (selection in listOf(emptySet(), setOf("org.suite.missing.package"))) {
            start(selection)
            await("Safety mode not enabled") { FirewallStatus.state.value.quarantine }
            phase = "blocked"
            val result = probe("tcp", 18080)
            if (result.first != 0) {
                val details = listOf("dumpsys connectivity", "ip rule", "ip route show table all", "dumpsys package org.suite.firewallprobe").joinToString("\n") { command ->
                    command + "\n" + ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(command)).use { it.readBytes().toString(Charsets.UTF_8) }
                }
                java.io.File(context.cacheDir, "vpn-failure.txt").writeText(details)
            }
            assertEquals("Safety mode allowed traffic", 0, result.first)
            phase = "control"
            stop()
        }
    }
    @Test fun existingTcpConnectionsCannotContinueAfterVpnReady() {
        val hosts = InstrumentationRegistry.getArguments().getString("hosts")?.split(',') ?: listOf("10.0.2.2")
        for (host in hosts) {
            phase = "control"
            assertEquals("Persistent connection baseline failed", 1, probe("tcp-open", 18080, host).first)
            val started = SystemClock.elapsedRealtime()
            start(setOf(probePackage))
            assertTrue("Server idle timeout could invalidate test", SystemClock.elapsedRealtime() - started < 90000)
            phase = "blocked"
            val result = probe("tcp-held", 18080, host)
            assertEquals("Pre-existing TCP connection escaped VPN", 0, result.first)
            assertTrue("Fixture process/socket vanished: $result", result.second in setOf("SocketException", "SocketTimeoutException", "ConnectException", "EOFException"))
            phase = "control"
            stop()
            assertRecovery(host)
        }
    }
    @Test fun authorizationRevocationStopsTheOldVpn() {
        assertEquals("Endpoint baseline required", 1, probe("tcp", 18080).first)
        start(setOf(probePackage))
        phase = "blocked"
        assertEquals(0, probe("tcp", 18080).first)
        // A pre-consented second package takes ownership through the real public API.
        shell("appops set $probePackage ACTIVATE_VPN allow")
        assertEquals("Competing authorization failed", 1, probe("prepare-vpn", 18080).first)
        await("Revoked VPN still claims readiness") { !FirewallStatus.state.value.active && !FirewallStatus.state.value.starting }
        await("Revoked reader leaked") { Thread.getAllStackTraces().keys.none { it.name == "firewall-packets" && it.isAlive } }
        phase = "control"
        assertRecovery()
        assertNull("Restore suite consent", VpnService.prepare(context))
    }
    @Test fun readerDuplicateDoesNotOwnOriginalDescriptor() {
        val pipe = ParcelFileDescriptor.createPipe()
        pipe[0].use { original ->
            val reader = ParcelFileDescriptor.dup(original.fileDescriptor)
            pipe[1].close()
            ParcelFileDescriptor.AutoCloseInputStream(reader).use { assertEquals(-1, it.read()) }
            assertTrue("Reader EOF closed original descriptor", original.fileDescriptor.valid())
        }
    }
    @Test fun repeatedRestartsAndStopReleaseReadersAndDescriptors() {
        val before = java.io.File("/proc/self/fd").list().orEmpty().size
        repeat(12) {
            start(setOf(probePackage))
            assertTrue(FirewallStatus.state.value.active)
            stop()
        }
        val after = java.io.File("/proc/self/fd").list().orEmpty().size
        assertTrue("FD growth: $before -> $after", after <= before + 5)
        await("Leaked reader thread") { Thread.getAllStackTraces().keys.none { it.name == "firewall-packets" && it.isAlive } }
    }
}
