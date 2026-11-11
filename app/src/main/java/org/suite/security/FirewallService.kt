package org.suite.security

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.FileInputStream
import java.util.concurrent.atomic.AtomicBoolean

data class FirewallState(val active: Boolean = false, val packets: Long = 0, val bytes: Long = 0, val events: List<Packet> = emptyList(), val message: String = "Firewall is off")
object FirewallStatus {
    internal val mutable = MutableStateFlow(FirewallState())
    val state = mutable.asStateFlow()
}
object Rules {
    fun blocked(context: Context): Set<String> = context.getSharedPreferences("firewall", Context.MODE_PRIVATE).getStringSet("blocked", emptySet())!!.toSet()
    fun save(context: Context, packages: Set<String>) { context.getSharedPreferences("firewall", Context.MODE_PRIVATE).edit().putStringSet("blocked", packages.toSet()).apply() }
}

/** Selected applications alone enter this TUN. Every captured packet is discarded. */
class FirewallService : VpnService() {
    private var tunnel: ParcelFileDescriptor? = null
    private var worker: Thread? = null
    private var running = AtomicBoolean(false)
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == STOP) { shutdown("Firewall is off"); stopSelf(); return START_NOT_STICKY }
        showNotification()
        shutdown("Updating rules")
        val blocked = Rules.blocked(this) - packageName
        if (blocked.isEmpty()) { shutdown("Select at least one app to block"); stopSelf(); return START_NOT_STICKY }
        try {
            val builder = Builder().setSession("Security Suite • blocked apps").setMtu(1500)
                .addAddress("10.111.0.1", 32).addRoute("0.0.0.0", 0)
                .addAddress("fd42:4242::1", 128).addRoute("::", 0)
                .addDnsServer("192.0.2.1")
            var selected = 0
            blocked.forEach { name ->
                try { builder.addAllowedApplication(name); selected++ } catch (_: android.content.pm.PackageManager.NameNotFoundException) { /* Removed app */ }
            }
            check(selected > 0) { "Selected apps are no longer installed" }
            val descriptor = builder.establish() ?: error("VPN permission was revoked")
            tunnel = descriptor
            val token = AtomicBoolean(true)
            running = token
            FirewallStatus.mutable.value = FirewallState(active = true, message = "Blocking $selected selected apps")
            worker = Thread({ drain(descriptor, token) }, "firewall-packets").apply { start() }
        } catch (e: Exception) { shutdown("Cannot start firewall: ${e.message}"); stopSelf() }
        return START_NOT_STICKY
    }
    private fun drain(descriptor: ParcelFileDescriptor, token: AtomicBoolean) {
        try {
            FileInputStream(descriptor.fileDescriptor).use { input ->
                val buffer = ByteArray(32767)
                val poll = StructPollfd().apply { fd = descriptor.fileDescriptor; events = OsConstants.POLLIN.toShort() }
                var packets = 0L
                var bytes = 0L
                val events = ArrayDeque<Packet>()
                var lastPublish = 0L
                while (token.get()) {
                    if (Os.poll(arrayOf(poll), 500) > 0 && token.get()) {
                        val size = input.read(buffer)
                        if (size <= 0) break
                        packets++
                        bytes += size
                        PacketParser.parse(buffer, size)?.let { packet ->
                            if (events.size >= 40) events.removeLast()
                            events.addFirst(packet)
                        }
                    }
                    val now = android.os.SystemClock.elapsedRealtime()
                    if (token.get() && now - lastPublish >= 500) {
                        val old = FirewallStatus.mutable.value
                        if (old.active) FirewallStatus.mutable.value = old.copy(packets = packets, bytes = bytes, events = events.toList())
                        lastPublish = now
                    }
                }
            }
        } catch (e: Exception) {
            if (token.get()) android.os.Handler(mainLooper).post {
                if (running === token) { shutdown("VPN stopped: ${e.message}"); stopSelf() }
            }
        }
    }
    private fun shutdown(message: String) {
        running.set(false)
        worker?.interrupt()
        runCatching { tunnel?.close() }
        tunnel = null
        worker = null
        FirewallStatus.mutable.value = FirewallStatus.mutable.value.copy(active = false, message = message)
    }
    override fun onRevoke() {
        android.os.Handler(mainLooper).post { shutdown("VPN permission revoked"); stopSelf() }
        super.onRevoke()
    }
    override fun onDestroy() { shutdown(FirewallStatus.mutable.value.message.let { if (FirewallStatus.mutable.value.active) "Firewall is off" else it }); super.onDestroy() }
    private fun showNotification() {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel("firewall", "Firewall status", NotificationManager.IMPORTANCE_LOW))
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 1, Intent(this, FirewallService::class.java).setAction(STOP), PendingIntent.FLAG_IMMUTABLE)
        startForeground(1, Notification.Builder(this, "firewall").setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("Security Suite firewall").setContentText("Selected apps are blocked locally")
            .setContentIntent(open).setOngoing(true).addAction(Notification.Action.Builder(null, "Stop", stop).build()).build())
    }
    companion object { const val STOP = "org.suite.security.STOP" }
}
