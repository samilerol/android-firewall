package org.suite.security

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.EOFException
import java.util.concurrent.atomic.AtomicBoolean

data class FirewallState(
    val active: Boolean = false, val packets: Long = 0, val bytes: Long = 0,
    val events: List<Packet> = emptyList(), val message: String = "Firewall is off",
    val monitoring: Boolean = false, val quarantine: Boolean = false,
    val alwaysOn: Boolean? = null, val lockdown: Boolean? = null
)
object FirewallStatus {
    internal val mutable = MutableStateFlow(FirewallState())
    val state = mutable.asStateFlow()
}
object Rules {
    fun blocked(context: Context): Set<String> = context.getSharedPreferences("firewall", Context.MODE_PRIVATE).getStringSet("blocked", emptySet())!!.toSet()
    fun save(context: Context, packages: Set<String>) { context.getSharedPreferences("firewall", Context.MODE_PRIVATE).edit().putStringSet("blocked", packages.toSet()).apply() }
}

/** Sink only. Process-death protection requires Android Always-on AND Lockdown. */
class FirewallService : VpnService() {
    private class Session(val tunnel: ParcelFileDescriptor) {
        val running = AtomicBoolean(true)
        var worker: Thread? = null
    }
    private val lock = Any()
    private var session: Session? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == STOP) {
            shutdown("Firewall stopped. Android Lockdown, if enabled, still blocks network access.")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        if (intent?.action == STATUS && session != null) {
            synchronized(lock) { FirewallStatus.mutable.value = protection(FirewallStatus.mutable.value) }
            return START_STICKY
        }
        try {
            showNotification()
            val blocked = Rules.blocked(this) - packageName
            // Resolve the complete set first. Missing rules must never silently become bypasses.
            val installed = blocked.filter { name ->
                try { @Suppress("DEPRECATION") packageManager.getApplicationInfo(name, 0); true }
                catch (_: android.content.pm.PackageManager.NameNotFoundException) { false }
            }.toSet()
            val quarantine = installed.isEmpty() || installed != blocked
            val builder = Builder().setSession("Android Firewall • local packet sink").setMtu(1500)
                .addAddress("10.111.0.1", 32).addRoute("0.0.0.0", 0)
                .addAddress("fd42:4242::1", 128).addRoute("::", 0)
                .addDnsServer("192.0.2.1").setBlocking(true)
            // No application list means capture every app: safe startup for Always-on,
            // empty rules, or an uninstalled rule target. No forwarding or bypass API.
            if (!quarantine) installed.forEach { builder.addAllowedApplication(it) }
            // Android replaces the old interface only after successful establishment.
            // Never close our old descriptor before this call succeeds.
            val descriptor = builder.establish() ?: error("VPN permission is unavailable")
            val next = Session(descriptor)
            synchronized(lock) {
                val previous = session
                session = next
                previous?.let { close(it) }
                FirewallStatus.mutable.value = protection(FirewallState(
                    active = true, monitoring = true, quarantine = quarantine,
                    message = if (quarantine) "Safety mode: ALL apps blocked. Select installed apps to narrow rules."
                        else "Blocking ${installed.size} selected apps"
                ))
            }
            try {
                // The reader owns a duplicate, never the descriptor keeping the VPN alive.
                val reader = ParcelFileDescriptor.dup(descriptor.fileDescriptor)
                val thread = Thread({ drain(next, reader) }, "firewall-packets")
                next.worker = thread
                try { thread.start() } catch (e: Exception) { reader.close(); throw e }
            } catch (_: Exception) { monitoringStopped(next) }
        } catch (_: Exception) {
            synchronized(lock) {
                val old = FirewallStatus.mutable.value
                FirewallStatus.mutable.value = protection(old.copy(message = if (session != null)
                    "Rule update failed; previous rules remain. New selections are NOT confirmed blocked."
                    else "Cannot establish VPN. Only Android Lockdown can prevent network bypass."))
            }
            // Keep foreground service and any previous tunnel; Android can retry Always-on.
        }
        return START_STICKY
    }

    private fun protection(state: FirewallState) = state.copy(
        alwaysOn = if (Build.VERSION.SDK_INT >= 29) isAlwaysOn else null,
        lockdown = if (Build.VERSION.SDK_INT >= 29) isLockdownEnabled else null
    )

    private fun drain(owner: Session, reader: ParcelFileDescriptor) {
        try {
            ParcelFileDescriptor.AutoCloseInputStream(reader).use { input ->
                val buffer = ByteArray(32767)
                val poll = StructPollfd().apply { fd = reader.fileDescriptor; events = OsConstants.POLLIN.toShort() }
                var packets = 0L
                var bytes = 0L
                val events = ArrayDeque<Packet>()
                var lastPublish = 0L
                while (owner.running.get()) {
                    if (Os.poll(arrayOf(poll), 500) > 0 && owner.running.get()) {
                        val errors = OsConstants.POLLERR or OsConstants.POLLHUP or OsConstants.POLLNVAL
                        if (poll.revents.toInt() and errors != 0) throw EOFException("TUN closed")
                        if (poll.revents.toInt() and OsConstants.POLLIN != 0) {
                            val size = input.read(buffer)
                            if (size <= 0) throw EOFException("TUN EOF")
                            packets++
                            bytes += size
                            PacketParser.parse(buffer, size)?.let { packet ->
                                if (events.size >= 40) events.removeLast()
                                events.addFirst(packet)
                            }
                        }
                    }
                    val now = android.os.SystemClock.elapsedRealtime()
                    if (now - lastPublish >= 500) {
                        synchronized(lock) {
                            if (session === owner && owner.running.get()) {
                                FirewallStatus.mutable.value = FirewallStatus.mutable.value.copy(
                                    packets = packets, bytes = bytes, events = events.toList())
                            }
                        }
                        lastPublish = now
                    }
                }
            }
        } catch (_: Exception) {
            // Retain original TUN descriptor: a monitoring failure must not release routing.
        } finally { monitoringStopped(owner) }
    }

    private fun monitoringStopped(owner: Session) = synchronized(lock) {
        if (session === owner && owner.running.get()) {
            FirewallStatus.mutable.value = FirewallStatus.mutable.value.copy(monitoring = false,
                message = "VPN interface retained; packet monitoring unavailable. Verify Android Lockdown.")
        }
    }
    private fun close(owner: Session) {
        owner.running.set(false)
        runCatching { owner.tunnel.close() }
        owner.worker?.interrupt()
    }
    private fun shutdown(message: String) = synchronized(lock) {
        session?.let { close(it) }
        session = null
        FirewallStatus.mutable.value = protection(FirewallState(message = message))
    }
    override fun onRevoke() {
        shutdown("VPN permission revoked. Only Android Lockdown can prevent network bypass.")
        stopSelf()
        super.onRevoke()
    }
    override fun onDestroy() {
        shutdown("VPN service stopped. Only Android Lockdown can prevent network bypass.")
        super.onDestroy()
    }
    private fun showNotification() {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel("firewall", "Firewall status", NotificationManager.IMPORTANCE_LOW))
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        startForeground(1, Notification.Builder(this, "firewall").setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("Android Firewall").setContentText("Open to check VPN and Android Lockdown status")
            .setContentIntent(open).setOngoing(true).build())
    }
    companion object {
        const val STOP = "org.suite.security.STOP"
        const val STATUS = "org.suite.security.STATUS"
    }
}
