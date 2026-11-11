package org.suite.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import java.io.File

object SecurityPolicy {
    val sensitive = setOf("CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "READ_CONTACTS", "READ_SMS", "SEND_SMS", "READ_CALL_LOG", "READ_PHONE_STATE", "READ_MEDIA_IMAGES", "READ_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE", "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "BIND_ACCESSIBILITY_SERVICE", "BIND_VPN_SERVICE", "PACKAGE_USAGE_STATS")
    fun sensitivePermissions(permissions: List<String>) = permissions.filter { it.substringAfterLast('.') in sensitive }
    fun apkSignals(debuggable: Boolean, cleartext: Boolean, target: Int, permissions: List<String>): List<String> = buildList {
        if (debuggable) add("Debuggable build: debugging may expose application state.")
        if (cleartext) add("Manifest permits cleartext traffic; network security configuration may override this.")
        if (target < 28) add("Legacy target SDK $target: fewer modern platform protections.")
        val count = sensitivePermissions(permissions).size
        if (count > 0) add("$count sensitive permission declarations. Declarations do not prove use or grants.")
    }
}
data class AppRecord(val label: String, val packageName: String, val uid: Int, val system: Boolean, val permissions: List<String>, val granted: Set<String>)
object DeviceChecks {
    @Suppress("DEPRECATION")
    fun apps(context: Context): List<AppRecord> = context.packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS).map { info ->
        val app = info.applicationInfo
        val permissions = info.requestedPermissions?.toList().orEmpty()
        AppRecord(app?.loadLabel(context.packageManager)?.toString() ?: info.packageName, info.packageName,
            app?.uid ?: -1, (app?.flags ?: 0) and ApplicationInfo.FLAG_SYSTEM != 0, permissions,
            permissions.filterIndexed { i, _ -> ((info.requestedPermissionsFlags?.getOrNull(i) ?: 0) and android.content.pm.PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0 }.toSet())
    }.sortedBy { it.label.lowercase() }

    fun rootSignals(): List<String> = buildList {
        val paths = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/sbin/.magisk", "/data/adb/magisk", "/system/app/Superuser.apk")
        paths.filter { File(it).exists() }.forEach { add("Artifact visible: $it") }
        if (Build.TAGS?.contains("test-keys") == true) add("Build signed with test keys (also common on development ROMs)")
    }
}
