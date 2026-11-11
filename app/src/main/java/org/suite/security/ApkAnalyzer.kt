package org.suite.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.CancellationSignal
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

object ApkAnalyzer {
    private const val MAX_BYTES = 100L * 1024 * 1024
    @Suppress("DEPRECATION")
    fun analyze(context: Context, uri: Uri, cancellation: CancellationSignal? = null): String {
        cancellation?.throwIfCanceled()
        val file = File.createTempFile("analysis-", ".apk", context.cacheDir)
        try {
            val digest = MessageDigest.getInstance("SHA-256")
            var total = 0L
            context.contentResolver.openAssetFileDescriptor(uri, "r", cancellation)?.use { asset ->
                asset.createInputStream().use { input ->
                    cancellation?.setOnCancelListener { runCatching { input.close() } }
                    try {
                        file.outputStream().use { output ->
                            val buffer = ByteArray(16384)
                            while (true) {
                                cancellation?.throwIfCanceled()
                                val size = input.read(buffer)
                                if (size < 0) break
                                total += size
                                require(total <= MAX_BYTES) { "APK exceeds the 100 MiB analysis limit" }
                                digest.update(buffer, 0, size)
                                output.write(buffer, 0, size)
                            }
                        }
                    } finally { cancellation?.setOnCancelListener(null) }
                }
            } ?: error("Cannot open the selected document")
            cancellation?.throwIfCanceled()
            ArchiveLimits.check(file)
            var dex = 0
            var native = 0
            var entries = 0
            ZipFile(file).use { zip ->
                val iterator = zip.entries()
                while (iterator.hasMoreElements()) {
                    cancellation?.throwIfCanceled()
                    val entry = iterator.nextElement()
                    require(++entries <= 20000) { "Too many archive entries" }
                    if (entry.name == "AndroidManifest.xml") {
                        require(entry.size in 1..(4L * 1024 * 1024)) { "Manifest exceeds safe metadata analysis limits" }
                    }
                    if (entry.name.matches(Regex("classes[0-9]*\\.dex"))) dex++
                    if (entry.name.startsWith("lib/") && entry.name.endsWith(".so")) native++
                }
            }
            cancellation?.throwIfCanceled()
            val info = context.packageManager.getPackageArchiveInfo(file.path, PackageManager.GET_PERMISSIONS or (if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES))
                ?: error("Not a readable Android APK (split bundles are unsupported)")
            cancellation?.throwIfCanceled()
            val app = info.applicationInfo ?: error("APK has no application metadata")
            val permissions = info.requestedPermissions?.toList().orEmpty()
            val signals = SecurityPolicy.apkSignals(app.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0,
                app.flags and ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC != 0, app.targetSdkVersion, permissions)
            val signers = if (Build.VERSION.SDK_INT >= 28) info.signingInfo?.apkContentsSigners else info.signatures
            val certificates = signers.orEmpty().map { sig ->
                MessageDigest.getInstance("SHA-256").digest(sig.toByteArray()).joinToString("") { "%02x".format(it) }
            }
            return buildString {
                appendLine("${info.packageName} • ${info.versionName ?: "unknown version"}")
                appendLine("Target SDK ${app.targetSdkVersion} • Min SDK ${app.minSdkVersion}")
                appendLine("$total bytes • $dex DEX files • $native native libraries")
                appendLine("\nSHA-256\n${digest.digest().joinToString("") { "%02x".format(it) }}")
                appendLine("\nSigner certificate SHA-256 (metadata, not independent signature verification)")
                appendLine(certificates.joinToString("\n").ifEmpty { "Unavailable" })
                appendLine("\nManifest indicators")
                appendLine(signals.joinToString("\n").ifEmpty { "No selected manifest indicators found." })
                appendLine("\nDeclared permissions (${permissions.size})")
                appendLine(permissions.joinToString("\n").ifEmpty { "None" })
                appendLine("\nStatic metadata only. Not malware detection, code auditing, or a guarantee of safety. Nothing is installed or executed.")
            }
        } finally { file.delete() }
    }
}
