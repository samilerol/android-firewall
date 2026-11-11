package org.suite.security

import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import android.system.Os
import java.io.RandomAccessFile

@RunWith(AndroidJUnit4::class)
class DeviceSmokeTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    @Test fun readsInstalledAppsAndOwnApkWithoutExecutingIt() {
        assertTrue(DeviceChecks.apps(context).any { it.packageName == context.packageName })
        val report = ApkAnalyzer.analyze(context, Uri.fromFile(File(context.applicationInfo.sourceDir)))
        assertTrue(report.contains(context.packageName))
        assertTrue(report.contains("SHA-256"))
        assertFalse(context.cacheDir.listFiles().orEmpty().any { it.name.startsWith("analysis-") })
    }
    @Test fun firewallRulesPersistLocally() {
        val before = Rules.load(context)
        try {
            Rules.save(context, setOf("org.example.blocked"), FirewallMode.BLOCK_ALL)
            assertEquals(FirewallRules(setOf("org.example.blocked"), FirewallMode.BLOCK_ALL), Rules.load(context))
        } finally { Rules.save(context, before.packages, before.mode) }
    }
    @Test fun failedRuleWriteDoesNotPublishUncommittedConfiguration() {
        val before = Rules.load(context)
        val directory = File(context.applicationInfo.dataDir, "shared_prefs")
        Rules.save(context, setOf("org.example.before"), FirewallMode.BLOCK_ALL)
        val mode = Os.stat(directory.path).st_mode and 0xfff
        try {
            assertTrue("Fault test requires an ordinary application UID", Os.getuid() >= 10000)
            Os.chmod(directory.path, mode and 0x92.inv()) // Remove write bits: real disk-write failure.
            val failure = runCatching { Rules.save(context, setOf("org.example.after")) }.exceptionOrNull()
            assertNotNull("Write failure was not reported", failure)
            assertEquals("Failed save changed the visible policy", FirewallRules(setOf("org.example.before"), FirewallMode.BLOCK_ALL), Rules.load(context))
        } finally {
            Os.chmod(directory.path, mode)
            Rules.save(context, before.packages, before.mode)
        }
    }
    @Test fun legacySelectionsRemainReadable() {
        val before = Rules.load(context)
        try {
            assertTrue(context.getSharedPreferences("firewall", 0).edit()
                .putStringSet("blocked", setOf("org.example.legacy")).remove("mode").commit())
            assertEquals(FirewallRules(setOf("org.example.legacy")), Rules.load(context))
        } finally { Rules.save(context, before.packages, before.mode) }
    }
    @Test fun invalidAndMissingApksFailWithoutLeavingCopies() {
        val file = File.createTempFile("invalid-fixture-", ".apk", context.cacheDir)
        try {
            file.writeText("not an APK archive")
            assertTrue(runCatching { ApkAnalyzer.analyze(context, Uri.fromFile(file)) }.isFailure)
            file.delete()
            assertTrue(runCatching { ApkAnalyzer.analyze(context, Uri.fromFile(file)) }.isFailure)
            assertFalse(context.cacheDir.listFiles().orEmpty().any { it.name.startsWith("analysis-") })
        } finally { file.delete() }
    }
    @Test fun oversizedApkIsRejectedBeforeMetadataParsing() {
        val file = File.createTempFile("oversize-fixture-", ".apk", context.cacheDir)
        try {
            RandomAccessFile(file, "rw").use { it.setLength(101L * 1024 * 1024) }
            val error = runCatching { ApkAnalyzer.analyze(context, Uri.fromFile(file)) }.exceptionOrNull()
            assertTrue("Expected size rejection, got $error", error is IllegalArgumentException && error.message?.contains("100 MiB") == true)
            assertFalse(context.cacheDir.listFiles().orEmpty().any { it.name.startsWith("analysis-") })
        } finally { file.delete() }
    }
}
