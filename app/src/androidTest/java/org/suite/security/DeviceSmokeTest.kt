package org.suite.security

import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

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
}
