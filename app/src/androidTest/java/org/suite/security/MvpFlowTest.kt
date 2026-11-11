package org.suite.security

import android.app.NotificationManager
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import androidx.lifecycle.ViewModelProvider
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.view.accessibility.AccessibilityNodeInfo
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Real accessibility/UI actions, without adding a production or test runtime dependency. */
@RunWith(AndroidJUnit4::class)
class MvpFlowTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val probe = "org.suite.firewallprobe"
    private var saved = FirewallRules(emptySet())
    @Before fun prepare() {
        saved = Rules.load(context)
        ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(
            "appops set ${context.packageName} ACTIVATE_VPN allow")).use { it.readBytes() }
        if (Build.VERSION.SDK_INT >= 33) shell("pm grant ${context.packageName} android.permission.POST_NOTIFICATIONS")
        assertNull(VpnService.prepare(context))
        stop()
        Rules.save(context, setOf(probe))
    }
    @After fun restore() {
        stop()
        Rules.save(context, saved.packages, saved.mode)
    }
    private fun shell(command: String) {
        ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(command)).use { it.readBytes() }
    }
    private fun stop() {
        context.startService(Intent(context, FirewallService::class.java).setAction(FirewallService.STOP))
        await("Service did not stop") { !FirewallStatus.state.value.running && !FirewallStatus.state.value.active }
    }
    private fun await(message: String, predicate: () -> Boolean) {
        val end = SystemClock.elapsedRealtime() + 60000
        while (SystemClock.elapsedRealtime() < end) {
            if (predicate()) return
            SystemClock.sleep(100)
        }
        fail("$message; nodes=${nodes().map { listOf(it.text, it.contentDescription, it.className, it.isEnabled, it.isVisibleToUser) }}")
    }

    private fun nodes(): List<AccessibilityNodeInfo> {
        val result = mutableListOf<AccessibilityNodeInfo>()
        fun visit(node: AccessibilityNodeInfo?) {
            if (node == null) return
            result.add(node)
            repeat(node.childCount) { visit(node.getChild(it)) }
        }
        visit(instrumentation.uiAutomation.rootInActiveWindow)
        return result
    }
    private fun text(value: String) = nodes().firstOrNull { it.text?.toString()?.equals(value, ignoreCase = true) == true && it.isVisibleToUser }
    private fun click(value: String) {
        var found: AccessibilityNodeInfo? = null
        await("Missing UI text: $value") { found = text(value); found != null }
        var node = requireNotNull(found)
        while (!node.isClickable && node.parent != null) node = node.parent
        assertTrue("Cannot click $value", node.performAction(AccessibilityNodeInfo.ACTION_CLICK))
    }
    private fun scrollTo(value: String, backwards: Boolean = false) {
        repeat(30) {
            if (text(value) != null) return
            val action = if (backwards) AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD else AccessibilityNodeInfo.ACTION_SCROLL_FORWARD
            nodes().firstOrNull { it.isScrollable && it.isVisibleToUser }?.performAction(action)
            SystemClock.sleep(700)
        }
        assertNotNull("Cannot scroll to $value; visible=${nodes().filter { it.isVisibleToUser }.map { it.text ?: it.contentDescription }}", text(value))
    }
    @Test fun draftModeSurvivesRecreationAndCancelDoesNotChangeProtection() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            click("Apps")
            click("Block all apps")
            await("Draft did not update") { nodes().any { it.text?.toString()?.startsWith("Every app loses network access.") == true } }
            assertEquals(FirewallRules(setOf(probe)), Rules.load(context))
            assertFalse(FirewallStatus.state.value.running)
            scenario.recreate()
            await("Draft mode lost on recreation") { nodes().any { it.text?.toString()?.startsWith("Every app loses network access.") == true } }
            scrollTo("Apply and start")
            click("Apply and start")
            click("Cancel")
            assertEquals(FirewallRules(setOf(probe)), Rules.load(context))
            assertFalse(FirewallStatus.state.value.running)
        }
    }
    @Test fun clearingLastSelectionRequiresConfirmationAndDoesNotActivateSafetyMode() {
        ActivityScenario.launch(MainActivity::class.java).use {
            click("Apps")
            await("Expected one selected app before editing") { nodes().any { it.text?.toString()?.startsWith("1 apps selected.") == true } }
            scrollTo("Review permissions")
            await("Labeled probe selection switch missing") { nodes().any { it.contentDescription?.toString() == "Block Firewall test probe" && it.isVisibleToUser } }
            val toggle = nodes().first { it.contentDescription?.toString() == "Block Firewall test probe" && it.isVisibleToUser }
            assertTrue(toggle.performAction(AccessibilityNodeInfo.ACTION_CLICK))
            await("App switch did not update its row") { nodes().any { it.text?.toString()?.startsWith("Not selected • UID") == true } }
            scrollTo("Clear rules and stop", backwards = true)
            assertEquals(setOf(probe), Rules.blocked(context))
            click("Clear rules and stop")
            click("Cancel")
            assertEquals(setOf(probe), Rules.blocked(context))
            click("Clear rules and stop")
            click("Clear and stop")
            await("Clear action did not complete") { Rules.blocked(context).isEmpty() && !FirewallStatus.state.value.running }
            assertFalse(FirewallStatus.state.value.active)
            assertFalse(FirewallStatus.state.value.quarantine)
        }
    }
    @Test fun explicitAllAppConfirmationStartsAndStopsTheRealVpn() {
        ActivityScenario.launch(MainActivity::class.java).use {
            click("Apps")
            click("Block all apps")
            scrollTo("Apply and start")
            click("Apply and start")
            await("All-app confirmation missing") { text("Block every application's internet?") != null }
            click("Block all apps")
            await("Explicit all-app VPN not ready") { FirewallStatus.state.value.active }
            assertEquals(FirewallMode.BLOCK_ALL, Rules.load(context).mode)
            assertFalse(FirewallStatus.state.value.quarantine)
            click("Overview")
            await("Stop must be visible without scrolling") { text("Stop firewall") != null }
            click("Stop firewall")
            await("Stop control failed") { !FirewallStatus.state.value.running }
        }
    }
    @Test fun freshEmptySelectionCannotStartAllAppBlocking() {
        Rules.save(context, emptySet())
        ActivityScenario.launch(MainActivity::class.java).use {
            await("Start button missing") { text("Start blocking") != null }
            var control = text("Start blocking")!!
            var disabled = !control.isEnabled
            val ancestry = mutableListOf<String>()
            repeat(12) {
                ancestry.add("${control.className}:${control.isEnabled}")
                disabled = disabled || !control.isEnabled
                control.parent?.let { control = it }
            }
            assertTrue("Start control is not disabled: $ancestry", disabled)
            assertFalse(FirewallStatus.state.value.running)
            scrollTo("Refresh device checks")
            click("Refresh device checks")
            val signals = DeviceChecks.rootSignals()
            scrollTo("Root indicators")
            await("Root heuristic result not rendered") {
                text(if (signals.isEmpty()) "No selected indicators visible" else "${signals.size} heuristic indicators found") != null
            }
            scrollTo("Select apps", backwards = true)
            click("Select apps")
            await("Empty selection action missing") { text("Clear rules and stop") != null }
        }
    }
    @Test fun searchSystemInternetFiltersAndPermissionsAreUsable() {
        val candidate = DeviceChecks.apps(context).first { it.system && it.packageName.contains('.') && it.permissions.isNotEmpty() && "android.permission.INTERNET" !in it.permissions }
        ActivityScenario.launch(MainActivity::class.java).use {
            click("Apps")
            scrollTo("Search name or package")
            await("Search field missing") { nodes().any { it.isEditable && it.isVisibleToUser } }
            val field = nodes().first { it.isEditable && it.isVisibleToUser }
            assertTrue(field.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, Bundle().apply {
                putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, candidate.packageName)
            }))
            scrollTo("No matching applications. Adjust your search or app filters.")
            scrollTo("Show system apps", backwards = true)
            click("Show system apps")
            scrollTo("No matching applications. Adjust your search or app filters.")
            scrollTo("Internet apps only", backwards = true)
            click("Internet apps only")
            scrollTo(candidate.packageName)
            scrollTo("Review permissions")
            click("Review permissions")
            await("Permission expansion did not update its control") { text("Hide permissions") != null }
            val permission = candidate.permissions.first()
            scrollTo("${if (permission in candidate.granted) "Granted" else "Not granted"} • $permission")
            assertEquals(FirewallRules(setOf(probe)), Rules.load(context))
            assertFalse(FirewallStatus.state.value.running)
            click("Overview")
            await("Overview did not reset to its controls") { text("Start blocking") != null }
        }
    }
    @Test fun apkAnalysisCancelsClosesPipeAndRecoversFromInvalidInput() {
        val invalid = File.createTempFile("ui-invalid-", ".apk", context.cacheDir).apply { writeText("invalid APK") }
        try {
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                click("APK")
                lateinit var model: SuiteModel
                scenario.onActivity { activity ->
                    model = ViewModelProvider(activity)[SuiteModel::class.java]
                    model.analyze(context, Uri.parse("content://org.suite.firewallprobe.documents/slow-apk"))
                }
                await("Cancel action missing") { text("Cancel analysis") != null }
                click("Cancel analysis")
                await("Cancellation did not complete") { text("Analysis cancelled.") != null }
                await("Provider writer leaked") {
                    context.contentResolver.query(Uri.parse("content://org.suite.firewallprobe.documents/status"), null, null, null, null)!!.use { it.moveToFirst() && it.getInt(0) == 0 }
                }
                assertFalse(context.cacheDir.listFiles().orEmpty().any { it.name.startsWith("analysis-") })
                scenario.onActivity { model.analyze(context, Uri.fromFile(invalid)) }
                await("Invalid APK error not shown") { nodes().any { it.text?.toString()?.startsWith("Analysis failed:") == true } }
                scenario.onActivity { model.analyze(context, Uri.parse("content://org.suite.firewallprobe.documents/apk")) }
                await("Valid APK could not be analyzed after error/cancel") {
                    nodes().any { it.text?.toString()?.let { value -> value.contains(probe) && value.contains("SHA-256") } == true } && !model.analyzing
                }
                assertFalse(context.cacheDir.listFiles().orEmpty().any { it.name.startsWith("analysis-") })
            }
        } finally { invalid.delete() }
    }
    @Test fun documentPickerCancelOrMissingHandlerLeavesAppUsable() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*")
        ActivityScenario.launch(MainActivity::class.java).use {
            click("APK")
            click("Choose APK")
            if (intent.resolveActivity(context.packageManager) == null) {
                await("Missing document provider was not explained") { text("Cannot open document picker. Enable a document provider and retry.") != null }
            } else {
                await("Document picker did not open") { nodes().any { it.packageName?.toString() != context.packageName } }
                shell("input keyevent 4")
                await("Cancel did not return to APK screen") { text("Choose APK") != null }
            }
            assertFalse(FirewallStatus.state.value.running)
        }
    }
    @Test fun vpnSettingsRoundTripPreservesProtection() {
        ActivityScenario.launch(MainActivity::class.java).use {
            click("Start blocking")
            await("VPN not ready") { FirewallStatus.state.value.active }
            scrollTo("Open Android VPN settings")
            click("Open Android VPN settings")
            if (Intent(android.provider.Settings.ACTION_VPN_SETTINGS).resolveActivity(context.packageManager) == null) {
                await("Missing settings handler was not explained") { text("Open Android Settings → Network → VPN manually.") != null }
            } else {
                await("VPN settings did not open") { nodes().any { it.packageName?.toString() == "com.android.settings" } }
                shell("input keyevent 4")
                await("Did not return from Settings") { nodes().any { it.packageName?.toString() == context.packageName } }
                scrollTo("Stop firewall", backwards = true)
            }
            assertTrue(FirewallStatus.state.value.active)
            assertEquals(setOf(probe), FirewallStatus.state.value.appliedPackages)
        }
    }
    @Test fun notificationStopInvokesItsRealPendingIntent() {
        ActivityScenario.launch(MainActivity::class.java).use {
            click("Start blocking")
            await("VPN not ready") { FirewallStatus.state.value.active }
            val manager = context.getSystemService(NotificationManager::class.java)
            val action = manager.activeNotifications.single { it.id == 1 }.notification.actions.single { it.title.toString() == "Stop VPN" }
            action.actionIntent.send()
            await("Notification Stop failed") { !FirewallStatus.state.value.running && !FirewallStatus.state.value.active }
        }
    }
    @Test fun capturedTrafficIsRenderedOnActivityScreen() {
        ActivityScenario.launch(MainActivity::class.java).use {
            click("Start blocking")
            await("VPN not ready") { FirewallStatus.state.value.active }
            click("Activity")
            await("Activity tab did not open") { text("Blocked network activity") != null }
            val latch = CountDownLatch(1)
            var code = -1
            var error: String? = null
            context.sendOrderedBroadcast(Intent().addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES or Intent.FLAG_RECEIVER_FOREGROUND)
                .setComponent(ComponentName(probe, "$probe.ProbeReceiver"))
                .putExtra("kind", "tcp").putExtra("host", "10.0.2.2").putExtra("port", 18080)
                .putExtra("nonce", "blocked-ui-activity-${SystemClock.elapsedRealtime()}"), null,
                object : BroadcastReceiver() { override fun onReceive(context: Context?, intent: Intent?) { code = resultCode; error = resultData; latch.countDown() } }, null, -1, null, null)
            try {
                await("TCP metadata was not rendered") { text("10.0.2.2:18080") != null }
            } finally { assertTrue(latch.await(30, TimeUnit.SECONDS)) }
            assertEquals(0, code)
            assertTrue("Unexpected fixture failure: $error", error in setOf("SocketTimeoutException", "ConnectException", "SocketException"))
            assertTrue(FirewallStatus.state.value.packets > 0)
        }
    }
    @Test fun declinedVpnConsentNeverClaimsProtection() {
        shell("appops set ${context.packageName} ACTIVATE_VPN deny")
        val consent = VpnService.prepare(context)
        assertNotNull(consent)
        ActivityScenario.launch(MainActivity::class.java).use {
            click("Start blocking")
            if (consent!!.resolveActivity(context.packageManager) == null) {
                await("Missing VPN consent handler did not produce an error") { text("Cannot open VPN authorization. Enable Android VPN dialogs and retry.") != null }
            } else {
                click("Cancel")
                await("Declined VPN consent not reported") { text("VPN permission declined. Firewall remains off.") != null }
            }
            assertFalse(FirewallStatus.state.value.active)
            assertFalse(FirewallStatus.state.value.running)
        }
    }

    @Test fun documentPickerReadsRealDownloadedApkAndReturnsReport() {
        val picker = Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*")
        ActivityScenario.launch(MainActivity::class.java).use {
            click("APK")
            click("Choose APK")
            if (picker.resolveActivity(context.packageManager) == null) {
                await("Missing picker was not explained") { text("Cannot open document picker. Enable a document provider and retry.") != null }
            } else {
                await("Picker not ready") { text("firewall-fixture.apk") != null || nodes().any { node -> node.contentDescription?.toString()?.let { value -> value.contains("roots", true) || value.contains("drawer", true) } == true } }
                if (text("firewall-fixture.apk") == null) {
                    val menu = nodes().first { node -> node.contentDescription?.toString()?.let { value -> value.contains("roots", true) || value.contains("drawer", true) } == true }
                    assertTrue(menu.performAction(AccessibilityNodeInfo.ACTION_CLICK))
                    click("Downloads")
                }
                click("firewall-fixture.apk")
                await("Picker URI was not analyzed") { nodes().any { node -> node.text?.toString()?.let { value -> value.contains(probe) && value.contains("SHA-256") } == true } }
                assertFalse(context.cacheDir.listFiles().orEmpty().any { file -> file.name.startsWith("analysis-") })
            }
        }
    }

}
