package org.suite.security

import android.content.Intent
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
        assertNull(VpnService.prepare(context))
        stop()
        Rules.save(context, setOf(probe))
    }
    @After fun restore() {
        stop()
        Rules.save(context, saved.packages, saved.mode)
    }
    private fun stop() {
        context.startService(Intent(context, FirewallService::class.java).setAction(FirewallService.STOP))
        await("Service did not stop") { !FirewallStatus.state.value.running && !FirewallStatus.state.value.active }
    }
    private fun await(message: String, predicate: () -> Boolean) {
        val end = SystemClock.elapsedRealtime() + 60000
        while (!predicate() && SystemClock.elapsedRealtime() < end) SystemClock.sleep(100)
        if (!predicate()) fail("$message; nodes=${nodes().map { listOf(it.text, it.contentDescription, it.className, it.isChecked, it.isVisibleToUser) }}")
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
    private fun text(value: String) = nodes().firstOrNull { it.text?.toString() == value && it.isVisibleToUser }
    private fun click(value: String) {
        await("Missing UI text: $value") { text(value) != null }
        var node = text(value)!!
        while (!node.isClickable && node.parent != null) node = node.parent
        assertTrue("Cannot click $value", node.performAction(AccessibilityNodeInfo.ACTION_CLICK))
    }
    private fun scrollTo(value: String, backwards: Boolean = false) {
        repeat(12) {
            if (text(value) != null) return
            val action = if (backwards) AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD else AccessibilityNodeInfo.ACTION_SCROLL_FORWARD
            nodes().firstOrNull { it.isScrollable && it.isVisibleToUser }?.performAction(action)
            SystemClock.sleep(300)
        }
        assertNotNull("Cannot scroll to $value", text(value))
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
            scrollTo("Review permissions")
            await("Labeled probe selection switch missing") { nodes().any { it.contentDescription?.toString() == "Block Firewall test probe" && it.isVisibleToUser } }
            val toggle = nodes().first { it.contentDescription?.toString() == "Block Firewall test probe" && it.isVisibleToUser }
            assertTrue(toggle.performAction(AccessibilityNodeInfo.ACTION_CLICK))
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
}
