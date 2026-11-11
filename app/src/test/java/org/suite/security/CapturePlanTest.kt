package org.suite.security

import org.junit.Assert.*
import org.junit.Test

class CapturePlanTest {
    private val own = "firewall"
    @Test fun selectedApplicationsDoNotCaptureOtherInstalledApplications() {
        val plan = CapturePlan.resolve(FirewallRules(setOf("blocked", own)), setOf("blocked", "allowed", own), own)
        assertEquals(setOf("blocked"), plan.packages)
        assertFalse(plan.captureAll)
        assertFalse(plan.quarantine)
    }
    @Test fun missingSelectionCannotSilentlyBecomeUnblocked() {
        val plan = CapturePlan.resolve(FirewallRules(setOf("installed", "removed")), setOf("installed"), own)
        assertTrue(plan.captureAll)
        assertTrue(plan.quarantine)
        assertTrue(plan.packages.isEmpty())
    }
    @Test fun emptyAlwaysOnConfigurationStillQuarantines() {
        val plan = CapturePlan.resolve(FirewallRules(emptySet()), emptySet(), own)
        assertTrue(plan.captureAll)
        assertTrue(plan.quarantine)
    }
    @Test fun selectingOnlyTheFirewallCannotCreateAnEmptyApplicationListBypass() {
        assertTrue(CapturePlan.resolve(FirewallRules(setOf(own)), setOf(own), own).quarantine)
    }
    @Test fun intentionalAllAppModeDoesNotMasqueradeAsAnError() {
        val plan = CapturePlan.resolve(FirewallRules(setOf("removed"), FirewallMode.BLOCK_ALL), emptySet(), own)
        assertTrue(plan.captureAll)
        assertFalse(plan.quarantine)
        assertTrue(plan.packages.isEmpty())
    }
}
