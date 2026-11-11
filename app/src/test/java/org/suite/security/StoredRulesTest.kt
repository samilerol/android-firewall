package org.suite.security

import org.junit.Assert.*
import org.junit.Test

class StoredRulesTest {
    private fun assertQuarantine(values: Map<String, *>) {
        val plan = CapturePlan.resolve(Rules.decode(values), setOf("blocked", "allowed"), "firewall")
        assertTrue("Corrupt storage narrowed capture: $values", plan.captureAll)
        assertTrue("Corrupt storage must be visible as safety mode", plan.quarantine)
    }
    @Test fun unknownModeCannotNarrowAllAppPolicy() {
        assertQuarantine(mapOf("mode" to "BLOCK_ALL_CORRUPT", "blocked" to setOf("blocked")))
    }
    @Test fun wrongModeTypeCannotNarrowPolicy() {
        assertQuarantine(mapOf("mode" to 42, "blocked" to setOf("blocked")))
    }
    @Test fun mixedSelectionTypesCannotSilentlyDropEntries() {
        assertQuarantine(mapOf("mode" to "SELECTED_APPS", "blocked" to setOf("blocked", 42)))
    }
    @Test fun wrongSelectionContainerQuarantines() {
        assertQuarantine(mapOf("blocked" to "blocked"))
    }
    @Test fun legacyModeAndValidExplicitModesRemainCompatible() {
        assertEquals(FirewallRules(setOf("blocked")), Rules.decode(mapOf("blocked" to setOf("blocked"))))
        for (mode in FirewallMode.entries) assertEquals(FirewallRules(setOf("blocked"), mode),
            Rules.decode(mapOf("blocked" to setOf("blocked"), "mode" to mode.name)))
    }
}
