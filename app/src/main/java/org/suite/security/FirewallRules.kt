package org.suite.security

import android.content.Context

enum class FirewallMode { SELECTED_APPS, BLOCK_ALL }

data class FirewallRules(val packages: Set<String>, val mode: FirewallMode = FirewallMode.SELECTED_APPS)

object Rules {
    fun load(context: Context): FirewallRules {
        val values = context.getSharedPreferences("firewall", Context.MODE_PRIVATE).all
        val packages = (values["blocked"] as? Set<*>)?.filterIsInstance<String>()?.toSet().orEmpty()
        val mode = FirewallMode.entries.firstOrNull { it.name == values["mode"] } ?: FirewallMode.SELECTED_APPS
        return FirewallRules(packages, mode)
    }
    fun blocked(context: Context): Set<String> = load(context).packages
    fun save(context: Context, packages: Set<String>, mode: FirewallMode = FirewallMode.SELECTED_APPS) {
        // Commit both fields together before a service can apply them. Surface storage failure.
        check(context.getSharedPreferences("firewall", Context.MODE_PRIVATE).edit()
            .putStringSet("blocked", packages.toSet()).putString("mode", mode.name).commit()) {
            "Cannot save firewall rules. Previous protection remains; retry after freeing storage."
        }
    }
}

/** Empty/missing rules from Android Always-on still fail into quarantine, never bypass. */
data class CapturePlan(val captureAll: Boolean, val quarantine: Boolean, val packages: Set<String>) {
    companion object {
        fun resolve(rules: FirewallRules, installed: Set<String>, ownPackage: String): CapturePlan {
            val selected = rules.packages - ownPackage
            val missing = selected - installed
            val quarantine = rules.mode != FirewallMode.BLOCK_ALL && (selected.isEmpty() || missing.isNotEmpty())
            val captureAll = rules.mode == FirewallMode.BLOCK_ALL || quarantine
            return CapturePlan(captureAll, quarantine, if (captureAll) emptySet() else selected)
        }
    }
}
