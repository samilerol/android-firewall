package org.suite.security

import android.content.Context

enum class FirewallMode { SELECTED_APPS, BLOCK_ALL }

data class FirewallRules(val packages: Set<String>, val mode: FirewallMode = FirewallMode.SELECTED_APPS)

object Rules {
    @Synchronized fun load(context: Context): FirewallRules {
        return decode(context.getSharedPreferences("firewall", Context.MODE_PRIVATE).all)
    }
    internal fun decode(values: Map<String, *>): FirewallRules {
        val storedPackages = values["blocked"]
        val storedMode = FirewallMode.entries.firstOrNull { it.name == values["mode"] }
        // Missing mode is the supported legacy schema. Present but invalid fields
        // must never silently narrow capture by dropping entries or changing modes.
        if ((values.containsKey("mode") && storedMode == null) ||
            (values.containsKey("blocked") &&
                (storedPackages !is Set<*> || storedPackages.any { it !is String }))) {
            return FirewallRules(emptySet()) // CapturePlan turns this into all-app quarantine.
        }
        val packages = (storedPackages as? Set<*>)?.filterIsInstance<String>()?.toSet().orEmpty()
        return FirewallRules(packages, storedMode ?: FirewallMode.SELECTED_APPS)
    }
    fun blocked(context: Context): Set<String> = load(context).packages
    @Synchronized fun save(context: Context, packages: Set<String>, mode: FirewallMode = FirewallMode.SELECTED_APPS) {
        // Commit both fields together before a service can apply them. Surface storage failure.
        val preferences = context.getSharedPreferences("firewall", Context.MODE_PRIVATE)
        val previous = load(context)
        if (!preferences.edit().putStringSet("blocked", packages.toSet()).putString("mode", mode.name).commit()) {
            // SharedPreferences commits to memory BEFORE disk, even when commit() returns false.
            // Readers share this monitor so an uncommitted policy cannot escape before rollback.
            val restoredOnDisk = preferences.edit().putStringSet("blocked", previous.packages)
                .putString("mode", previous.mode.name).commit()
            error(if (restoredOnDisk) "Cannot save new rules; previous rules restored. Retry."
                else "Cannot save rules; previous in-memory rules restored. Free storage and retry.")
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
