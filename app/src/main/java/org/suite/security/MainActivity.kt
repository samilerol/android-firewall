package org.suite.security

import android.Manifest
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.Saver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class SuiteModel : ViewModel() {
    var apps by mutableStateOf<List<AppRecord>>(emptyList())
    var loading by mutableStateOf(false)
    var error by mutableStateOf<String?>(null)
    var root by mutableStateOf<List<String>?>(null)
    var report by mutableStateOf("Choose an APK document for local metadata analysis. Maximum 100 MiB; no upload, installation, or execution.")
    var analyzing by mutableStateOf(false)
    fun refresh(context: android.content.Context) {
        if (loading) return
        loading = true
        viewModelScope.launch {
            runCatching { withContext(Dispatchers.IO) { DeviceChecks.apps(context) to DeviceChecks.rootSignals() } }
                .onSuccess { apps = it.first; root = it.second; error = null }
                .onFailure { error = "Cannot read device data: ${it.message}" }
            loading = false
        }
    }
    fun analyze(context: android.content.Context, uri: android.net.Uri) {
        if (analyzing) return
        analyzing = true
        viewModelScope.launch {
            report = runCatching { withContext(Dispatchers.IO) { ApkAnalyzer.analyze(context, uri) } }
                .getOrElse { "Analysis failed: ${it.message}" }
            analyzing = false
        }
    }
}
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            val colors = darkColorScheme(primary = Color(0xFF78E0C0), secondary = Color(0xFFA9BDFA), background = Color(0xFF0D141C), surface = Color(0xFF17212D))
            MaterialTheme(colorScheme = colors) { Suite() }
        }
    }
    @OptIn(ExperimentalMaterial3Api::class)
    @Composable private fun Suite(model: SuiteModel = viewModel()) {
        val context = applicationContext
        val status by FirewallStatus.state.collectAsStateWithLifecycle()
        var savedRules by remember { mutableStateOf(Rules.load(context)) }
        val packageSaver = remember { Saver<Set<String>, ArrayList<String>>(save = { ArrayList(it) }, restore = { it.toSet() }) }
        var blocked by rememberSaveable(stateSaver = packageSaver) { mutableStateOf(savedRules.packages) }
        var mode by rememberSaveable { mutableStateOf(savedRules.mode) }
        val pending = blocked != savedRules.packages || mode != savedRules.mode
        var saving by remember { mutableStateOf(false) }
        var confirmation by remember { mutableStateOf<String?>(null) }
        val scope = rememberCoroutineScope()
        var tab by rememberSaveable { mutableIntStateOf(0) }
        var query by rememberSaveable { mutableStateOf("") }
        var expanded by remember { mutableStateOf<String?>(null) }
        var showSystem by rememberSaveable { mutableStateOf(false) }
        var internetOnly by rememberSaveable { mutableStateOf(true) }
        var consentMessage by remember { mutableStateOf<String?>(null) }
        val notifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }
        fun startFirewall() {
            runCatching {
                startForegroundService(Intent(context, FirewallService::class.java))
                if (Build.VERSION.SDK_INT >= 33) notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
            }.onFailure { consentMessage = "Cannot start firewall: ${it.message}" }
        }
        fun stopFirewall() { startService(Intent(context, FirewallService::class.java).setAction(FirewallService.STOP)) }
        val vpnConsent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            if (it.resultCode == RESULT_OK) startFirewall() else consentMessage = "VPN permission declined. Firewall remains off."
        }
        fun applyRules(stop: Boolean = false) {
            if (saving) return
            val next = FirewallRules(blocked.toSet(), mode)
            saving = true
            consentMessage = null
            scope.launch {
                try {
                    withContext(Dispatchers.IO) { Rules.save(context, next.packages, next.mode) }
                    savedRules = next
                    if (stop) stopFirewall() else {
                        val intent = VpnService.prepare(this@MainActivity)
                        if (intent != null) vpnConsent.launch(intent) else startFirewall()
                    }
                } catch (e: Exception) { consentMessage = e.message ?: "Cannot apply rules; previous protection remains." }
                finally { saving = false }
            }
        }
        fun requestApply() {
            when {
                mode == FirewallMode.BLOCK_ALL -> confirmation = "all"
                blocked.isEmpty() -> confirmation = "clear"
                else -> applyRules()
            }
        }
        confirmation?.let { action ->
            AlertDialog(onDismissRequest = { confirmation = null },
                title = { Text(if (action == "all") "Block every application's internet?" else "Clear rules and stop blocking?") },
                text = { Text(if (action == "all")
                    "All apps will lose network access, including messaging and browsers. This remains a local VPN; Android Lockdown is needed during process loss."
                    else "No selected apps will be blocked after stopping. If Android Lockdown is enabled, Android will keep blocking all connections until you disable it in VPN settings.") },
                confirmButton = { TextButton(onClick = { confirmation = null; applyRules(stop = action == "clear") }) { Text(if (action == "all") "Block all apps" else "Clear and stop") } },
                dismissButton = { TextButton(onClick = { confirmation = null }) { Text("Cancel") } })
        }
        val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> uri?.let { model.analyze(context, it) } }
        LaunchedEffect(Unit) { model.refresh(context) }
        val lifecycle = LocalLifecycleOwner.current.lifecycle
        DisposableEffect(lifecycle) {
            val observer = LifecycleEventObserver { _, event ->
                if (event == Lifecycle.Event.ON_RESUME && FirewallStatus.state.value.running) {
                    startService(Intent(context, FirewallService::class.java).setAction(FirewallService.STATUS))
                }
            }
            lifecycle.addObserver(observer)
            onDispose { lifecycle.removeObserver(observer) }
        }
        Scaffold(topBar = { TopAppBar(title = { Column { Text("Android Firewall"); Text("LOCAL • PRIVATE • OPEN SOURCE", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary) } }) },
            bottomBar = { NavigationBar {
                listOf("Overview", "Apps", "Activity", "APK").forEachIndexed { index, name ->
                    NavigationBarItem(selected = tab == index, onClick = { tab = index }, icon = { Text(listOf("◈", "▦", "↔", "◇")[index]) }, label = { Text(name) })
                }
            } }) { padding ->
            LazyColumn(Modifier.fillMaxSize().padding(padding), contentPadding = PaddingValues(20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
                if (model.error != null) item { Text(model.error!!, color = MaterialTheme.colorScheme.error) }
                when (tab) {
                    0 -> {
                        item { Text("Your device, under your control", style = MaterialTheme.typography.headlineMedium) }
                        item { Panel("App firewall • beta") {
                            Text(status.message, style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
                            Text("${savedRules.packages.size} saved selections • ${status.packets} captured packets discarded • ${status.bytes} bytes")
                            if (status.active) Text(when {
                                status.quarantine -> "Applied: ALL apps blocked by safety mode (empty or unavailable saved rules)."
                                status.appliedMode == FirewallMode.BLOCK_ALL -> "Applied: ALL apps blocked by your explicit choice."
                                else -> "Applied: ${status.appliedPackages.size} package selections; shared UIDs may affect more apps."
                            })
                            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                                Button(enabled = !saving && (status.running || mode == FirewallMode.BLOCK_ALL || blocked.isNotEmpty()), onClick = {
                                    if (status.running) stopFirewall() else requestApply()
                                }) { Text(if (status.running) "Stop firewall" else "Start blocking") }
                                TextButton(onClick = { tab = 1 }) { Text("Select apps") }
                            }
                            Text("Selected apps are routed to a local packet sink. Without Android Lockdown, other apps use their normal network. Only one VPN can run at a time.")
                            Text(when (status.lockdown) {
                                true -> "Last service check: Android Lockdown was ON: this sink-only VPN also prevents unselected apps from connecting."
                                false -> "Last service check: Android Lockdown was OFF: stopping or losing this VPN can allow traffic."
                                null -> "Lockdown status is not available here. Verify it in Android VPN settings."
                            }, color = MaterialTheme.colorScheme.secondary)
                            Text("For protection during crashes and reboot, enable BOTH Always-on VPN and Block connections without VPN in Android settings. These settings cannot be enabled by this app.")
                            TextButton(onClick = { runCatching { startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) }
                                .onFailure { consentMessage = "Open Android Settings → Network → VPN manually." } }) { Text("Open Android VPN settings") }
                            if (pending) Text("Unapplied changes. Open Apps and apply to update protection.", color = MaterialTheme.colorScheme.secondary)
                            if (status.running && (!status.monitoring || !status.active || status.retryRequired)) {
                                TextButton(enabled = !saving, onClick = { requestApply() }) { Text("Retry protection") }
                            }
                            if (blocked.isEmpty() && mode == FirewallMode.SELECTED_APPS && !status.running) Text("Choose apps first, or explicitly select Block all apps in the Apps tab.")
                            consentMessage?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                            Text("No forwarding or anonymity service. Empty or missing app rules enter safety mode and block ALL apps. Lockdown with this sink-only design also blocks unselected apps.", style = MaterialTheme.typography.bodySmall)
                        } }
                        item { Panel("Application overview") {
                            Text(if (model.loading) "Reading installed apps…" else "${model.apps.size} installed packages")
                            Text("${model.apps.count { SecurityPolicy.sensitivePermissions(it.permissions).isNotEmpty() }} declare selected sensitive permissions")
                            Text("Permissions indicate access potential, not malicious behavior.")
                            TextButton(onClick = { model.refresh(context) }) { Text("Refresh device checks") }
                        } }
                        item { Panel("Root indicators") {
                            val root = model.root
                            Text(when { root == null -> "Checking…"; root.isEmpty() -> "No selected indicators visible"; else -> "${root.size} heuristic indicators found" }, color = MaterialTheme.colorScheme.primary)
                            root?.forEach { Text("• $it") }
                            Text("Read-only artifact and build-tag checks. Hidden root can evade detection; test keys can be benign. This does not establish device integrity.")
                        } }
                        item { Panel("Privacy by design") { Text("No INTERNET permission, ads, analytics, accounts, or remote services. Rules stay on this device. Packet metadata stays in memory (40 recent entries); payloads are discarded. APK temporary files are deleted after analysis.") } }
                    }
                    1 -> {
                        item { Text("App firewall & permissions", style = MaterialTheme.typography.headlineSmall) }
                        item { Text("Choose a mode, edit your selections, then apply once. Changes do not affect the current VPN until applied. Shared-UID apps may be affected together; system app rules can disrupt device functions.") }
                        item { Panel("Blocking mode") {
                            Row(Modifier.fillMaxWidth().clickable { mode = FirewallMode.SELECTED_APPS }) {
                                RadioButton(selected = mode == FirewallMode.SELECTED_APPS, onClick = { mode = FirewallMode.SELECTED_APPS })
                                Text("Selected apps", modifier = Modifier.padding(top = 12.dp))
                            }
                            Row(Modifier.fillMaxWidth().clickable { mode = FirewallMode.BLOCK_ALL }) {
                                RadioButton(selected = mode == FirewallMode.BLOCK_ALL, onClick = { mode = FirewallMode.BLOCK_ALL })
                                Text("Block all apps", modifier = Modifier.padding(top = 12.dp))
                            }
                            Text(if (mode == FirewallMode.BLOCK_ALL) "Every app loses network access. Your individual selections are preserved for later." else "${blocked.size} apps selected. Unselected apps can connect only while Android Lockdown is OFF.")
                            Button(enabled = !saving && (pending || !status.running || status.retryRequired), onClick = { requestApply() }) { Text(if (saving) "Saving…" else if (mode == FirewallMode.SELECTED_APPS && blocked.isEmpty()) "Clear rules and stop" else "Apply and start") }
                            if (pending) Text("Changes pending; current protection is unchanged.")
                            consentMessage?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                        } }
                        if (!model.loading && model.error == null && model.apps.isNotEmpty()) {
                            val missing = blocked - model.apps.map { it.packageName }.toSet()
                            if (missing.isNotEmpty()) item { Panel("Unavailable saved applications") {
                                Text("Unavailable selections trigger all-app safety mode when applied. Remove them before applying selective rules.")
                                missing.sorted().forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
                                TextButton(onClick = {
                                    blocked = blocked - missing
                                }) { Text("Remove unavailable rules") }
                            } }
                        }
                        item { OutlinedTextField(value = query, onValueChange = { query = it }, label = { Text("Search name or package") }, modifier = Modifier.fillMaxWidth(), singleLine = true) }
                        item { Row { Checkbox(checked = showSystem, onCheckedChange = { showSystem = it }); Text("Show system apps", modifier = Modifier.padding(top = 12.dp)); TextButton(onClick = { model.refresh(context) }) { Text("Refresh") } } }
                        item { Row { Checkbox(checked = internetOnly, onCheckedChange = { internetOnly = it }); Text("Internet apps only", modifier = Modifier.padding(top = 12.dp)) } }
                        if (model.loading) item { LinearProgressIndicator(Modifier.fillMaxWidth()) }
                        val selectedUids = model.apps.filter { it.packageName in blocked }.map { it.uid }.toSet()
                        val visible = model.apps.filter { it.packageName != packageName && (showSystem || !it.system) && (!internetOnly || Manifest.permission.INTERNET in it.permissions) && (it.label.contains(query, true) || it.packageName.contains(query, true)) }
                        if (!model.loading && visible.isEmpty()) item { Text("No matching applications. Adjust your search or app filters.") }
                        items(visible, key = { it.packageName }) { app ->
                            Panel(app.label) {
                                Text(app.packageName, style = MaterialTheme.typography.bodySmall)
                                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                    Text("${if (app.packageName in blocked) "Selected for blocking" else "Not selected"} • UID ${app.uid}", modifier = Modifier.padding(top = 12.dp))
                                    Switch(modifier = Modifier.semantics { contentDescription = "Block ${app.label}" }, enabled = mode == FirewallMode.SELECTED_APPS, checked = app.packageName in blocked, onCheckedChange = { deny ->
                                        blocked = if (deny) blocked + app.packageName else blocked - app.packageName
                                    })
                                }
                                if (app.uid in selectedUids && app.packageName !in blocked) Text("Shares a UID with a selection: Android blocks the whole UID when applied.", color = MaterialTheme.colorScheme.secondary)
                                val sensitive = SecurityPolicy.sensitivePermissions(app.permissions)
                                Text("${sensitive.size} sensitive / ${app.permissions.size} declared permissions")
                                TextButton(onClick = { expanded = if (expanded == app.packageName) null else app.packageName }) { Text(if (expanded == app.packageName) "Hide permissions" else "Review permissions") }
                                if (expanded == app.packageName) {
                                    Text("Grant state is reported by Android. Special access may require separate system settings.", style = MaterialTheme.typography.bodySmall)
                                    app.permissions.forEach { permission -> Text("${if (permission in app.granted) "Granted" else "Not granted"} • $permission", style = MaterialTheme.typography.bodySmall, color = if (permission in sensitive) MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.onSurface) }
                                    if (app.permissions.isEmpty()) Text("No requested permissions")
                                }
                            }
                        }
                    }
                    2 -> {
                        item { Text("Blocked network activity", style = MaterialTheme.typography.headlineSmall) }
                        item { Panel("This VPN session") {
                            Text("${status.packets} packets • ${status.bytes} bytes discarded", style = MaterialTheme.typography.titleLarge)
                            Text("Traffic reaching this VPN is visible, including Android VPN control/validation packets. Retransmissions count separately. No attribution to individual apps, hostnames, allowed traffic, decrypted content, or full device usage. Packet parsing is metadata only; all captured packets are discarded regardless of parsing. Most recent 40 sampled packet headers below (at most 20 samples/second).")
                        } }
                        if (status.events.isEmpty()) item { Text("No captured activity yet. Enable the firewall and use a blocked app to generate traffic.") }
                        items(status.events) { packet -> Card(Modifier.fillMaxWidth()) { Column(Modifier.padding(16.dp)) { Text("${packet.protocol} • IPv${packet.version}", color = MaterialTheme.colorScheme.primary); Text(packet.destination + (packet.port?.let { ":$it" } ?: "")); Text("${packet.bytes} bytes discarded", style = MaterialTheme.typography.bodySmall) } } }
                    }
                    3 -> {
                        item { Text("APK inspection", style = MaterialTheme.typography.headlineSmall) }
                        item { Button(enabled = !model.analyzing, onClick = { picker.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream", "application/zip")) }) { Text(if (model.analyzing) "Analyzing locally…" else "Choose APK") } }
                        if (model.analyzing) item { LinearProgressIndicator(Modifier.fillMaxWidth()) }
                        item { Panel("Static metadata report") { SelectionContainer { Text(model.report) } } }
                    }
                }
            }
        }
    }
}
@Composable private fun Panel(title: String, content: @Composable ColumnScope.() -> Unit) {
    Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.secondary)
            content()
        }
    }
}
