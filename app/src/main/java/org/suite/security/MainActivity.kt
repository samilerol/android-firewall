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
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
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
        var blocked by remember { mutableStateOf(Rules.blocked(context)) }
        var tab by remember { mutableIntStateOf(0) }
        var query by remember { mutableStateOf("") }
        var expanded by remember { mutableStateOf<String?>(null) }
        var showSystem by remember { mutableStateOf(false) }
        var consentMessage by remember { mutableStateOf<String?>(null) }
        val notifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }
        fun startFirewall() { startForegroundService(Intent(context, FirewallService::class.java)) }
        val vpnConsent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            if (it.resultCode == RESULT_OK) startFirewall() else consentMessage = "VPN permission declined. Firewall remains off."
        }
        val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> uri?.let { model.analyze(context, it) } }
        LaunchedEffect(Unit) { model.refresh(context) }
        val lifecycle = LocalLifecycleOwner.current.lifecycle
        DisposableEffect(lifecycle) {
            val observer = LifecycleEventObserver { _, event ->
                if (event == Lifecycle.Event.ON_RESUME && (FirewallStatus.state.value.active || FirewallStatus.state.value.starting)) {
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
                        item { Panel("Rootless firewall") {
                            Text(status.message, style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
                            Text("${blocked.size} selected • ${status.packets} captured packets discarded • ${status.bytes} bytes")
                            Text("Selected apps are routed to a local packet sink. Without Android Lockdown, other apps use their normal network. Only one VPN can run at a time.")
                            Text(when (status.lockdown) {
                                true -> "Android Lockdown is ON: this sink-only VPN also prevents unselected apps from connecting."
                                false -> "Android Lockdown is OFF: stopping or losing this VPN can allow traffic."
                                null -> "Lockdown status is not available here. Verify it in Android VPN settings."
                            }, color = MaterialTheme.colorScheme.secondary)
                            Text("For protection during crashes and reboot, enable BOTH Always-on VPN and Block connections without VPN in Android settings. These settings cannot be enabled by this app.")
                            TextButton(onClick = { runCatching { startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) }
                                .onFailure { consentMessage = "Open Android Settings → Network → VPN manually." } }) { Text("Open Android VPN settings") }
                            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                                Button(enabled = blocked.isNotEmpty() || status.active || status.starting, onClick = {
                                    consentMessage = null
                                    if (status.active || status.starting) startService(Intent(context, FirewallService::class.java).setAction(FirewallService.STOP))
                                    else {
                                        if (Build.VERSION.SDK_INT >= 33) notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
                                        val intent = VpnService.prepare(this@MainActivity)
                                        if (intent != null) vpnConsent.launch(intent) else startFirewall()
                                    }
                                }) { Text(if (status.active || status.starting) "Stop firewall" else "Start best-effort blocking") }
                                TextButton(onClick = { tab = 1 }) { Text("Select apps") }
                            }
                            consentMessage?.let { Text(it) }
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
                        item { Text("Switch on to save a block rule. Updates are attempted while active; check the Overview result. An empty selection or missing package triggers ALL-app safety blocking. Shared-UID apps may be affected together. System app rules can disrupt device functions.") }
                        item { OutlinedTextField(value = query, onValueChange = { query = it }, label = { Text("Search name or package") }, modifier = Modifier.fillMaxWidth(), singleLine = true) }
                        item { Row { Checkbox(checked = showSystem, onCheckedChange = { showSystem = it }); Text("Show system apps", modifier = Modifier.padding(top = 12.dp)); TextButton(onClick = { model.refresh(context) }) { Text("Refresh") } } }
                        if (model.loading) item { LinearProgressIndicator(Modifier.fillMaxWidth()) }
                        val visible = model.apps.filter { it.packageName != packageName && (showSystem || !it.system) && (it.label.contains(query, true) || it.packageName.contains(query, true)) }
                        if (!model.loading && visible.isEmpty()) item { Text("No matching applications") }
                        items(visible, key = { it.packageName }) { app ->
                            Panel(app.label) {
                                Text(app.packageName, style = MaterialTheme.typography.bodySmall)
                                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                    Text("${if (app.packageName in blocked) "Block rule saved" else "No block rule"} • UID ${app.uid}", modifier = Modifier.padding(top = 12.dp))
                                    Switch(checked = app.packageName in blocked, onCheckedChange = { deny ->
                                        blocked = if (deny) blocked + app.packageName else blocked - app.packageName
                                        Rules.save(context, blocked)
                                        if (status.active || status.starting) startFirewall()
                                    })
                                }
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
                            Text("Only selected apps' traffic reaching the VPN is visible. Retransmissions count separately. No attribution to individual apps, hostnames, allowed traffic, decrypted content, or full device usage. Packet parsing is metadata only; all captured packets are discarded regardless of parsing. Most recent 40 sampled packet headers below (at most 20 samples/second).")
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
