package com.zeengal.litep2p

import android.content.Intent
import android.content.Context
import android.content.pm.PackageManager
import android.Manifest
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.AdapterView
import android.widget.Button
import android.widget.CompoundButton
import android.widget.ImageView
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import com.zeengal.litep2p.databinding.ActivityMainBinding
import java.net.Inet4Address
import java.net.NetworkInterface
import android.widget.ArrayAdapter
import com.zeengal.litep2p.ui.home.HomeFragment
import com.zeengal.litep2p.ui.dashboard.DashboardFragment
import com.zeengal.litep2p.hook.P2P
import com.zeengal.litep2p.core.LiteP2P
import java.io.File
import java.io.IOException
import org.json.JSONObject

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var statusText: TextView
    private lateinit var ipAddressText: TextView
    private lateinit var commsModeSpinner: Spinner
    // Explicit protocol override from a launch intent (e.g. adb autostart /
    // EXTRA_COMMS_MODE). Captured directly so it applies even when the spinner
    // component isn't fully initialised yet.
    private var launchCommsModeOverride: String? = null
    // When a protocol override arrives while the engine is already running (e.g. it
    // was auto-started by the sticky service with a previous mode), we stop and then
    // restart with the requested mode. This holds the requested mode until the engine
    // reaches IDLE.
    private var pendingRestartCommsMode: String? = null
    private lateinit var startButton: Button
    private lateinit var stopButton: Button
    // Backed by Material Chips now; Chip is a CompoundButton but not a CheckBox.
    private lateinit var proxyGatewayCheck: CompoundButton
    private lateinit var proxyClientCheck: CompoundButton
    private lateinit var batteryExemptionButton: Button

    // Control-panel additions
    private lateinit var statusDot: View
    private lateinit var uptimeText: TextView
    private lateinit var peerIdText: TextView
    private lateinit var peerIdRow: View
    private lateinit var statPeersValue: TextView
    private lateinit var statReadyValue: TextView
    private lateinit var statInValue: TextView
    private lateinit var statOutValue: TextView
    private lateinit var advancedToggle: View
    private lateinit var advancedPanel: View
    private lateinit var advancedChevron: ImageView
    private lateinit var advancedSummary: TextView
    private lateinit var peersSectionHeader: View
    private lateinit var peersChevron: ImageView
    private lateinit var peersCountBadge: TextView
    private lateinit var peersContainer: View

    /** Wall-clock start of the current RUNNING period, or null when not running. */
    private var runningSinceMs: Long? = null
    private var uptimeTicker: Runnable? = null
    
    enum class EngineState {
        IDLE,
        STARTING,
        RUNNING,
        STOPPING
    }
    
    private var engineState = EngineState.IDLE
    private val handler = Handler(Looper.getMainLooper())
    private var stopTimeoutHandler: Handler? = null
    private var stopTimeoutRunnable: Runnable? = null

    private var autoStartConsumed = false

    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var lastPushedNetworkAvailable: Boolean? = null
    private var lastPushedIsWifi: Boolean? = null
    private var lastPushedNetworkKey: String? = null

    private var multicastLock: WifiManager.MulticastLock? = null

    private data class NetworkState(
        val available: Boolean,
        val isWifi: Boolean,
        val key: String?
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Edge-to-edge: the console surface runs under the system bars, and the root
        // view pads itself by the status/navigation bar insets so content stays clear.
        WindowCompat.setDecorFitsSystemWindows(window, false)
        ViewCompat.setOnApplyWindowInsetsListener(binding.mainRoot) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            WindowInsetsCompat.CONSUMED
        }

        // One tap clears the whole console: logs, messages and traces.
        findViewById<View>(R.id.clearConsoleButton).setOnClickListener {
            LiteP2PLogger.clear()
            P2P.clearMessageEvents()
            Toast.makeText(this, "Console cleared", Toast.LENGTH_SHORT).show()
        }

        // Ensure Android has a real config.json to load (matches desktop behavior).
        // We only install it once; after that it can be replaced via adb (or future UI tooling).
        ensureDefaultConfigInstalled()
        
        // Store instance for JNI callbacks
        instance = this

        supportFragmentManager.beginTransaction()
            .replace(R.id.home_fragment_container, HomeFragment())
            .replace(R.id.logs_fragment_container, DashboardFragment())
            .commit()

        statusText = findViewById(R.id.statusText)
        ipAddressText = findViewById(R.id.ipAddressText)
        commsModeSpinner = findViewById(R.id.comms_mode_spinner)
        startButton = findViewById(R.id.startButton)
        stopButton = findViewById(R.id.stopButton)
        proxyGatewayCheck = findViewById(R.id.proxyGatewayCheck)
        proxyClientCheck = findViewById(R.id.proxyClientCheck)
        batteryExemptionButton = findViewById(R.id.batteryExemptionButton)

        statusDot = findViewById(R.id.statusDot)
        uptimeText = findViewById(R.id.uptimeText)
        peerIdText = findViewById(R.id.peerIdText)
        peerIdRow = findViewById(R.id.peerIdRow)
        statPeersValue = findViewById(R.id.statPeersValue)
        statReadyValue = findViewById(R.id.statReadyValue)
        statInValue = findViewById(R.id.statInValue)
        statOutValue = findViewById(R.id.statOutValue)
        advancedToggle = findViewById(R.id.advancedToggle)
        advancedPanel = findViewById(R.id.advancedPanel)
        advancedChevron = findViewById(R.id.advancedChevron)
        advancedSummary = findViewById(R.id.advancedSummary)
        peersSectionHeader = findViewById(R.id.peersSectionHeader)
        peersChevron = findViewById(R.id.peersChevron)
        peersCountBadge = findViewById(R.id.peersCountBadge)
        peersContainer = findViewById(R.id.home_fragment_container)

        setUpControlPanel()

        ArrayAdapter.createFromResource(
            this,
            R.array.comms_modes_array,
            android.R.layout.simple_spinner_item
        ).also { adapter ->
            adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
            commsModeSpinner.adapter = adapter
        }
        
        // Set listener to update connection type when spinner selection changes
        commsModeSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>, view: View?, position: Int, id: Long) {
                val selectedMode = parent.getItemAtPosition(position).toString()
                P2P.setConnectionType(selectedMode)
                updateAdvancedSummary()
            }
            
            override fun onNothingSelected(parent: AdapterView<*>) {
                // Do nothing
            }
        }
        
        // Set up button click listeners
        startButton.setOnClickListener {
            startEngine()
        }
        
        stopButton.setOnClickListener {
            stopEngine()
        }

        // Apply proxy config changes immediately while running.
        // (Previously, proxy config was only applied once at Start, which made runtime testing easy to misconfigure.)
        proxyGatewayCheck.setOnCheckedChangeListener { _, _ ->
            if (engineState == EngineState.RUNNING) {
                LiteP2P.configureProxy(proxyGatewayCheck.isChecked, proxyClientCheck.isChecked)
                EngineController.rememberProxySettings(proxyGatewayCheck.isChecked, proxyClientCheck.isChecked)
            }
            updateAdvancedSummary()
        }
        proxyClientCheck.setOnCheckedChangeListener { _, _ ->
            if (engineState == EngineState.RUNNING) {
                LiteP2P.configureProxy(proxyGatewayCheck.isChecked, proxyClientCheck.isChecked)
                EngineController.rememberProxySettings(proxyGatewayCheck.isChecked, proxyClientCheck.isChecked)
            }
            updateAdvancedSummary()
        }

        // Battery optimization exemption. Doze/App Standby can defer network access while
        // the device is idle, which delays or drops messages even with a foreground service.
        batteryExemptionButton.setOnClickListener {
            if (BatteryOptimizationHelper.isIgnoringBatteryOptimizations(this)) {
                Toast.makeText(this, "Already exempt from battery optimization", Toast.LENGTH_SHORT).show()
                BatteryOptimizationHelper.openBatteryOptimizationSettings(this)
            } else if (!BatteryOptimizationHelper.requestExemption(this)) {
                Toast.makeText(this, "Battery settings unavailable on this device", Toast.LENGTH_SHORT).show()
            }
        }
        updateBatteryExemptionButton()

        // Engine state is process-wide (owned by LiteP2PService), not Activity-scoped, so the
        // UI recovers correctly after rotation or after returning from the background.
        EngineController.state.observe(this) { state ->
            engineState = mapEngineState(state)
            statusText.text = when (state) {
                EngineController.State.IDLE -> {
                    // Engine fully stopped: cancel the slow-stop watchdog if one is armed.
                    // (Previously done in the removed MainActivity.onEngineStopComplete
                    // JNI callback; now driven by the EngineController state observer.)
                    stopTimeoutHandler?.let { h ->
                        stopTimeoutRunnable?.let { r -> h.removeCallbacks(r) }
                    }
                    stopTimeoutHandler = null
                    stopTimeoutRunnable = null

                    // If we stopped the engine to apply a new protocol mode, restart it
                    // now that it is fully idle and safe to start again.
                    if (pendingRestartCommsMode != null) {
                        handler.post { startEngine() }
                    }
                    "Idle"
                }
                EngineController.State.STARTING -> "Starting…"
                EngineController.State.RUNNING -> "Running"
                EngineController.State.STOPPING -> "Stopping…"
            }
            val dotColor = when (state) {
                EngineController.State.IDLE -> R.color.status_idle
                EngineController.State.STARTING, EngineController.State.STOPPING -> R.color.status_warn
                EngineController.State.RUNNING -> R.color.status_ok
            }
            statusDot.backgroundTintList = android.content.res.ColorStateList.valueOf(
                ContextCompat.getColor(this, dotColor)
            )

            // Uptime is measured from the moment the engine reaches RUNNING, which is
            // what actually matters when correlating with log timestamps.
            if (state == EngineController.State.RUNNING) {
                if (runningSinceMs == null) runningSinceMs = System.currentTimeMillis()
            } else {
                runningSinceMs = null
                uptimeText.text = "--:--:--"
            }

            updateButtonStates()
        }

        // Seed the buttons from the engine's *actual* current state rather than
        // assuming IDLE. The engine lives in LiteP2PService and may already be running
        // when this Activity is created (returning from background, rotation, or a
        // relaunch while the service kept going), in which case hardcoding
        // start=enabled/stop=disabled here would briefly show the wrong affordance and
        // allow a second start to be requested.
        engineState = mapEngineState(EngineController.currentState)
        updateButtonStates()

        updateIpAddress()

        maybeRequestNotificationPermission()

        // Optional: allow adb-driven automation to start the engine without manual UI interaction.
        // Example:
        //   adb shell am start -n com.zeengal.litep2p/.MainActivity --ez LITEP2P_AUTOSTART true
        applyLaunchOptions(intent)
    }

    override fun onResume() {
        super.onResume()
        updateBatteryExemptionButton()
    }

    /**
     * Wires the parts of the control panel that are pure presentation: identity,
     * live counters, uptime and the collapsible sections.
     */
    private fun setUpControlPanel() {
        // Peer IDs are long and are needed constantly on the other side of a test, so
        // make them one tap to copy rather than something to squint at and retype.
        peerIdText.text = PeerIdManager.getPeerId(this)
        peerIdRow.setOnClickListener {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as? android.content.ClipboardManager
            cm?.setPrimaryClip(
                android.content.ClipData.newPlainText("peer id", peerIdText.text.toString())
            )
            Toast.makeText(this, "Peer ID copied", Toast.LENGTH_SHORT).show()
        }

        advancedToggle.setOnClickListener { toggleSection(advancedPanel, advancedChevron) }
        peersSectionHeader.setOnClickListener { toggleSection(peersContainer, peersChevron) }

        // Live counters. These previously existed only by scrolling the log tab, which
        // made "is anything actually flowing?" surprisingly hard to answer.
        P2P.peers.observe(this) { peers ->
            statPeersValue.text = peers.size.toString()
            val ready = peers.count { it.connected }
            statReadyValue.text = ready.toString()
            peersCountBadge.text = if (peers.isEmpty()) {
                "none discovered"
            } else {
                "$ready ready · ${peers.size} discovered"
            }
        }

        P2P.messageEvents.observe(this) { events ->
            statInValue.text = events.count { it.direction == P2P.MessageDirection.IN }.toString()
            statOutValue.text = events.count { it.direction == P2P.MessageDirection.OUT }.toString()
        }

        startUptimeTicker()
        updateAdvancedSummary()
    }

    private fun toggleSection(panel: View, chevron: ImageView) {
        val show = panel.visibility != View.VISIBLE
        panel.visibility = if (show) View.VISIBLE else View.GONE
        chevron.animate().rotation(if (show) 180f else 0f).setDuration(150).start()
    }

    /** Collapsed advanced section still shows what is configured, so nothing is hidden. */
    private fun updateAdvancedSummary() {
        val mode = runCatching { commsModeSpinner.selectedItem?.toString() }.getOrNull() ?: "UDP"
        val roles = buildList {
            if (proxyGatewayCheck.isChecked) add("gateway")
            if (proxyClientCheck.isChecked) add("client")
        }
        advancedSummary.text = if (roles.isEmpty()) mode else "$mode · ${roles.joinToString("+")}"
    }

    private fun startUptimeTicker() {
        uptimeTicker?.let { handler.removeCallbacks(it) }
        val ticker = object : Runnable {
            override fun run() {
                runningSinceMs?.let {
                    val s = (System.currentTimeMillis() - it) / 1000
                    uptimeText.text = String.format("%02d:%02d:%02d", s / 3600, (s % 3600) / 60, s % 60)
                }
                handler.postDelayed(this, 1000)
            }
        }
        uptimeTicker = ticker
        handler.post(ticker)
    }

    private fun updateBatteryExemptionButton() {
        val exempt = BatteryOptimizationHelper.isIgnoringBatteryOptimizations(this)
        batteryExemptionButton.text = if (exempt) {
            "Battery: unrestricted \u2713"
        } else {
            "Allow background battery use"
        }
    }

    /**
     * Android 13+ requires runtime consent before the foreground service notification is
     * visible. The service still runs if this is denied; the notification is just hidden.
     */
    private fun maybeRequestNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val granted = checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        if (!granted) {
            try {
                requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_POST_NOTIFICATIONS)
            } catch (t: Throwable) {
                android.util.Log.w("MainActivity", "Notification permission request failed: ${t.message}")
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        applyLaunchOptions(intent)
    }

    private fun applyLaunchOptions(intent: Intent?) {
        if (intent == null) return

        try {
            val peerId = intent.getStringExtra(EXTRA_PEER_ID)
            if (!peerId.isNullOrBlank()) {
                PeerIdManager.setPeerId(this, peerId)
                android.util.Log.i("MainActivity", "Applied EXTRA_PEER_ID=$peerId")
            }

            val commsMode = intent.getStringExtra(EXTRA_COMMS_MODE)
            if (!commsMode.isNullOrBlank()) {
                launchCommsModeOverride = commsMode
                setSpinnerSelectionByText(commsModeSpinner, commsMode)
                android.util.Log.i("MainActivity", "Applied EXTRA_COMMS_MODE=$commsMode")
            }

            if (intent.hasExtra(EXTRA_PROXY_GATEWAY)) {
                proxyGatewayCheck.isChecked = intent.getBooleanExtra(EXTRA_PROXY_GATEWAY, false)
            }
            if (intent.hasExtra(EXTRA_PROXY_CLIENT)) {
                proxyClientCheck.isChecked = intent.getBooleanExtra(EXTRA_PROXY_CLIENT, false)
            }

            val autoStart = intent.getBooleanExtra(EXTRA_AUTOSTART, false)
            if (autoStart && !autoStartConsumed) {
                autoStartConsumed = true
                android.util.Log.i("MainActivity", "EXTRA_AUTOSTART=true; scheduling startEngine()")
                handler.postDelayed({
                    startEngine()
                }, 500)
            }

            // Handle message sending via intent (for automated testing).
            // Optional LITEP2P_SEND_REPEAT=<n> fires a dense paced burst of n
            // copies from a background thread (same path as the GUI "repeat").
            val sendToPeer = intent.getStringExtra(EXTRA_SEND_TO_PEER)
            val sendMessage = intent.getStringExtra(EXTRA_SEND_MESSAGE)
            if (!sendToPeer.isNullOrBlank() && !sendMessage.isNullOrBlank()) {
                val repeat = intent.getIntExtra(EXTRA_SEND_REPEAT, 1).coerceIn(1, 10_000)
                android.util.Log.i("MainActivity", "EXTRA_SEND_MESSAGE: sending '${sendMessage}' to peer '${sendToPeer}' (repeat=$repeat)")
                // Use handler.post to ensure engine is ready (small delay)
                handler.postDelayed({
                    try {
                        if (repeat > 1) {
                            P2P.sendBurst(sendToPeer, sendMessage.toByteArray(Charsets.UTF_8), repeat)
                        } else {
                            P2P.sendMessageTracked(sendToPeer, sendMessage.toByteArray(Charsets.UTF_8))
                        }
                        android.util.Log.i("MainActivity", "Message send requested to peer: $sendToPeer (repeat=$repeat)")
                    } catch (e: Exception) {
                        android.util.Log.e("MainActivity", "Failed to send message to peer $sendToPeer: ${e.message}", e)
                    }
                }, 100)
                // Clear the extras to avoid re-sending on activity recreation
                intent.removeExtra(EXTRA_SEND_MESSAGE)
                intent.removeExtra(EXTRA_SEND_TO_PEER)
                intent.removeExtra(EXTRA_SEND_REPEAT)
            }

            // Handle explicit connect-to-peer via intent (for automated testing):
            //   adb shell am start -n com.zeengal.litep2p/.MainActivity --es LITEP2P_CONNECT_TO_PEER "<peer_id>"
            // The target peer must already be known (e.g. discovered on the LAN).
            val connectToPeer = intent.getStringExtra(EXTRA_CONNECT_TO_PEER)
            if (!connectToPeer.isNullOrBlank()) {
                android.util.Log.i("MainActivity", "EXTRA_CONNECT_TO_PEER: connecting to '$connectToPeer'")
                handler.postDelayed({
                    try {
                        P2P.connect(connectToPeer)
                        android.util.Log.i("MainActivity", "Connect initiated to peer: $connectToPeer")
                    } catch (e: Exception) {
                        android.util.Log.e("MainActivity", "Failed to connect to peer $connectToPeer: ${e.message}", e)
                    }
                }, 100)
                intent.removeExtra(EXTRA_CONNECT_TO_PEER)
            }
        } catch (t: Throwable) {
            android.util.Log.w("MainActivity", "Failed to apply launch options: ${t.message}")
        }
    }

    private fun setSpinnerSelectionByText(spinner: Spinner, value: String) {
        val adapter = spinner.adapter
        if (adapter == null) {
            android.util.Log.w("MainActivity", "setSpinnerSelectionByText: adapter not ready for '$value'")
            return
        }
        val target = value.trim()
        for (i in 0 until adapter.count) {
            val item = adapter.getItem(i)?.toString() ?: continue
            if (item.equals(target, ignoreCase = true)) {
                spinner.setSelection(i)
                return
            }
        }
        android.util.Log.w("MainActivity", "setSpinnerSelectionByText: '$value' not found among ${adapter.count} items")
    }

    private fun ensureDefaultConfigInstalled() {
        val target = File(filesDir, "config.json")
        if (target.exists() && target.isFile && target.length() > 0) {
            android.util.Log.d("MainActivity", "Config already present at ${target.absolutePath}")
            // Still patch missing telemetry keys so UI can show updates quickly.
            patchTelemetryDefaultsIfMissing(target)
            // Migrate existing installs: provision the shared transport key so Android
            // peers can decrypt CONTROL_CONNECT sent by the desktop (and vice-versa).
            patchSharedTransportKeyIfMissing(target)
            return
        }

        try {
            assets.open("config.json").use { input ->
                target.outputStream().use { output ->
                    input.copyTo(output)
                }
            }
            android.util.Log.i("MainActivity", "Installed default config.json to ${target.absolutePath}")
            patchTelemetryDefaultsIfMissing(target)
            patchSharedTransportKeyIfMissing(target)
        } catch (ioe: IOException) {
            android.util.Log.w("MainActivity", "Failed to install default config.json: ${ioe.message}")
        } catch (t: Throwable) {
            android.util.Log.w("MainActivity", "Failed to install default config.json: ${t.message}")
        }
    }

    /**
     * Existing installations keep the config.json that was baked into their first APK,
     * which predates `security.transport_key`. Without the shared key, every Android
     * peer generates its own random device-local key (keystore/transport_key.hex), so
     * encrypted CONTROL_CONNECT datagrams cannot be decrypted by desktop peers (or by
     * other Android peers) and connections stay in CONNECTING forever.
     *
     * This migrates an existing on-device config by copying the shared network key from
     * the asset default (single source of truth) into security.transport_key.
     */
    private fun patchSharedTransportKeyIfMissing(configFile: File) {
        try {
            val root = JSONObject(configFile.readText())

            val security = if (root.has("security")) {
                root.optJSONObject("security")
                    ?: JSONObject().also { root.put("security", it) }
            } else {
                JSONObject().also { root.put("security", it) }
            }

            if (security.optString("transport_key").trim().isNotEmpty()) {
                return // Already provisioned.
            }

            var sharedKey: String? = null
            try {
                assets.open("config.json").use { input ->
                    val assetRoot = JSONObject(input.bufferedReader().use { it.readText() })
                    sharedKey = assetRoot.optJSONObject("security")
                        ?.optString("transport_key")
                        ?.takeIf { it.trim().isNotEmpty() }
                }
            } catch (e: IOException) {
                android.util.Log.w("MainActivity", "Failed to read asset config for transport_key: ${e.message}")
            }

            if (sharedKey == null) {
                android.util.Log.w("MainActivity", "Shared transport_key not found in asset config; skipping patch")
                return
            }

            security.put("transport_key", sharedKey)
            configFile.writeText(root.toString(2))
            android.util.Log.i("MainActivity", "Patched shared transport_key into config.json")
        } catch (t: Throwable) {
            android.util.Log.w("MainActivity", "Failed to patch shared transport key: ${t.message}")
        }
    }

    private fun patchTelemetryDefaultsIfMissing(configFile: File) {
        try {
            val raw = configFile.readText()
            val root = JSONObject(raw)

            val monitoring = if (root.has("monitoring")) {
                root.optJSONObject("monitoring") ?: JSONObject().also { root.put("monitoring", it) }
            } else {
                JSONObject().also { root.put("monitoring", it) }
            }

            val telemetry = if (monitoring.has("telemetry")) {
                monitoring.optJSONObject("telemetry") ?: JSONObject().also { monitoring.put("telemetry", it) }
            } else {
                JSONObject().also { monitoring.put("telemetry", it) }
            }

            var changed = false

            if (!telemetry.has("enabled")) {
                telemetry.put("enabled", true)
                changed = true
            }

            // Android policy: telemetry must not be emitted as log lines.
            // (We render telemetry only in the Telemetry tab via a dedicated UI channel.)
            if (!telemetry.has("log_json") || telemetry.optBoolean("log_json", false)) {
                telemetry.put("log_json", false)
                changed = true
            }
            if (!telemetry.has("include_peer_ids")) {
                telemetry.put("include_peer_ids", true)
                changed = true
            }
            if (!telemetry.has("flush_interval_ms")) {
                telemetry.put("flush_interval_ms", 2000)
                changed = true
            }

            if (changed) {
                configFile.writeText(root.toString(2))
                android.util.Log.i("MainActivity", "Patched telemetry defaults into config.json")
            }
        } catch (t: Throwable) {
            android.util.Log.w("MainActivity", "Failed to patch telemetry defaults: ${t.message}")
        }
    }

    override fun onDestroy() {
        super.onDestroy()

        // Stop the 1 Hz uptime callback; it would otherwise keep a reference to this
        // Activity's views after it is gone.
        uptimeTicker?.let { handler.removeCallbacks(it) }
        uptimeTicker = null

        // Deliberately does NOT stop the engine. LiteP2PService owns the engine lifecycle so
        // messages keep flowing when the Activity is backgrounded, rotated, or destroyed.
        // Network monitoring and the multicast lock also live in the service now.
        // Clear instance reference
        instance = null
    }

    private fun updateWifiMulticastLock(enable: Boolean) {
        try {
            if (enable) {
                if (multicastLock?.isHeld == true) {
                    return
                }
                val wm = applicationContext.getSystemService(WIFI_SERVICE) as? WifiManager
                if (wm == null) {
                    return
                }
                val lock = multicastLock ?: wm.createMulticastLock("litep2p-multicast").apply {
                    // We manage hold state explicitly.
                    setReferenceCounted(false)
                }.also { multicastLock = it }

                lock.acquire()
                android.util.Log.i("LiteP2P_Network", "MulticastLock acquired")
            } else {
                val lock = multicastLock
                if (lock != null && lock.isHeld) {
                    lock.release()
                    android.util.Log.i("LiteP2P_Network", "MulticastLock released")
                }
            }
        } catch (t: Throwable) {
            android.util.Log.w("LiteP2P_Network", "Failed to update MulticastLock: ${t.message}")
        }
    }

    private fun startNetworkMonitoring() {
        // Best-effort: keep native aware of connectivity changes so it can re-bootstrap signaling.
        // (Without this, turning mobile data off/on can leave peers stuck DISCONNECTED.)
        if (connectivityManager != null || networkCallback != null) {
            return
        }

        val cm = getSystemService(CONNECTIVITY_SERVICE) as? ConnectivityManager
        connectivityManager = cm
        if (cm == null) {
            return
        }

        fun pushCurrentState() {
            val state = queryNetworkState(cm)
            pushNetworkStateToNative(state.available, state.isWifi, state.key)
        }

        fun logNetworkCallback(event: String, extra: String = "") {
            // This is intentionally a regular log line (not telemetry) so our adb logcat harness can
            // correlate MARK wifi_disable/wifi_enable with when Android reports a network change.
            val state = queryNetworkState(cm)
            val suffix = if (extra.isNotBlank()) " $extra" else ""
            android.util.Log.i(
                "LiteP2P_Network",
                "NetworkCallbacks: $event available=${state.available} wifi=${state.isWifi} net=${state.key}$suffix"
            )
        }

        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                logNetworkCallback("onAvailable")
                pushCurrentState()
            }

            override fun onLost(network: Network) {
                logNetworkCallback("onLost")
                pushCurrentState()
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                val hasInternet = networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                val validated = networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                val isWifiTransport = networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                logNetworkCallback(
                    "onCapabilitiesChanged",
                    "internet=$hasInternet validated=$validated wifiTransport=$isWifiTransport"
                )
                pushCurrentState()
            }
        }

        networkCallback = cb
        try {
            cm.registerDefaultNetworkCallback(cb)
        } catch (t: Throwable) {
            // Some OEM builds can throw unexpected exceptions; best-effort only.
            android.util.Log.w("MainActivity", "Failed to register network callback: ${t.message}")
        }

        // Push initial state.
        pushCurrentState()
    }

    private fun stopNetworkMonitoring() {
        val cm = connectivityManager
        val cb = networkCallback
        if (cm != null && cb != null) {
            try {
                cm.unregisterNetworkCallback(cb)
            } catch (_: Throwable) {
            }
        }

        // Best-effort: release in case the activity is destroyed while Wi‑Fi is active.
        updateWifiMulticastLock(false)
        multicastLock = null

        networkCallback = null
        connectivityManager = null
        lastPushedNetworkAvailable = null
        lastPushedIsWifi = null
        lastPushedNetworkKey = null
    }

    private fun queryNetworkState(cm: ConnectivityManager): NetworkState {
        // Important: the *default* network can remain cellular even while Wi‑Fi is up.
        // For LAN discovery + private-endpoint gating we care about whether *any* Wi‑Fi
        // network is connected, not whether Wi‑Fi is the default route.

        val defaultNetwork = try {
            cm.activeNetwork
        } catch (se: SecurityException) {
            android.util.Log.w(
                "MainActivity",
                "ACCESS_NETWORK_STATE missing/blocked; disabling network awareness: ${se.message}"
            )
            return NetworkState(available = false, isWifi = false, key = null)
        }

        val networks = try {
            cm.allNetworks
        } catch (se: SecurityException) {
            android.util.Log.w(
                "MainActivity",
                "ACCESS_NETWORK_STATE missing/blocked; disabling network awareness: ${se.message}"
            )
            return NetworkState(available = false, isWifi = false, key = defaultNetwork?.toString())
        } catch (t: Throwable) {
            return NetworkState(available = false, isWifi = false, key = defaultNetwork?.toString())
        }

        var wifiNetwork: Network? = null
        var anyInternet = false

        for (n in networks) {
            val caps = try {
                cm.getNetworkCapabilities(n)
            } catch (se: SecurityException) {
                null
            } catch (_: Throwable) {
                null
            } ?: continue

            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                anyInternet = true
            }

            // Treat Wi‑Fi as present as soon as the OS exposes a Wi‑Fi transport.
            // This is intentionally looser than VALIDATED/INTERNET because LAN-only Wi‑Fi
            // still needs discovery/messaging.
            if (wifiNetwork == null && caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                wifiNetwork = n
            }
        }

        val isWifi = wifiNetwork != null
        val available = anyInternet

        // Use a stable-ish identifier for dedupe and logging. Prefer Wi‑Fi identity when present
        // so wifi->wifi changes still trigger recovery.
        val networkKey = try {
            (wifiNetwork ?: defaultNetwork)?.toString()
        } catch (_: Throwable) {
            null
        }

        return NetworkState(available, isWifi, networkKey)
    }

    private fun pushNetworkStateToNative(isAvailable: Boolean, isWifi: Boolean, networkKey: String?) {
        // Android Wi‑Fi stacks often filter UDP broadcast/multicast by default to save power.
        // LAN discovery relies on these packets, so keep a MulticastLock while on Wi‑Fi.
        updateWifiMulticastLock(isWifi && networkKey != null)

        // Avoid spamming native with identical updates.
        // Include active-network identity so SSID changes (wifi→wifi) still trigger recovery.
        if (lastPushedNetworkAvailable == isAvailable &&
            lastPushedIsWifi == isWifi &&
            lastPushedNetworkKey == networkKey
        ) {
            return
        }
        lastPushedNetworkAvailable = isAvailable
        lastPushedIsWifi = isWifi
        lastPushedNetworkKey = networkKey

        try {
            P2P.setSystemNetworkInfo(isWifi, isAvailable)
        } catch (t: Throwable) {
            android.util.Log.w("MainActivity", "Failed to push network state to native: ${t.message}")
        }
    }

    private fun startEngine() {
        android.util.Log.d("MainActivity", "startEngine called, current state: $engineState")

        // Prefer an explicit launch override (intent autostart), then the UI spinner.
        val selectedMode = launchCommsModeOverride
            ?: commsModeSpinner.selectedItem?.toString()
            ?: "UDP"
        launchCommsModeOverride = null
        // Map the UI's "Heterogeneous" / "ALL" options to the native "ALL" mode so the
        // engine listens on TCP + UDP + QUIC simultaneously.
        val commsMode = if (selectedMode == "Heterogeneous" || selectedMode == "ALL") "ALL" else selectedMode
        P2P.setConnectionType(selectedMode)
        val peerId = PeerIdManager.getPeerId(this)

        // If the engine is already running/starting with a DIFFERENT protocol (e.g. it
        // was auto-started by the sticky service using the previously saved mode) while
        // the user asked for a different one, stop and restart so the new protocol takes
        // effect. Otherwise starting early can crash native or ignore the request.
        if (engineState != EngineState.IDLE) {
            if (commsMode != EngineController.lastCommsMode) {
                android.util.Log.i(
                    "MainActivity",
                    "Protocol changed while engine $engineState: $commsMode (was ${EngineController.lastCommsMode}); scheduling restart"
                )
                pendingRestartCommsMode = commsMode
                EngineController.stop(this)
            } else {
                Toast.makeText(this, "Engine is $engineState; please wait", Toast.LENGTH_SHORT).show()
            }
            return
        }

        // Consume a pending restart (engine just reached IDLE after we stopped it).
        val startMode = pendingRestartCommsMode ?: commsMode
        pendingRestartCommsMode = null

        // Hand off to the foreground service. It performs the actual native start on a
        // background thread, holds the wake/multicast locks, and survives this Activity.
        EngineController.start(
            this,
            startMode,
            peerId,
            proxyGatewayCheck.isChecked,
            proxyClientCheck.isChecked
        )
    }
    
    private fun stopEngine() {
        android.util.Log.d("MainActivity", "stopEngine called, current state: $engineState")
        // Don't stop if already stopping or idle
        if (engineState == EngineState.STOPPING || engineState == EngineState.IDLE) {
            Toast.makeText(this, "Engine is already stopping or idle", Toast.LENGTH_SHORT).show()
            return
        }

        // Set up a watchdog to surface slow stops, but DO NOT re-enable Start.
        // Stop completion must be driven by native callback (onEngineStopComplete).
        stopTimeoutHandler = Handler(Looper.getMainLooper())
        val timeoutRunnable = Runnable {
            android.util.Log.w("MainActivity", "Stop is taking longer than expected; still stopping")
            statusText.text = "Stopping (slow...)"
            Toast.makeText(this, "Stopping is taking longer than expected…", Toast.LENGTH_SHORT).show()
            updateButtonStates()
        }
        stopTimeoutRunnable = timeoutRunnable
        stopTimeoutHandler?.postDelayed(timeoutRunnable, 10000) // 10 second timeout

        EngineController.stop(this)
    }
    
    private fun mapEngineState(state: EngineController.State): EngineState = when (state) {
        EngineController.State.IDLE -> EngineState.IDLE
        EngineController.State.STARTING -> EngineState.STARTING
        EngineController.State.RUNNING -> EngineState.RUNNING
        EngineController.State.STOPPING -> EngineState.STOPPING
    }

    /**
     * Single source of truth for control affordances.
     *
     * Exactly one of Start/Stop is actionable at a time, and neither is during a
     * transition, so a second start or stop cannot be requested while the engine is
     * still coming up or shutting down.
     */
    private fun updateButtonStates() {
        val canStart = engineState == EngineState.IDLE
        val canStop = engineState == EngineState.RUNNING
        // Transport and proxy roles must not change mid-transition.
        val settingsEditable = canStart || canStop

        startButton.isEnabled = canStart
        stopButton.isEnabled = canStop

        // Label the transitions so a disabled pair is never mistaken for a frozen UI.
        startButton.text = if (engineState == EngineState.STARTING) "Starting…" else "Start"
        stopButton.text = if (engineState == EngineState.STOPPING) "Stopping…" else "Stop"

        proxyGatewayCheck.isEnabled = settingsEditable
        proxyClientCheck.isEnabled = settingsEditable
        commsModeSpinner.isEnabled = canStart

        android.util.Log.d(
            "MainActivity",
            "updateButtonStates: state=$engineState start=$canStart stop=$canStop"
        )
    }

    // Callbacks from native code

    private fun updateIpAddress() {
        try {
            for (ni in NetworkInterface.getNetworkInterfaces()) {
                for (ip in ni.inetAddresses) {
                    if (!ip.isLoopbackAddress && ip is Inet4Address) {
                        ipAddressText.text = "IP: ${ip.hostAddress}"
                        return
                    }
                }
            }
        } catch (e: Exception) {
            ipAddressText.text = "IP: Error"
        }
        ipAddressText.text = "IP: N/A"
    }

    // Native engine entry points live in :litep2p-core (LiteP2PNative / LiteP2P). The
    // engine is driven by LiteP2PService with no Activity present, and completion
    // callbacks flow through EngineBridge -> EngineController. MainActivity observes
    // EngineController.state for UI updates; it no longer receives direct JNI calls.

    companion object {
        @Volatile
        internal var instance: MainActivity? = null

        // adb-intent extras for automation / harnesses.
        private const val EXTRA_AUTOSTART = "LITEP2P_AUTOSTART"
        private const val EXTRA_COMMS_MODE = "LITEP2P_COMMS_MODE"
        private const val EXTRA_PEER_ID = "LITEP2P_PEER_ID"
        private const val EXTRA_PROXY_GATEWAY = "LITEP2P_PROXY_GATEWAY"
        private const val EXTRA_PROXY_CLIENT = "LITEP2P_PROXY_CLIENT"
        // Message sending via adb for automated testing:
        //   adb shell am start -n com.zeengal.litep2p/.MainActivity \
        //     --es LITEP2P_SEND_TO_PEER "desktop-1" --es LITEP2P_SEND_MESSAGE "Hello!"
        private const val EXTRA_SEND_MESSAGE = "LITEP2P_SEND_MESSAGE"
        private const val EXTRA_SEND_TO_PEER = "LITEP2P_SEND_TO_PEER"
        // Optional dense-burst repeat count (1 = single send): LITEP2P_SEND_REPEAT=<n>
        private const val EXTRA_SEND_REPEAT = "LITEP2P_SEND_REPEAT"
        // Explicit connect-to-peer via adb for automated testing:
        //   adb shell am start -n com.zeengal.litep2p/.MainActivity --es LITEP2P_CONNECT_TO_PEER "<peer_id>"
        private const val EXTRA_CONNECT_TO_PEER = "LITEP2P_CONNECT_TO_PEER"
        private const val REQ_POST_NOTIFICATIONS = 4101

        // NOTE: The native library (liblitep2p.so) is loaded by :litep2p-core's
        // LiteP2PNative, not here. Engine completion callbacks are delivered via
        // EngineBridge -> EngineController, so MainActivity has no @JvmStatic
        // native-callback methods.
    }
}
