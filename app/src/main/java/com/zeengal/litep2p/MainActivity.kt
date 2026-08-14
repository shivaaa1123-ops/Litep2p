package com.zeengal.litep2p

import android.content.Intent
import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.AdapterView
import android.widget.Button
import android.widget.CheckBox
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.zeengal.litep2p.databinding.ActivityMainBinding
import java.net.Inet4Address
import java.net.NetworkInterface
import android.widget.ArrayAdapter
import com.zeengal.litep2p.ui.home.HomeFragment
import com.zeengal.litep2p.ui.dashboard.DashboardFragment
import com.zeengal.litep2p.hook.P2P
import java.io.File
import java.io.IOException
import org.json.JSONObject

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var statusText: TextView
    private lateinit var ipAddressText: TextView
    private lateinit var commsModeSpinner: Spinner
    private lateinit var startButton: Button
    private lateinit var stopButton: Button
    private lateinit var proxyGatewayCheck: CheckBox
    private lateinit var proxyClientCheck: CheckBox
    
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

        // Ensure Android has a real config.json to load (matches desktop behavior).
        // We only install it once; after that it can be replaced via adb (or future UI tooling).
        ensureDefaultConfigInstalled()
        
        // Store instance for JNI callbacks
        Companion.instance = this

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
                com.zeengal.litep2p.hook.P2P.setConnectionType(selectedMode)
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
                nativeConfigureProxy(proxyGatewayCheck.isChecked, proxyClientCheck.isChecked)
            }
        }
        proxyClientCheck.setOnCheckedChangeListener { _, _ ->
            if (engineState == EngineState.RUNNING) {
                nativeConfigureProxy(proxyGatewayCheck.isChecked, proxyClientCheck.isChecked)
            }
        }
        
        // Initially disable stop button and enable start button
        startButton.isEnabled = true
        stopButton.isEnabled = false
        
        updateIpAddress()

        startNetworkMonitoring()

        // Optional: allow adb-driven automation to start the engine without manual UI interaction.
        // Example:
        //   adb shell am start -n com.zeengal.litep2p/.MainActivity --ez LITEP2P_AUTOSTART true
        applyLaunchOptions(intent)
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

            // Handle message sending via intent (for automated testing)
            val sendToPeer = intent.getStringExtra(EXTRA_SEND_TO_PEER)
            val sendMessage = intent.getStringExtra(EXTRA_SEND_MESSAGE)
            if (!sendToPeer.isNullOrBlank() && !sendMessage.isNullOrBlank()) {
                android.util.Log.i("MainActivity", "EXTRA_SEND_MESSAGE: sending '${sendMessage}' to peer '${sendToPeer}'")
                // Use handler.post to ensure engine is ready (small delay)
                handler.postDelayed({
                    try {
                        P2P.sendMessageTracked(sendToPeer, sendMessage.toByteArray(Charsets.UTF_8))
                        android.util.Log.i("MainActivity", "Message sent successfully to peer: $sendToPeer")
                    } catch (e: Exception) {
                        android.util.Log.e("MainActivity", "Failed to send message to peer $sendToPeer: ${e.message}", e)
                    }
                }, 100)
                // Clear the extras to avoid re-sending on activity recreation
                intent.removeExtra(EXTRA_SEND_MESSAGE)
                intent.removeExtra(EXTRA_SEND_TO_PEER)
            }
        } catch (t: Throwable) {
            android.util.Log.w("MainActivity", "Failed to apply launch options: ${t.message}")
        }
    }

    private fun setSpinnerSelectionByText(spinner: Spinner, value: String) {
        val adapter = spinner.adapter ?: return
        val target = value.trim()
        for (i in 0 until adapter.count) {
            val item = adapter.getItem(i)?.toString() ?: continue
            if (item.equals(target, ignoreCase = true)) {
                spinner.setSelection(i)
                return
            }
        }
    }

    private fun ensureDefaultConfigInstalled() {
        val target = File(filesDir, "config.json")
        if (target.exists() && target.isFile && target.length() > 0) {
            android.util.Log.d("MainActivity", "Config already present at ${target.absolutePath}")
            // Still patch missing telemetry keys so UI can show updates quickly.
            patchTelemetryDefaultsIfMissing(target)
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
        } catch (ioe: IOException) {
            android.util.Log.w("MainActivity", "Failed to install default config.json: ${ioe.message}")
        } catch (t: Throwable) {
            android.util.Log.w("MainActivity", "Failed to install default config.json: ${t.message}")
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

        stopNetworkMonitoring()
        stopEngine()
        // Clear instance reference
        Companion.instance = null
    }

    private fun updateWifiMulticastLock(enable: Boolean) {
        try {
            if (enable) {
                if (multicastLock?.isHeld == true) {
                    return
                }
                val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
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

        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
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
            return NetworkState(false, false, null)
        }

        val networks = try {
            cm.allNetworks
        } catch (se: SecurityException) {
            android.util.Log.w(
                "MainActivity",
                "ACCESS_NETWORK_STATE missing/blocked; disabling network awareness: ${se.message}"
            )
            return NetworkState(false, false, defaultNetwork?.toString())
        } catch (t: Throwable) {
            return NetworkState(false, false, defaultNetwork?.toString())
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
            com.zeengal.litep2p.hook.P2P.setSystemNetworkInfo(isWifi, isAvailable)
        } catch (t: Throwable) {
            android.util.Log.w("MainActivity", "Failed to push network state to native: ${t.message}")
        }
    }

    private fun startEngine() {
        android.util.Log.d("MainActivity", "startEngine called, current state: $engineState")
        // Don't start unless fully IDLE.
        // STOPPING can take time (e.g., NAT/STUN teardown); starting early can crash native.
        if (engineState != EngineState.IDLE) {
            Toast.makeText(this, "Engine is $engineState; please wait", Toast.LENGTH_SHORT).show()
            return
        }
        
        engineState = EngineState.STARTING
        android.util.Log.d("MainActivity", "Setting engineState to STARTING")
        updateButtonStates()
        statusText.text = "Starting..."
        
        val selectedMode = commsModeSpinner.selectedItem.toString()
        com.zeengal.litep2p.hook.P2P.setConnectionType(selectedMode)
        val peerId = PeerIdManager.getPeerId(this)
        
        // Run engine startup on background thread to avoid blocking UI
        // (NAT/STUN detection can take several seconds)
        Thread {
            val result = nativeStartLiteP2PWithPeerId(selectedMode, peerId)
            
            // Update UI on main thread
            runOnUiThread {
                if (result != "OK") {
                    android.util.Log.w("MainActivity", "nativeStartLiteP2PWithPeerId returned: $result")
                    engineState = EngineState.IDLE
                    statusText.text = "Start failed: $result"
                    updateButtonStates()
                    Toast.makeText(this, "Start failed: $result", Toast.LENGTH_SHORT).show()
                    return@runOnUiThread
                }

                // Configure proxy roles immediately after start.
                // This keeps runtime behavior explicit (compile-time inclusion alone does not enable proxy roles).
                nativeConfigureProxy(proxyGatewayCheck.isChecked, proxyClientCheck.isChecked)
            }
        }.start()
    }
    
    private fun stopEngine() {
        android.util.Log.d("MainActivity", "stopEngine called, current state: $engineState")
        // Don't stop if already stopping or idle
        if (engineState == EngineState.STOPPING || engineState == EngineState.IDLE) {
            Toast.makeText(this, "Engine is already stopping or idle", Toast.LENGTH_SHORT).show()
            return
        }
        
        engineState = EngineState.STOPPING
        android.util.Log.d("MainActivity", "Setting engineState to STOPPING")
        updateButtonStates()
        
        // Set up a watchdog to surface slow stops, but DO NOT re-enable Start.
        // Stop completion must be driven by native callback (onEngineStopComplete).
        stopTimeoutHandler = Handler(Looper.getMainLooper())
        val timeoutRunnable = Runnable {
            android.util.Log.w("MainActivity", "Stop is taking longer than expected; still stopping")
            statusText.text = "Stopping (slow...)"
            Toast.makeText(this, "Stopping is taking longer than expected…", Toast.LENGTH_SHORT).show()
            // Keep engineState as STOPPING so Start stays disabled.
            updateButtonStates()
        }
        stopTimeoutRunnable = timeoutRunnable
        stopTimeoutHandler?.postDelayed(timeoutRunnable, 10000) // 10 second timeout
        
        nativeStopLiteP2P()
        statusText.text = "Stopping..."
    }
    
    private fun updateButtonStates() {
        android.util.Log.d("MainActivity", "updateButtonStates called, engineState: $engineState")
        when (engineState) {
            EngineState.IDLE -> {
                android.util.Log.d("MainActivity", "Setting startButton enabled, stopButton disabled")
                startButton.isEnabled = true
                stopButton.isEnabled = false
                proxyGatewayCheck.isEnabled = true
                proxyClientCheck.isEnabled = true
            }
            EngineState.STARTING -> {
                android.util.Log.d("MainActivity", "Setting both buttons disabled (STARTING)")
                startButton.isEnabled = false
                stopButton.isEnabled = false
                proxyGatewayCheck.isEnabled = false
                proxyClientCheck.isEnabled = false
            }
            EngineState.RUNNING -> {
                android.util.Log.d("MainActivity", "Setting startButton disabled, stopButton enabled")
                startButton.isEnabled = false
                stopButton.isEnabled = true
                proxyGatewayCheck.isEnabled = true
                proxyClientCheck.isEnabled = true
            }
            EngineState.STOPPING -> {
                android.util.Log.d("MainActivity", "Setting both buttons disabled (STOPPING)")
                startButton.isEnabled = false
                stopButton.isEnabled = false
                proxyGatewayCheck.isEnabled = false
                proxyClientCheck.isEnabled = false
            }
        }
        android.util.Log.d("MainActivity", "Button states updated - startButton: ${startButton.isEnabled}, stopButton: ${stopButton.isEnabled}")
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

    external fun nativeStartLiteP2PWithPeerId(commsMode: String, peerId: String): String
    external fun nativeStopLiteP2P()
    external fun nativeConfigureProxy(enableGateway: Boolean, enableClient: Boolean)

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
        
        @JvmStatic
        fun onEngineStartComplete() {
            android.util.Log.d("MainActivity", "onEngineStartComplete called, instance: ${instance != null}")
            instance?.runOnUiThread {
                android.util.Log.d("MainActivity", "onEngineStartComplete updating UI")
                instance?.engineState = EngineState.RUNNING
                instance?.statusText?.text = "Running"
                instance?.updateButtonStates()
                android.util.Log.d("MainActivity", "onEngineStartComplete UI updated, stopButton enabled: ${instance?.stopButton?.isEnabled}")
            }
        }
        
        @JvmStatic
        fun onEngineStopComplete() {
            android.util.Log.d("MainActivity", "onEngineStopComplete called, instance: ${instance != null}")
            if (instance == null) {
                android.util.Log.w("MainActivity", "onEngineStopComplete: instance is null, cannot update UI")
                return
            }
            
            // Cancel timeout
            instance?.stopTimeoutHandler?.let { handler ->
                instance?.stopTimeoutRunnable?.let { runnable ->
                    handler.removeCallbacks(runnable)
                }
            }
            instance?.stopTimeoutHandler = null
            instance?.stopTimeoutRunnable = null
            
            instance?.runOnUiThread {
                android.util.Log.d("MainActivity", "onEngineStopComplete updating UI")
                try {
                    instance?.engineState = EngineState.IDLE
                    instance?.statusText?.text = "Idle"
                    instance?.updateButtonStates()
                    android.util.Log.d("MainActivity", "onEngineStopComplete UI updated, startButton enabled: ${instance?.startButton?.isEnabled}")
                } catch (e: Exception) {
                    android.util.Log.e("MainActivity", "Error updating UI in onEngineStopComplete", e)
                }
            }
        }
        
        init {
            System.loadLibrary("litep2p")
        }
    }
}
