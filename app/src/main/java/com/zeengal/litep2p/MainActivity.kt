package com.zeengal.litep2p

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
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
import com.zeengal.litep2p.ui.logs.LogsFragment

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

    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var lastPushedNetworkAvailable: Boolean? = null
    private var lastPushedIsWifi: Boolean? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        // Store instance for JNI callbacks
        Companion.instance = this

        supportFragmentManager.beginTransaction()
            .replace(R.id.home_fragment_container, HomeFragment())
            .replace(R.id.logs_fragment_container, LogsFragment())
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
    }

    override fun onDestroy() {
        super.onDestroy()

        stopNetworkMonitoring()
        stopEngine()
        // Clear instance reference
        Companion.instance = null
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
            val (available, isWifi) = queryNetworkState(cm)
            pushNetworkStateToNative(available, isWifi)
        }

        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                pushCurrentState()
            }

            override fun onLost(network: Network) {
                pushCurrentState()
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
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
        networkCallback = null
        connectivityManager = null
        lastPushedNetworkAvailable = null
        lastPushedIsWifi = null
    }

    private fun queryNetworkState(cm: ConnectivityManager): Pair<Boolean, Boolean> {
        val network = try {
            cm.activeNetwork
        } catch (se: SecurityException) {
            android.util.Log.w(
                "MainActivity",
                "ACCESS_NETWORK_STATE missing/blocked; disabling network awareness: ${se.message}"
            )
            return false to false
        }

        if (network == null) {
            return false to false
        }

        val caps = try {
            cm.getNetworkCapabilities(network)
        } catch (se: SecurityException) {
            android.util.Log.w(
                "MainActivity",
                "ACCESS_NETWORK_STATE missing/blocked; disabling network awareness: ${se.message}"
            )
            return false to false
        } ?: return false to false

        // Consider the network "available" as soon as the device reports INTERNET capability.
        // VALIDATED can lag after toggling data/Wi‑Fi, and we want the native engine to start
        // recovery (signaling reconnect, endpoint refresh) immediately.
        val available = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)

        val isWifi = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
        return available to isWifi
    }

    private fun pushNetworkStateToNative(isAvailable: Boolean, isWifi: Boolean) {
        // Avoid spamming native with identical updates.
        if (lastPushedNetworkAvailable == isAvailable && lastPushedIsWifi == isWifi) {
            return
        }
        lastPushedNetworkAvailable = isAvailable
        lastPushedIsWifi = isWifi

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
