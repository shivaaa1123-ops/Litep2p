package com.zeengal.litep2p

import android.os.Bundle
import android.widget.Button
import android.widget.Spinner
import android.widget.TextView
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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        supportFragmentManager.beginTransaction()
            .replace(R.id.home_fragment_container, HomeFragment())
            .replace(R.id.logs_fragment_container, LogsFragment())
            .commit()

        statusText = findViewById(R.id.statusText)
        ipAddressText = findViewById(R.id.ipAddressText)
        commsModeSpinner = findViewById(R.id.comms_mode_spinner)

        ArrayAdapter.createFromResource(
            this,
            R.array.comms_modes_array,
            android.R.layout.simple_spinner_item
        ).also { adapter ->
            adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
            commsModeSpinner.adapter = adapter
        }

        val startButton: Button = findViewById(R.id.startButton)
        startButton.setOnClickListener {
            val selectedMode = commsModeSpinner.selectedItem.toString()
            val peerId = PeerIdManager.getPeerId(this)
            nativeStartLiteP2PWithPeerId(selectedMode, peerId)
            statusText.text = "Running"
        }

        val stopButton: Button = findViewById(R.id.stopButton)
        stopButton.setOnClickListener {
            nativeStopLiteP2P()
            statusText.text = "Idle"
        }

        updateIpAddress()
    }

    override fun onDestroy() {
        super.onDestroy()
        nativeStopLiteP2P()
    }

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

    companion object {
        init {
            System.loadLibrary("litep2p")
        }
    }
}
