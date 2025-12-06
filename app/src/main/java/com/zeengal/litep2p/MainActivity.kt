package com.zeengal.litep2p

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.zeengal.litep2p.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    companion object {
        init {
            // name of the native library produced by CMake (liblitep2p.so)
            try {
                System.loadLibrary("litep2p")
            } catch (t: Throwable) {
                t.printStackTrace()
            }
        }
    }

    // Native methods
    private external fun nativeStartLiteP2P(): String
    private external fun nativeStopLiteP2P()
    private external fun nativeSetLogger()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Hook up UI
        binding.statusText.text = "Idle"

        // Register this Activity as logger target in native code
        nativeSetLogger()
        appendLog("Logger bridge registered.")

        binding.startButton.setOnClickListener {
            binding.statusText.text = "Starting…"
            appendLog("Starting LiteP2P (native) ...")
            Thread {
                try {
                    val res = nativeStartLiteP2P()
                    runOnUiThread {
                        binding.statusText.text = "Running"
                        appendLog("Native start returned: $res")
                    }
                } catch (e: Throwable) {
                    runOnUiThread {
                        binding.statusText.text = "Error"
                        appendLog("Error starting native engine: ${e.message}")
                    }
                }
            }.start()
        }

        binding.startButton.isEnabled = true

        binding.stopButton.setOnClickListener {
            appendLog("Stopping LiteP2P (native) ...")
            nativeStopLiteP2P()
            binding.statusText.text = "Stopped"
        }
    }

    // This method will be called from native code via JNI
    // Signature must match what native calls: (Ljava/lang/String;)V
    fun onNativeLog(message: String) {
        runOnUiThread {
            appendLog(message)
        }
    }

    private fun appendLog(msg: String) {
        val old = binding.logText.text.toString()
        val next = if (old.isEmpty()) msg else old + "\n" + msg
        binding.logText.text = next
        binding.logScroll.post { binding.logScroll.fullScroll(android.view.View.FOCUS_DOWN) }
    }

    override fun onDestroy() {
        try {
            nativeStopLiteP2P()
        } catch (_: Throwable) {}
        super.onDestroy()
    }
}