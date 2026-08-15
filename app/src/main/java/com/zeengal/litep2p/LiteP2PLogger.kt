package com.zeengal.litep2p

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData

object LiteP2PLogger {
    private val _logs = MutableLiveData<List<String>>(emptyList())
    val logs: LiveData<List<String>> = _logs

    private val logHistory = mutableListOf<String>()

    // This method will be called from the C++ code
    @JvmStatic
    fun addLog(message: String) {
        // Telemetry is displayed in the Telemetry tab only (not in Logs).
        // Still capture it if it arrives on the log stream (best-effort fallback).
        if (TelemetryStore.maybeCaptureFromLog(message)) {
            return
        }

        // We'll keep the last 100 messages
        if (logHistory.size > 100) {
            logHistory.removeAt(logHistory.size - 1)
        }
        // Add the newest log to the top of the list
        logHistory.add(0, message)
        _logs.postValue(logHistory.toList())
    }

    /**
     * Clears the visible log buffer (UI "clear console" action). New engine output
     * keeps arriving afterwards; only the history captured so far is dropped.
     */
    fun clear() {
        logHistory.clear()
        _logs.postValue(emptyList())
    }
}