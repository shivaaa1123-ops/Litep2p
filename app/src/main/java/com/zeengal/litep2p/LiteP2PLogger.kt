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
        // We'll keep the last 100 messages
        if (logHistory.size > 100) {
            logHistory.removeAt(logHistory.size - 1)
        }
        // Add the newest log to the top of the list
        logHistory.add(0, message)
        _logs.postValue(logHistory.toList())
    }
}