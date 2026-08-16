package com.zeengal.litep2p

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object TelemetryStore {

    private val _telemetryRawJson = MutableLiveData<String>("{}")
    val telemetryRawJson: LiveData<String> = _telemetryRawJson

    private val _telemetryText = MutableLiveData<String>("Waiting for telemetry…")
    val telemetryText: LiveData<String> = _telemetryText

    private val tsFmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)

    /**
     * Best-effort extraction of telemetry snapshots from log lines.
     * Desktop emits lines like: `TELEMETRY { ...json... }`
     */
    fun maybeCaptureFromLog(line: String): Boolean {
        // Android log lines often include prefixes like:
        //   "[12:34:56.789] TELEMETRY {...}" or "INFO TELEMETRY {...}"
        val idx = line.indexOf("TELEMETRY")
        if (idx < 0) return false

        // Try to extract the JSON payload after the TELEMETRY token.
        val jsonStart = line.indexOf('{', startIndex = idx)
        if (jsonStart < 0) {
            return true // It's still a telemetry line; filter it out of Logs.
        }

        val json = line.substring(jsonStart).trim()
        updateFromJson(json)
        return true
    }

    /**
     * Direct entry-point for the native engine (via JNI): pass raw JSON (no "TELEMETRY" prefix).
     */
    @JvmStatic
    fun addTelemetryJson(json: String) {
        updateFromJson(json)
    }

    private fun updateFromJson(json: String) {
        try {
            val obj = JSONObject(json)
            _telemetryRawJson.postValue(obj.toString())
            _telemetryText.postValue(formatHumanReadable(obj))
        } catch (t: Throwable) {
            // Keep the UI usable even if JSON parsing fails.
            _telemetryRawJson.postValue(json)
            _telemetryText.postValue("Telemetry (unparsed)\n\n" + json)
        }
    }

    private fun formatHumanReadable(obj: JSONObject): String {
        val sb = StringBuilder()

        val tsMs = obj.optLong("ts_ms", -1L)
        val uptimeMs = obj.optLong("uptime_ms", -1L)
        val engineId = obj.optString("engine_id", "")
        val reason = obj.optString("reason", "")

        sb.appendLine("Telemetry")
        if (engineId.isNotEmpty()) sb.appendLine("  engine_id: $engineId")
        if (reason.isNotEmpty()) sb.appendLine("  reason: $reason")
        if (tsMs > 0) sb.appendLine("  ts: ${tsFmt.format(Date(tsMs))} ($tsMs)")
        if (uptimeMs >= 0) sb.appendLine("  uptime: ${formatDuration(uptimeMs)} ($uptimeMs ms)")
        sb.appendLine()

        // Resource footprint (api-spec.md §6.1): RAM / CPU / threads / connections.
        val gauges = obj.optJSONObject("gauges")
        if (gauges != null) {
            val rssBytes = gauges.optLong("rss_bytes", -1L)
            val threadCount = gauges.optLong("thread_count", -1L)
            val cpuPct = gauges.optLong("cpu_pct_estimate", -1L)
            val peersConnected = gauges.optLong("peers_connected", -1L)
            val peersTotal = gauges.optLong("peers_total", -1L)
            if (rssBytes > 0 || threadCount > 0 || cpuPct >= 0 || peersConnected >= 0) {
                sb.appendLine("Resources")
                if (rssBytes > 0) sb.appendLine("  RAM: ${formatBytes(rssBytes)}")
                if (cpuPct >= 0) sb.appendLine("  CPU: ~$cpuPct% of one core")
                if (threadCount > 0) sb.appendLine("  Threads: $threadCount")
                if (peersConnected >= 0) {
                    val total = if (peersTotal >= 0) "/$peersTotal" else ""
                    sb.appendLine("  Peers connected: $peersConnected$total")
                }
                sb.appendLine()
            }
        }

        fun appendFlatSection(title: String, o: JSONObject?) {
            if (o == null) return
            val names = o.keys().asSequence().toList().sorted()
            if (names.isEmpty()) return
            sb.appendLine("$title (${names.size})")
            for (k in names) {
                sb.appendLine("  $k: ${o.opt(k)}")
            }
            sb.appendLine()
        }

        appendFlatSection("Counters", obj.optJSONObject("counters"))
        appendFlatSection("Gauges", obj.optJSONObject("gauges"))

        val hists = obj.optJSONObject("hists_ms")
        if (hists != null) {
            val names = hists.keys().asSequence().toList().sorted()
            if (names.isNotEmpty()) {
                sb.appendLine("Histograms (ms) (${names.size})")
                for (k in names) {
                    val h = hists.optJSONObject(k)
                    if (h == null) {
                        sb.appendLine("  $k: ${hists.opt(k)}")
                        continue
                    }
                    val count = h.optLong("count", 0L)
                    val sum = h.optLong("sum", 0L)
                    val min = h.optLong("min", 0L)
                    val max = h.optLong("max", 0L)
                    val avg = if (count > 0) (sum.toDouble() / count.toDouble()) else 0.0
                    sb.appendLine("  $k: count=$count avg=${String.format(Locale.US, "%.2f", avg)} min=$min max=$max")
                }
                sb.appendLine()
            }
        }
        
        // Connection path summary
        val summary = obj.optJSONObject("connection_summary")
        if (summary != null) {
            sb.appendLine("Connection Summary")
            val totalPeers = summary.optInt("total_peers", 0)
            val connected = summary.optInt("connected", 0)
            val lanDirect = summary.optInt("lan_direct", 0)
            val wanHolePunch = summary.optInt("wan_hole_punch", 0)
            val turnRelay = summary.optInt("turn_relay", 0)
            val signalingRelay = summary.optInt("signaling_relay", 0)
            val unknown = summary.optInt("unknown", 0)
            
            sb.appendLine("  Total Peers: $totalPeers")
            sb.appendLine("  Connected: $connected")
            if (connected > 0) {
                sb.appendLine("  🏠 LAN Direct: $lanDirect (${String.format(Locale.US, "%.1f", lanDirect * 100.0 / connected)}%)")
                sb.appendLine("  🌐 WAN Hole Punch: $wanHolePunch (${String.format(Locale.US, "%.1f", wanHolePunch * 100.0 / connected)}%)")
                sb.appendLine("  🔄 TURN Relay: $turnRelay (${String.format(Locale.US, "%.1f", turnRelay * 100.0 / connected)}%)")
                sb.appendLine("  📡 Signaling Relay: $signalingRelay (${String.format(Locale.US, "%.1f", signalingRelay * 100.0 / connected)}%)")
                if (unknown > 0) sb.appendLine("  ❓ Unknown: $unknown (${String.format(Locale.US, "%.1f", unknown * 100.0 / connected)}%)")
            }
            sb.appendLine()
        }
        
        // Per-peer connection details
        val peers = obj.optJSONArray("peers")
        if (peers != null && peers.length() > 0) {
            sb.appendLine("Peer Connections (${peers.length()})")
            for (i in 0 until peers.length()) {
                val peer = peers.optJSONObject(i) ?: continue
                val peerId = peer.optString("peer_id", "")
                val connPath = peer.optString("connection_path", "UNKNOWN")
                val isConnected = peer.optBoolean("is_connected", false)
                val connectedAtMs = peer.optLong("connected_at_ms", 0)
                
                val shortId = if (peerId.length > 8) peerId.substring(0, 8) + "…" else peerId
                val pathEmoji = when (connPath) {
                    "LAN_DIRECT" -> "🏠"
                    "WAN_HOLE_PUNCH" -> "🌐"
                    "WAN_TURN_RELAY" -> "🔄"
                    "TURN_RELAY" -> "🔄"
                    "SIGNALING_RELAY" -> "📡"
                    else -> "❓"
                }
                val status = if (isConnected) "✅" else "❌"
                
                sb.appendLine("  $status $shortId: $pathEmoji $connPath")
            }
            sb.appendLine()
        }

        return sb.toString().trimEnd()
    }

    private fun formatDuration(ms: Long): String {
        if (ms < 0) return "N/A"
        var s = ms / 1000
        val hours = s / 3600
        s %= 3600
        val minutes = s / 60
        val seconds = s % 60
        return String.format(Locale.US, "%02d:%02d:%02d", hours, minutes, seconds)
    }

    private fun formatBytes(bytes: Long): String = when {
        bytes >= 1024L * 1024L * 1024L ->
            String.format(Locale.US, "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0))
        bytes >= 1024L * 1024L ->
            String.format(Locale.US, "%.1f MB", bytes / (1024.0 * 1024.0))
        bytes >= 1024L ->
            String.format(Locale.US, "%.1f KB", bytes / 1024.0)
        else -> "$bytes B"
    }
}
