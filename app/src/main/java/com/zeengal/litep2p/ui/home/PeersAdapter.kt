package com.zeengal.litep2p.ui.home

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.res.ColorStateList
import android.text.SpannableString
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.button.MaterialButton
import com.google.android.material.chip.Chip
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.zeengal.litep2p.core.EngineResult
import com.zeengal.litep2p.core.LiteP2P
import com.zeengal.litep2p.core.PeerInfo
import com.zeengal.litep2p.R
import com.zeengal.litep2p.hook.P2P

/**
 * Renders the discovered/connected peers as modern cards.
 *
 * Every row shows:
 *   - a status dot colour-coded by the peer FSM state
 *   - the peer ID, endpoint, connection path and latency
 *   - an explicit action: Connect (idle peers) or Send (ready peers)
 *
 * Row tap mirrors the button; long-press copies the peer ID.
 */
class PeersAdapter(private var items: List<PeerInfo> = emptyList()) :
    RecyclerView.Adapter<PeersAdapter.Holder>() {

    companion object {
        private const val TAG = "PeersAdapter"
    }

    /** Invoked when the user taps "File" on a ready peer (system picker). */
    var onSendFile: ((PeerInfo) -> Unit)? = null

    /** Invoked when the user taps "Call" on a ready peer (voice call). */
    var onCall: ((PeerInfo) -> Unit)? = null

    class Holder(view: View) : RecyclerView.ViewHolder(view) {
        val dot: View = view.findViewById(R.id.peerStatusDot)
        val id: TextView = view.findViewById(R.id.peerIdText)
        val meta: TextView = view.findViewById(R.id.peerMetaText)
        val action: MaterialButton = view.findViewById(R.id.peerActionButton)
        val file: MaterialButton = view.findViewById(R.id.peerFileButton)
        val call: MaterialButton = view.findViewById(R.id.peerCallButton)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
        val v = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_peer, parent, false)
        return Holder(v)
    }

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val p = items[position]
        val context = holder.itemView.context

        // --- status dot ---
        val (statusText, statusColorRes) = statusLabelAndColor(p)
        holder.dot.backgroundTintList =
            ColorStateList.valueOf(ContextCompat.getColor(context, statusColorRes))

        holder.id.text = p.id

        // --- meta line: endpoint · status · path · latency ---
        val latency = if (p.latency >= 0) "${p.latency}ms" else "—"
        // The C ABI reports canonical connection-path names (litep2p.h §3.6).
        val connType = when (p.connectionType) {
            "LAN_DIRECT", "LAN" -> "LAN"
            "WAN_HOLE_PUNCH", "WAN_DIRECT" -> "Direct"
            "TURN_RELAY", "TURN" -> "TURN"
            "SIGNALING_RELAY", "SIGNALING" -> "Relay"
            else -> null
        }
        val meta = buildString {
            append("${p.ip}:${p.port}")
            append("  ·  ").append(statusText)
            connType?.let { append("  ·  ").append(it) }
            append("  ·  ").append(latency)
        }
        val ss = SpannableString(meta)
        val statusStart = meta.indexOf(statusText)
        if (statusStart >= 0) {
            ss.setSpan(
                ForegroundColorSpan(ContextCompat.getColor(context, statusColorRes)),
                statusStart, statusStart + statusText.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
            )
        }
        holder.meta.text = ss

        // --- explicit action button ---
        if (p.connected) {
            holder.action.text = "Send"
            holder.action.setIconResource(R.drawable.ic_send)
            holder.action.setOnClickListener { showSendDialog(context, p) }

            // File-transfer action for ready peers.
            holder.file.visibility = View.VISIBLE
            holder.file.setOnClickListener { onSendFile?.invoke(p) }

            // Voice-call action for ready peers (requires RECORD_AUDIO permission,
            // which the host activity requests on first use).
            holder.call.visibility = View.VISIBLE
            holder.call.setOnClickListener { onCall?.invoke(p) }
        } else {
            holder.action.text = "Connect"
            holder.action.setIconResource(R.drawable.ic_play)
            holder.action.setOnClickListener { requestConnect(context, p) }
            holder.file.visibility = View.GONE
            holder.call.visibility = View.GONE
        }

        // Row tap mirrors the button.
        holder.itemView.setOnClickListener {
            if (p.connected) showSendDialog(context, p) else requestConnect(context, p)
        }

        // Long-press copies the peer ID.
        holder.itemView.setOnLongClickListener {
            copyToClipboard(context, p.id)
            Toast.makeText(context, "Peer ID copied", Toast.LENGTH_SHORT).show()
            true
        }
    }

    private fun requestConnect(context: Context, p: PeerInfo) {
        Toast.makeText(context, "Connecting to ${shortId(p.id)}…", Toast.LENGTH_SHORT).show()
        P2P.connect(p.id)
    }

    private fun showSendDialog(context: Context, p: PeerInfo) {
        val view = LayoutInflater.from(context).inflate(R.layout.dialog_send_message, null)
        val editText = view.findViewById<EditText>(R.id.messageEditText)
        val repeatEdit = view.findViewById<EditText>(R.id.repeatEditText)

        fun applyPreset(bytes: Int) {
            val body = ByteArray(bytes) { (it % 94 + 33).toByte() }
            editText.setText(String(body, Charsets.ISO_8859_1))
        }

        view.findViewById<Chip>(R.id.presetPing).setOnClickListener {
            editText.setText("ping ${System.currentTimeMillis()}")
        }
        view.findViewById<Chip>(R.id.preset1k).setOnClickListener { applyPreset(1024) }
        view.findViewById<Chip>(R.id.preset64k).setOnClickListener { applyPreset(64 * 1024) }
        view.findViewById<Chip>(R.id.preset256k).setOnClickListener { applyPreset(256 * 1024) }

        editText.setText("hello from android")

        MaterialAlertDialogBuilder(context)
            .setTitle("Send to ${shortId(p.id)}")
            .setView(view)
            .setPositiveButton("Send") { dialog, _ ->
                val message = editText.text.toString()
                val repeat = (repeatEdit.text.toString().toIntOrNull() ?: 1).coerceIn(1, 10_000)
                if (message.isNotEmpty()) {
                    val bytes = message.toByteArray(Charsets.UTF_8)
                    sendBulk(p.id, bytes, repeat)
                    Toast.makeText(
                        context,
                        "Sending $repeat × ${formatBytes(bytes.size.toLong())} in background",
                        Toast.LENGTH_SHORT
                    ).show()
                }
                dialog.dismiss()
            }
            .setNegativeButton("Cancel") { dialog, _ -> dialog.cancel() }
            .show()
    }

    /**
     * Sends [times] copies of [bytes] to [peerId] without blocking the UI thread and
     * without flooding the engine's single-threaded event loop.
     *
     * The engine caps in-flight plain sends at `peer_management.max_pending_sends`
     * (default 1000); past that, `litep2p_send()` returns
     * [EngineResult.QUEUE_FULL]. A burst that ignores this and hammers the queue
     * from the main thread can starve heartbeats/control/ACK traffic and wedge the
     * node until it is restarted. So we:
     *  - run the burst on a background thread (the SDK API is thread-safe), and
     *  - pace against [LiteP2P.pendingSendCount] and back off + retry on
     *    [EngineResult.QUEUE_FULL] so every message is delivered at the engine's
     *    natural drain rate instead of being dropped.
     */
    private fun sendBulk(peerId: String, bytes: ByteArray, times: Int) {
        Thread {
            // Keep headroom under the default 1000 cap — tune for your config.
            val pacingLimit = 600
            var backoffMs = 5L
            var sent = 0
            var failed = 0
            repeat(times) {
                // Wait while the engine is backed up so we never overrun the queue.
                var spins = 0
                while (LiteP2P.pendingSendCount() >= pacingLimit && spins < 50_000) {
                    Thread.sleep(backoffMs)
                    spins++
                }
                var rc = P2P.sendMessageTracked(peerId, bytes)
                if (rc == EngineResult.QUEUE_FULL) {
                    // Engine is temporarily at capacity — back off and retry once rather
                    // than dropping the message.
                    backoffMs = (backoffMs * 2).coerceAtMost(250L)
                    Thread.sleep(backoffMs)
                    rc = P2P.sendMessageTracked(peerId, bytes)
                }
                if (rc == EngineResult.OK) sent++ else failed++
            }
            if (failed > 0) {
                Log.w(TAG, "Bulk send: $sent delivered, $failed rejected by engine")
            }
        }.start()
    }

    private fun copyToClipboard(context: Context, id: String) {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("peer_id", id))
    }

    private fun shortId(id: String) = if (id.length > 12) id.take(12) + "…" else id

    private fun formatBytes(n: Long): String = when {
        n >= 1024L * 1024L -> String.format("%.1f MB", n / (1024.0 * 1024.0))
        n >= 1024L -> String.format("%.1f KB", n / 1024.0)
        else -> "$n B"
    }

    private fun statusLabelAndColor(p: PeerInfo): Pair<String, Int> {
        if (p.connected) {
            return "ready" to R.color.peer_status_ready
        }

        val s = p.fsmState.trim()
        if (s.isBlank()) {
            return "disconnected" to R.color.peer_status_disconnected
        }

        return when (s.uppercase()) {
            "DISCOVERED" -> "discovered" to R.color.peer_status_discovered
            "CONNECTING" -> "connecting" to R.color.peer_status_connecting
            "CONNECTED" -> "connected" to R.color.peer_status_connected
            "HANDSHAKING" -> "handshaking" to R.color.peer_status_handshaking
            "READY" -> "ready" to R.color.peer_status_ready
            else -> s.lowercase() to R.color.peer_status_disconnected
        }
    }

    override fun getItemCount(): Int = items.size

    fun update(newItems: List<PeerInfo>) {
        val diffCallback = PeerDiffCallback(this.items, newItems)
        val diffResult = DiffUtil.calculateDiff(diffCallback)

        this.items = newItems
        diffResult.dispatchUpdatesTo(this)
    }

    class PeerDiffCallback(
        private val oldList: List<PeerInfo>,
        private val newList: List<PeerInfo>
    ) : DiffUtil.Callback() {

        override fun getOldListSize(): Int = oldList.size
        override fun getNewListSize(): Int = newList.size

        override fun areItemsTheSame(oldItemPosition: Int, newItemPosition: Int): Boolean {
            return oldList[oldItemPosition].id == newList[newItemPosition].id
        }

        override fun areContentsTheSame(oldItemPosition: Int, newItemPosition: Int): Boolean {
            return oldList[oldItemPosition] == newList[newItemPosition]
        }
    }
}
