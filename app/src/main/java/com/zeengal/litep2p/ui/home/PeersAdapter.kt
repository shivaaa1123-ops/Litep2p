package com.zeengal.litep2p.ui.home

import android.app.AlertDialog
import android.util.Log
import android.text.SpannableString
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.RecyclerView
import com.zeengal.litep2p.PeerInfo
import com.zeengal.litep2p.R
import com.zeengal.litep2p.hook.P2P

class PeersAdapter(private var items: List<PeerInfo> = emptyList()) :
    RecyclerView.Adapter<PeersAdapter.Holder>() {

    class Holder(view: View) : RecyclerView.ViewHolder(view) {
        val id: TextView = view.findViewById(R.id.peerIdText)
        val meta: TextView = view.findViewById(R.id.peerMetaText)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
        val v = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_peer, parent, false)
        return Holder(v)
    }

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val p = items[position]
        val (statusText, statusColorRes) = statusLabelAndColor(p)
        val latency = if (p.latency >= 0) "${p.latency}ms" else "N/A"
        
        // Format connection type with descriptive labels
        val connType = when (p.connectionType) {
            "LAN" -> "🏠 LAN"              // Direct local network
            "WAN_DIRECT" -> "🌐 Direct"    // Hole punch succeeded
            "TURN" -> "🔄 TURN"            // Via TURN relay server
            "SIGNALING" -> "📡 Relay"      // Via signaling relay
            else -> ""                      // UNKNOWN or empty
        }

        // Full peer ID, compact meta to keep list dense.
        holder.id.text = p.id
        val metaPrefix = "${p.ip}:${p.port}  •  "
        val metaStatus = statusText
        val metaConnType = if (connType.isNotEmpty()) "  •  $connType" else ""
        val metaSuffix = "  •  latency=$latency"
        val meta = metaPrefix + metaStatus + metaConnType + metaSuffix

        val ss = SpannableString(meta)
        val start = metaPrefix.length
        val end = start + metaStatus.length
        val color = ContextCompat.getColor(holder.itemView.context, statusColorRes)
        ss.setSpan(ForegroundColorSpan(color), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
        holder.meta.text = ss

        holder.itemView.setOnClickListener {
            val currentPosition = holder.adapterPosition
            if (currentPosition != RecyclerView.NO_POSITION) {
                val currentPeer = items[currentPosition]
                val context = holder.itemView.context

                if (!currentPeer.connected) {
                    Toast.makeText(context, "Connecting...", Toast.LENGTH_SHORT).show()
                    // Log connection type and peer info
                    val connectionType = P2P.getConnectionType() // Assume this returns "TCP" or "UDP"
                    Log.i("LiteP2P_UI", "User requested $connectionType connection to peer ${currentPeer.id} (IP: ${currentPeer.ip}, Port: ${currentPeer.port})")
                    P2P.connect(currentPeer.id)
                } else {
                    val dialogView = LayoutInflater.from(context).inflate(R.layout.dialog_send_message, null)
                    val editText = dialogView.findViewById<EditText>(R.id.messageEditText)

                    AlertDialog.Builder(context)
                        .setTitle("Send Message")
                        .setView(dialogView)
                        .setPositiveButton("Send") { dialog, _ ->
                            val message = editText.text.toString()
                            if (message.isNotEmpty()) {
                                P2P.sendMessageTracked(currentPeer.id, message.toByteArray())
                            }
                            dialog.dismiss()
                        }
                        .setNegativeButton("Cancel") { dialog, _ ->
                            dialog.cancel()
                        }
                        .show()
                }
            }
        }
    }

    private fun statusLabelAndColor(p: PeerInfo): Pair<String, Int> {
        // Always prefer READY when connected==true.
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
        private val TAG = "PeerDiffCallback"

        override fun getOldListSize(): Int = oldList.size
        override fun getNewListSize(): Int = newList.size
        
        override fun areItemsTheSame(oldItemPosition: Int, newItemPosition: Int): Boolean {
            return oldList[oldItemPosition].id == newList[newItemPosition].id
        }
        
        override fun areContentsTheSame(oldItemPosition: Int, newItemPosition: Int): Boolean {
            val oldPeer = oldList[oldItemPosition]
            val newPeer = newList[newItemPosition]
            val areSame = oldPeer == newPeer
            if (!areSame) {
                Log.d(TAG, "areContentsTheSame: false for peer ${oldPeer.id}")
                Log.d(TAG, "  Old: connected=${oldPeer.connected}, latency=${oldPeer.latency}")
                Log.d(TAG, "  New: connected=${newPeer.connected}, latency=${newPeer.latency}")
            }
            return areSame
        }
    }
}
