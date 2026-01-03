package com.zeengal.litep2p.ui.home

import android.app.AlertDialog
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.RecyclerView
import com.zeengal.litep2p.PeerInfo
import com.zeengal.litep2p.R
import com.zeengal.litep2p.hook.P2P

class PeersAdapter(private var items: List<PeerInfo> = emptyList()) :
    RecyclerView.Adapter<PeersAdapter.Holder>() {

    class Holder(view: View) : RecyclerView.ViewHolder(view) {
        val id: TextView = view.findViewById(R.id.peerIdText)
        val ip: TextView = view.findViewById(R.id.peerIpText)
        val port: TextView = view.findViewById(R.id.peerPortText)
        val status: TextView = view.findViewById(R.id.peerStatusText)
        val latency: TextView = view.findViewById(R.id.peerLatencyText)
        val networkId: TextView = view.findViewById(R.id.peerNetworkIdText)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
        val v = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_peer, parent, false)
        return Holder(v)
    }

    // Safely truncate peer ID for display (handles IDs shorter than 8 chars)
    private fun truncateId(id: String): String {
        return if (id.length > 8) "${id.take(8)}..." else id
    }

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val p = items[position]
        holder.id.text = "ID: ${truncateId(p.id)}"
        holder.ip.text = "IP: ${p.ip}"
        holder.port.text = "Port: ${p.port}"
        holder.status.text = "Status: ${if (p.connected) "Connected" else "Disconnected"}"
        holder.latency.text = "Latency: ${if (p.latency >= 0) "${p.latency}ms" else "N/A"}"
        holder.networkId.text = "Network ID: ${p.networkId}"

        holder.itemView.setOnClickListener {
            val currentPosition = holder.adapterPosition
            if (currentPosition != RecyclerView.NO_POSITION) {
                val currentPeer = items[currentPosition]
                val context = holder.itemView.context

                if (!currentPeer.connected) {
                    Toast.makeText(context, "Connecting to ${truncateId(currentPeer.id)}...", Toast.LENGTH_SHORT).show()
                    // Log connection type and peer info
                    val connectionType = P2P.getConnectionType() // Assume this returns "TCP" or "UDP"
                    Log.i("LiteP2P_UI", "User requested $connectionType connection to peer ${currentPeer.id} (IP: ${currentPeer.ip}, Port: ${currentPeer.port})")
                    P2P.connect(currentPeer.id)
                } else {
                    val dialogView = LayoutInflater.from(context).inflate(R.layout.dialog_send_message, null)
                    val editText = dialogView.findViewById<EditText>(R.id.messageEditText)

                    AlertDialog.Builder(context)
                        .setTitle("Send Message to ${truncateId(currentPeer.id)}")
                        .setView(dialogView)
                        .setPositiveButton("Send") { dialog, _ ->
                            val message = editText.text.toString()
                            if (message.isNotEmpty()) {
                                P2P.sendMessage(currentPeer.id, message.toByteArray())
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
