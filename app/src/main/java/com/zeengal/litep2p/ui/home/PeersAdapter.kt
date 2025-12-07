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

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val p = items[position]
        holder.id.text = "ID: ${p.id}"
        holder.ip.text = "IP: ${p.ip}"
        holder.port.text = "Port: ${p.port}"
        holder.status.text = "Status: ${if (p.connected) "Connected" else "Disconnected"}"
        holder.latency.text = "Latency: ${p.latency}ms"
        holder.networkId.text = "Network ID: ${p.networkId}"

        holder.itemView.isActivated = !p.connected

        holder.itemView.setOnClickListener {
            val context = holder.itemView.context
            
            if (!p.connected) {
                Toast.makeText(context, "Connecting to ${p.id}...", Toast.LENGTH_SHORT).show()
                P2P.connect(p.id)
            } else {
                val dialogView = LayoutInflater.from(context).inflate(R.layout.dialog_send_message, null)
                val editText = dialogView.findViewById<EditText>(R.id.messageEditText)

                AlertDialog.Builder(context)
                    .setTitle("Send Message to ${p.id}")
                    .setView(dialogView)
                    .setPositiveButton("Send") { dialog, _ ->
                        val message = editText.text.toString()
                        if (message.isNotEmpty()) {
                            P2P.sendMessage(p.id, message.toByteArray())
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

    override fun getItemCount(): Int = items.size

    fun update(newItems: List<PeerInfo>) {
        val diffCallback = PeerDiffCallback(this.items, newItems)
        val diffResult = DiffUtil.calculateDiff(diffCallback)
        
        this.items = newItems
        diffResult.dispatchUpdatesTo(this)
    }
}
