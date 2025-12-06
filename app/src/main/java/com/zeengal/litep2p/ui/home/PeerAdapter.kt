package com.zeengal.litep2p.ui.home

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.zeengal.litep2p.PeerInfo
import com.zeengal.litep2p.R

class PeersAdapter(private var items: List<PeerInfo> = emptyList()) :
    RecyclerView.Adapter<PeersAdapter.Holder>() {

    class Holder(view: View) : RecyclerView.ViewHolder(view) {
        val title: TextView? = view.findViewById(R.id.peerTitle)
        val subtitle: TextView? = view.findViewById(R.id.peerSubtitle)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
        val v = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_peer, parent, false)
        return Holder(v)
    }

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val p = items[position]
        holder.title?.text = "${p.id} ${if (p.connected) "●" else "○"}"
        holder.subtitle?.text = "${p.ip}:${p.port}  latency=${p.latency}ms"
    }

    override fun getItemCount(): Int = items.size

    fun update(newItems: List<PeerInfo>) {
        items = newItems
        notifyDataSetChanged()
    }
}