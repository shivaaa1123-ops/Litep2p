package com.zeengal.litep2p.ui.dashboard

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.zeengal.litep2p.R
import com.zeengal.litep2p.hook.P2P
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MessageEventsAdapter(
    private var items: List<P2P.MessageEvent> = emptyList(),
    private var onItemClick: ((P2P.MessageEvent) -> Unit)? = null
) : RecyclerView.Adapter<MessageEventsAdapter.Holder>() {

    private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.US)

    class Holder(view: View) : RecyclerView.ViewHolder(view) {
        val text: TextView = view.findViewById(R.id.logText)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
        val v = LayoutInflater.from(parent.context).inflate(R.layout.item_log, parent, false)
        return Holder(v)
    }

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val e = items[position]
        val ts = timeFmt.format(Date(e.timestampMs))
        val dir = if (e.direction == P2P.MessageDirection.IN) "IN " else "OUT"
        holder.text.text = "$ts [$dir] ${e.peerId}: ${e.preview}"

        holder.itemView.setOnClickListener {
            onItemClick?.invoke(e)
        }
    }

    override fun getItemCount(): Int = items.size

    fun submit(newItems: List<P2P.MessageEvent>) {
        items = newItems
        notifyDataSetChanged()
    }

    fun setOnItemClickListener(listener: (P2P.MessageEvent) -> Unit) {
        onItemClick = listener
    }
}
