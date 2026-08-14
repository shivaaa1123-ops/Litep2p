package com.zeengal.litep2p.ui.dashboard

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.zeengal.litep2p.R

class TelemetryLinesAdapter(
    private var items: List<String> = emptyList()
) : RecyclerView.Adapter<TelemetryLinesAdapter.Holder>() {

    class Holder(view: View) : RecyclerView.ViewHolder(view) {
        val text: TextView = view.findViewById(R.id.logText)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
        val v = LayoutInflater.from(parent.context).inflate(R.layout.item_log, parent, false)
        return Holder(v)
    }

    override fun onBindViewHolder(holder: Holder, position: Int) {
        holder.text.text = items[position]
    }

    override fun getItemCount(): Int = items.size

    fun submit(newItems: List<String>) {
        items = newItems
        notifyDataSetChanged()
    }
}
