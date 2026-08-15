package com.zeengal.litep2p.ui.logs

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import com.zeengal.litep2p.R

class LogsAdapter(private var logs: List<String> = emptyList()) :
    RecyclerView.Adapter<LogsAdapter.LogViewHolder>() {

    class LogViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val logTextView: TextView = view.findViewById(R.id.logText)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): LogViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_log, parent, false)
        return LogViewHolder(view)
    }

    override fun onBindViewHolder(holder: LogViewHolder, position: Int) {
        val line = logs[position]
        holder.logTextView.text = line
        holder.logTextView.setTextColor(
            ContextCompat.getColor(holder.itemView.context, severityColorId(line))
        )
    }

    override fun getItemCount(): Int = logs.size

    fun updateLogs(newLogs: List<String>) {
        logs = newLogs
        notifyDataSetChanged()
    }

    companion object {
        /**
         * Best-effort severity detection. The native logger emits messages through a
         * single string channel (no level token), so we infer severity from the
         * prefixes the engine actually uses, e.g. LOG_ERROR -> "ERROR: ...",
         * LOG_WARN -> "WARN: ...", or component-scoped "TCP Error: ..." /
         * "BufferPool: Warning - ...". Colour tokens come from colors.xml.
         */
        private fun severityColorId(line: String): Int {
            if (line.isEmpty()) return R.color.log_info
            val lower = line.lowercase()
            val start = lower.take(24)
            if (start.startsWith("error") || start.startsWith("fatal")) {
                return R.color.log_error
            }
            if (start.startsWith("warn")) {
                return R.color.log_warn
            }
            if (lower.contains("error:")) {
                return R.color.log_error
            }
            if (lower.contains("warning:") || lower.contains("warning -") || lower.contains(" warning ")) {
                return R.color.log_warn
            }
            return R.color.log_info
        }
    }
}