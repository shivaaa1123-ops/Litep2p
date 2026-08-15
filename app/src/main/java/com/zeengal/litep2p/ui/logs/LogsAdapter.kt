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
            ContextCompat.getColor(holder.itemView.context, severityColorId(severityOf(line)))
        )
    }

    override fun getItemCount(): Int = logs.size

    fun updateLogs(newLogs: List<String>) {
        logs = newLogs
        notifyDataSetChanged()
    }

    enum class Severity { INFO, WARN, ERROR }

    companion object {
        /**
         * Best-effort severity detection. The native logger emits messages through a
         * single string channel (no level token), so we infer severity from the
         * prefixes the engine actually uses, e.g. LOG_ERROR -> "ERROR: ...",
         * LOG_WARN -> "WARN: ...", or component-scoped "TCP Error: ..." /
         * "BufferPool: Warning - ...". Shared with the Logs tab's severity filter.
         */
        fun severityOf(line: String): Severity {
            if (line.isEmpty()) return Severity.INFO
            val lower = line.lowercase()
            val start = lower.take(24)
            if (start.startsWith("error") || start.startsWith("fatal")) {
                return Severity.ERROR
            }
            if (start.startsWith("warn")) {
                return Severity.WARN
            }
            if (lower.contains("error:")) {
                return Severity.ERROR
            }
            if (lower.contains("warning:") || lower.contains("warning -") || lower.contains(" warning ")) {
                return Severity.WARN
            }
            return Severity.INFO
        }

        private fun severityColorId(severity: Severity): Int = when (severity) {
            Severity.ERROR -> R.color.log_error
            Severity.WARN -> R.color.log_warn
            Severity.INFO -> R.color.log_info
        }
    }
}