package com.zeengal.litep2p.ui.logs

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.chip.Chip
import com.zeengal.litep2p.LiteP2PLogger
import com.zeengal.litep2p.R

/**
 * Logs tab with severity filtering.
 *
 * The filter chips (All / Warnings / Errors) narrow the visible stream without
 * touching the underlying log buffer, so switching filters never loses lines.
 * A live line counter sits on the right of the filter row.
 */
class LogsFragment : Fragment() {

    private enum class Filter { ALL, WARNINGS, ERRORS }

    private var filter = Filter.ALL
    private var allLogs: List<String> = emptyList()

    private lateinit var logsRecyclerView: RecyclerView
    private lateinit var logsAdapter: LogsAdapter
    private var countText: TextView? = null
    private var emptyHint: TextView? = null

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val root = inflater.inflate(R.layout.fragment_logs, container, false)

        logsAdapter = LogsAdapter()
        logsRecyclerView = root.findViewById(R.id.logsRecycler)
        logsRecyclerView.layoutManager = LinearLayoutManager(requireContext())
        logsRecyclerView.adapter = logsAdapter

        countText = root.findViewById(R.id.logCountText)
        emptyHint = root.findViewById(R.id.logsEmptyHint)

        root.findViewById<Chip>(R.id.logFilterAll).setOnClickListener {
            filter = Filter.ALL
            applyFilter()
        }
        root.findViewById<Chip>(R.id.logFilterWarnings).setOnClickListener {
            filter = Filter.WARNINGS
            applyFilter()
        }
        root.findViewById<Chip>(R.id.logFilterErrors).setOnClickListener {
            filter = Filter.ERRORS
            applyFilter()
        }

        return root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        LiteP2PLogger.logs.observe(viewLifecycleOwner) { logs ->
            allLogs = logs
            applyFilter()
        }
    }

    private fun applyFilter() {
        val visible = when (filter) {
            Filter.ALL -> allLogs
            Filter.WARNINGS -> allLogs.filter {
                LogsAdapter.severityOf(it) != LogsAdapter.Severity.INFO
            }
            Filter.ERRORS -> allLogs.filter {
                LogsAdapter.severityOf(it) == LogsAdapter.Severity.ERROR
            }
        }
        logsAdapter.updateLogs(visible)
        countText?.text = if (visible.size == allLogs.size) {
            "${allLogs.size}"
        } else {
            "${visible.size}/${allLogs.size}"
        }
        emptyHint?.visibility = if (visible.isEmpty()) View.VISIBLE else View.GONE
    }

    override fun onDestroyView() {
        super.onDestroyView()
        countText = null
        emptyHint = null
    }
}