package com.zeengal.litep2p.ui.logs

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.zeengal.litep2p.LiteP2PLogger

class LogsFragment : Fragment() {

    private lateinit var logsRecyclerView: RecyclerView
    private lateinit var logsAdapter: LogsAdapter

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        logsRecyclerView = RecyclerView(requireContext())
        logsRecyclerView.layoutManager = LinearLayoutManager(requireContext())
        logsAdapter = LogsAdapter()
        logsRecyclerView.adapter = logsAdapter
        return logsRecyclerView
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        LiteP2PLogger.logs.observe(viewLifecycleOwner) { logs ->
            logsAdapter.updateLogs(logs)
        }
    }
}