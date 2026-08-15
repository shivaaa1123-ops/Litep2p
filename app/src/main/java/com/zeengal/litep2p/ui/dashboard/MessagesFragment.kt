package com.zeengal.litep2p.ui.dashboard

import android.os.Bundle
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.zeengal.litep2p.MessageTraceStore
import com.zeengal.litep2p.hook.P2P

class MessagesFragment : Fragment() {

    private lateinit var adapter: MessageEventsAdapter
    private var latestEvents: List<P2P.MessageEvent> = emptyList()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val root = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.VERTICAL
        }

        val hint = TextView(requireContext()).apply {
            text = "Tap a message for trace details."
            textSize = 12f
            setPadding(16, 12, 16, 12)
            gravity = Gravity.START
        }

        val list = RecyclerView(requireContext()).apply {
            layoutManager = LinearLayoutManager(requireContext())
        }

        adapter = MessageEventsAdapter()
        adapter.setOnItemClickListener { event ->
            showTraceDialog(event.messageId)
        }
        list.adapter = adapter

        root.addView(hint, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        ))
        root.addView(list, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            0,
            1f
        ))

        return root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        P2P.messageEvents.observe(viewLifecycleOwner) { events ->
            latestEvents = events
            adapter.submit(events)
        }

        // Re-render whenever a message's delivery state changes (ACK received,
        // failure detected, retry, etc.) so row colours track the live status.
        MessageTraceStore.traceUpdates.observe(viewLifecycleOwner) {
            if (latestEvents.isNotEmpty()) {
                adapter.submit(latestEvents)
            }
        }
    }

    private fun showTraceDialog(messageId: String) {
        val dialog = MessageTraceDialog.newInstance(messageId)
        dialog.show(childFragmentManager, "MessageTraceDialog")
    }
}
