package com.zeengal.litep2p.ui.dashboard

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.button.MaterialButton
import com.zeengal.litep2p.MessageTraceStore
import com.zeengal.litep2p.R
import com.zeengal.litep2p.hook.P2P

class MessagesFragment : Fragment() {

    private lateinit var adapter: MessageEventsAdapter
    private var latestEvents: List<P2P.MessageEvent> = emptyList()
    private var countText: TextView? = null

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val root = inflater.inflate(R.layout.fragment_messages, container, false)

        countText = root.findViewById(R.id.messageCountText)

        val list = root.findViewById<RecyclerView>(R.id.messagesRecycler)
        list.layoutManager = LinearLayoutManager(requireContext())

        adapter = MessageEventsAdapter()
        adapter.setOnItemClickListener { event ->
            showTraceDialog(event.messageId)
        }
        list.adapter = adapter

        root.findViewById<MaterialButton>(R.id.clearMessagesButton).setOnClickListener {
            P2P.clearMessageEvents()
        }

        return root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        P2P.messageEvents.observe(viewLifecycleOwner) { events ->
            latestEvents = events
            adapter.submit(events)
            countText?.text = events.size.toString()
        }

        // Re-render whenever a message's delivery state changes (ACK received,
        // failure detected, retry, etc.) so row colours track the live status.
        MessageTraceStore.traceUpdates.observe(viewLifecycleOwner) {
            if (latestEvents.isNotEmpty()) {
                adapter.submit(latestEvents)
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        countText = null
    }

    private fun showTraceDialog(messageId: String) {
        val dialog = MessageTraceDialog.newInstance(messageId)
        dialog.show(childFragmentManager, "MessageTraceDialog")
    }
}
