package com.zeengal.litep2p.ui.home

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.zeengal.litep2p.EngineController
import com.zeengal.litep2p.MainActivity
import com.zeengal.litep2p.R
import com.zeengal.litep2p.hook.P2P

class HomeFragment : Fragment() {

    private lateinit var peersAdapter: PeersAdapter
    private var emptyState: View? = null
    private var emptySubtitle: TextView? = null

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val root = inflater.inflate(R.layout.fragment_home, container, false)

        peersAdapter = PeersAdapter()
        // File-transfer action on the peer cards is handled by the host activity
        // (it owns the ActivityResultLauncher for the system photo picker).
        peersAdapter.onSendFile = { peer ->
            (requireActivity() as? MainActivity)?.openFilePickerForPeer(peer.id)
        }
        // Voice-call action on the peer cards is also handled by the host
        // activity (it owns the RECORD_AUDIO permission request + call UI).
        peersAdapter.onCall = { peer ->
            (requireActivity() as? MainActivity)?.startVoiceCallToPeer(peer.id)
        }
        val recyclerView: RecyclerView = root.findViewById(R.id.peersRecycler)
        recyclerView.layoutManager = LinearLayoutManager(context)
        recyclerView.adapter = peersAdapter

        emptyState = root.findViewById(R.id.peersEmptyState)
        emptySubtitle = root.findViewById(R.id.peersEmptySubtitle)

        P2P.peers.observe(viewLifecycleOwner) { peers ->
            peersAdapter.update(peers)
            // Connections are explicit user actions; nothing auto-connects here.
            emptyState?.visibility = if (peers.isEmpty()) View.VISIBLE else View.GONE
        }

        // The empty-state hint depends on whether the engine is even running.
        EngineController.state.observe(viewLifecycleOwner) { state ->
            emptySubtitle?.text = when (state) {
                EngineController.State.RUNNING -> "Discovering on the local network…"
                EngineController.State.STARTING -> "Engine is starting…"
                else -> "Start the engine to begin discovery"
            }
        }

        return root
    }

    override fun onDestroyView() {
        super.onDestroyView()
        emptyState = null
        emptySubtitle = null
    }
}
