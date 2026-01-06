package com.zeengal.litep2p.ui.home

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.zeengal.litep2p.R
import com.zeengal.litep2p.hook.P2P

class HomeFragment : Fragment() {

    private lateinit var peersAdapter: PeersAdapter

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        val root = inflater.inflate(R.layout.fragment_home, container, false)
        
        peersAdapter = PeersAdapter()
        val recyclerView: RecyclerView = root.findViewById(R.id.peersRecycler)
        recyclerView.layoutManager = LinearLayoutManager(context)
        recyclerView.adapter = peersAdapter

        P2P.peers.observe(viewLifecycleOwner) { peers ->
            peersAdapter.update(peers)
            // REMOVED: Automatic connection logic
            // Connections now require explicit user clicks only
        }
        
        return root
    }
}
