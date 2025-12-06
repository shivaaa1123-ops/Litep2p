package com.zeengal.litep2p.ui.home

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.lifecycle.Observer
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.zeengal.litep2p.NativeCallback
import com.zeengal.litep2p.PeerInfo
import com.zeengal.litep2p.R
import com.zeengal.litep2p.hook.P2P
import com.zeengal.litep2p.databinding.FragmentHomeBinding

class HomeFragment : Fragment() {

    private var _binding: FragmentHomeBinding? = null
    private val binding get() = _binding!!

    private var adapter: PeersAdapter? = null

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View {
        _binding = FragmentHomeBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        // find recycler either via binding (if present) or by id
        val recycler = try {
            binding.peersRecycler
        } catch (t: Throwable) {
            view.findViewById<RecyclerView?>(R.id.peersRecycler)
        }

        if (recycler != null) {
            adapter = PeersAdapter()
            recycler.layoutManager = LinearLayoutManager(requireContext())
            recycler.adapter = adapter
        } else {
            // optional: log / update a status view that recycler isn't present
        }

        // observe native callback LiveData
        NativeCallback.peers.observe(viewLifecycleOwner, Observer { list: List<PeerInfo> ->
            adapter?.update(list)
        })

        // Optional: wire buttons if fragment has them (or wire activity's buttons elsewhere)
        binding.root.findViewById<View?>(R.id.startButton)?.setOnClickListener {
            // Use the P2P JNI wrapper you provided
            P2P.startServer(16666) // example port
        }
        binding.root.findViewById<View?>(R.id.stopButton)?.setOnClickListener {
            P2P.stop()
        }
    }

    override fun onDestroyView() {
        _binding = null
        super.onDestroyView()
    }
}