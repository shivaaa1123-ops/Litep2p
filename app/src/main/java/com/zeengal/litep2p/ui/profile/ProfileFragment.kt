package com.zeengal.litep2p.ui.profile

import android.content.pm.PackageManager
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.fragment.app.Fragment
import com.zeengal.litep2p.PeerIdManager
import com.zeengal.litep2p.R

class ProfileFragment : Fragment() {

    private var peerIdText: TextView? = null
    private var appVersionText: TextView? = null

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        val root = inflater.inflate(R.layout.fragment_profile, container, false)
        
        peerIdText = root.findViewById(R.id.peer_id_text)
        appVersionText = root.findViewById(R.id.app_version_text)
        
        // Display peer ID
        val peerId = PeerIdManager.getPeerId(requireContext())
        peerIdText?.text = peerId
        
        // Display app version
        try {
            val packageInfo = requireContext().packageManager.getPackageInfo(
                requireContext().packageName,
                0
            )
            appVersionText?.text = "Version ${packageInfo.versionName}"
        } catch (e: PackageManager.NameNotFoundException) {
            appVersionText?.text = "Version Unknown"
        }
        
        return root
    }

    override fun onDestroyView() {
        super.onDestroyView()
        peerIdText = null
        appVersionText = null
    }
}
