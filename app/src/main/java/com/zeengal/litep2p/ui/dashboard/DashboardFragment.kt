package com.zeengal.litep2p.ui.dashboard

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.viewpager2.widget.ViewPager2
import com.google.android.material.tabs.TabLayout
import com.google.android.material.tabs.TabLayoutMediator
import com.zeengal.litep2p.R

class DashboardFragment : Fragment() {

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        return inflater.inflate(R.layout.fragment_dashboard, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val tabs = view.findViewById<TabLayout>(R.id.dashboardTabs)
        val pager = view.findViewById<ViewPager2>(R.id.dashboardPager)

        pager.adapter = DashboardPagerAdapter(this)
        pager.offscreenPageLimit = 3

        TabLayoutMediator(tabs, pager) { tab, position ->
            tab.text = when (position) {
                0 -> "Logs"
                1 -> "Messages"
                2 -> "Telemetry"
                3 -> "Resources"
                else -> "Tab ${position + 1}"
            }
        }.attach()

        // Ensure the home screen shows peers + logs by default.
        pager.setCurrentItem(0, false)
    }
}
