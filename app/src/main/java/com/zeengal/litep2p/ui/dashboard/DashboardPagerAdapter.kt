package com.zeengal.litep2p.ui.dashboard

import androidx.fragment.app.Fragment
import androidx.viewpager2.adapter.FragmentStateAdapter
import com.zeengal.litep2p.ui.logs.LogsFragment

class DashboardPagerAdapter(fragment: Fragment) : FragmentStateAdapter(fragment) {

    override fun getItemCount(): Int = 4

    override fun createFragment(position: Int): Fragment {
        return when (position) {
            0 -> LogsFragment()
            1 -> MessagesFragment()
            2 -> TelemetryFragment()
            3 -> ResourcesFragment()
            else -> LogsFragment()
        }
    }
}
