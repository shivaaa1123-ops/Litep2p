package com.zeengal.litep2p.ui.dashboard

import android.app.ActivityManager
import android.content.Context
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ScrollView
import android.widget.TextView
import androidx.fragment.app.Fragment
import com.zeengal.litep2p.hook.P2P
import kotlin.math.roundToInt

class ResourcesFragment : Fragment() {

    private val handler = Handler(Looper.getMainLooper())
    private var ticker: Runnable? = null

    private lateinit var text: TextView

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        text = TextView(requireContext()).apply {
            textSize = 12f
            setPadding(16, 16, 16, 16)
            setLineSpacing(0f, 1.2f)
            typeface = android.graphics.Typeface.MONOSPACE
        }

        return ScrollView(requireContext()).apply {
            addView(text)
        }
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        fun update() {
            val ctx = requireContext()
            val am = ctx.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
            val pid = Process.myPid()

            val memInfo = ActivityManager.MemoryInfo()
            am.getMemoryInfo(memInfo)

            val procMem = am.getProcessMemoryInfo(intArrayOf(pid)).firstOrNull()
            val pssKb = procMem?.totalPss ?: -1
            val rssKb = procMem?.totalPrivateDirty ?: -1

            val javaUsedMb = (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / (1024.0 * 1024.0)
            val javaMaxMb = Runtime.getRuntime().maxMemory() / (1024.0 * 1024.0)

            val cpuMs = Process.getElapsedCpuTime()
            val peers = P2P.peers.value?.size ?: 0

            val availMb = memInfo.availMem / (1024.0 * 1024.0)
            val totalMb = if (android.os.Build.VERSION.SDK_INT >= 16) memInfo.totalMem / (1024.0 * 1024.0) else -1.0

            val sb = StringBuilder()
            sb.appendLine("Process")
            sb.appendLine("  pid=$pid")
            sb.appendLine("  cpu_time_ms=$cpuMs")
            sb.appendLine("  peers=$peers")
            sb.appendLine()
            sb.appendLine("Memory")
            sb.appendLine("  java_used_mb=${javaUsedMb.roundToInt()} / java_max_mb=${javaMaxMb.roundToInt()}")
            if (pssKb >= 0) sb.appendLine("  pss_kb=$pssKb")
            if (rssKb >= 0) sb.appendLine("  private_dirty_kb=$rssKb")
            sb.appendLine("  system_avail_mb=${availMb.roundToInt()}")
            if (totalMb >= 0) sb.appendLine("  system_total_mb=${totalMb.roundToInt()}")

            text.text = sb.toString()
        }

        ticker = object : Runnable {
            override fun run() {
                update()
                handler.postDelayed(this, 1000)
            }
        }
        handler.post(ticker!!)
    }

    override fun onDestroyView() {
        super.onDestroyView()
        ticker?.let { handler.removeCallbacks(it) }
        ticker = null
    }
}
