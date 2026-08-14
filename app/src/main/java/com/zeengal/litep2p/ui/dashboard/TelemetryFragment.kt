package com.zeengal.litep2p.ui.dashboard

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ScrollView
import android.widget.TextView
import androidx.fragment.app.Fragment
import com.zeengal.litep2p.TelemetryStore

class TelemetryFragment : Fragment() {

    private lateinit var text: TextView

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        text = TextView(requireContext()).apply {
            textSize = 12f
            setPadding(16, 16, 16, 16)
            typeface = android.graphics.Typeface.MONOSPACE
            setLineSpacing(0f, 1.2f)
            text = "Waiting for telemetry…"
        }

        return ScrollView(requireContext()).apply {
            addView(text)
        }
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        // Desktop-like: a single snapshot that updates in place.
        TelemetryStore.telemetryText.observe(viewLifecycleOwner) { snapshotText ->
            text.text = snapshotText
        }
    }
}
