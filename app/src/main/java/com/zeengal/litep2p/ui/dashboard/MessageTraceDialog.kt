package com.zeengal.litep2p.ui.dashboard

import android.app.Dialog
import android.graphics.Typeface
import android.os.Bundle
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.fragment.app.DialogFragment
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.zeengal.litep2p.MessageTraceStore
import com.zeengal.litep2p.R
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Dialog that shows full message tracing information.
 */
class MessageTraceDialog : DialogFragment() {

    companion object {
        private const val ARG_MESSAGE_ID = "message_id"

        fun newInstance(messageId: String): MessageTraceDialog {
            return MessageTraceDialog().apply {
                arguments = Bundle().apply {
                    putString(ARG_MESSAGE_ID, messageId)
                }
            }
        }
    }

    private val timeFmt = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)
    private val dateFmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val messageId = arguments?.getString(ARG_MESSAGE_ID) ?: ""
        val trace = MessageTraceStore.getTrace(messageId)

        val context = requireContext()

        val scrollView = ScrollView(context).apply {
            setPadding(24, 16, 24, 16)
        }

        val container = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        }

        if (trace == null) {
            container.addView(TextView(context).apply {
                text = "No trace data available for this message."
                textSize = 14f
            })
        } else {
            // Header section
            container.addView(createSectionHeader("Message Info"))
            container.addView(createInfoRow("ID", trace.messageId))
            container.addView(createInfoRow("Direction", if (trace.direction == MessageTraceStore.Direction.OUT) "↑ OUTGOING" else "↓ INCOMING"))
            container.addView(createInfoRow("Peer", trace.peerId))
            container.addView(createInfoRow("Protocol", trace.protocol))
            container.addView(createInfoRow("Size", "${trace.sizeBytes} bytes"))
            container.addView(createInfoRow("Created", dateFmt.format(Date(trace.createdAtMs))))

            // Status section
            container.addView(createSectionHeader("Status"))
            val statusText = when (trace.status) {
                MessageTraceStore.MessageStatus.PENDING -> "⏳ PENDING"
                MessageTraceStore.MessageStatus.DELIVERED -> "✓ DELIVERED"
                MessageTraceStore.MessageStatus.FAILED -> "✗ FAILED"
                MessageTraceStore.MessageStatus.RECEIVED -> "✓ RECEIVED"
            }
            val statusColor = when (trace.status) {
                MessageTraceStore.MessageStatus.PENDING ->
                    ContextCompat.getColor(context, R.color.status_warn)
                MessageTraceStore.MessageStatus.DELIVERED, MessageTraceStore.MessageStatus.RECEIVED ->
                    ContextCompat.getColor(context, R.color.status_ok)
                MessageTraceStore.MessageStatus.FAILED ->
                    ContextCompat.getColor(context, R.color.status_err)
            }
            container.addView(createColoredInfoRow("Status", statusText, statusColor))

            if (trace.latencyMs != null) {
                container.addView(createInfoRow("Latency", "${trace.latencyMs} ms"))
            }
            if (trace.retryCount > 0) {
                container.addView(createInfoRow("Retries", trace.retryCount.toString()))
            }
            if (!trace.errorMessage.isNullOrEmpty()) {
                container.addView(createColoredInfoRow("Error", trace.errorMessage!!,
                    ContextCompat.getColor(context, R.color.status_err)))
            }

            // Preview section
            container.addView(createSectionHeader("Content Preview"))
            container.addView(TextView(context).apply {
                text = trace.preview.ifEmpty { "(empty)" }
                textSize = 12f
                typeface = Typeface.MONOSPACE
                setTextColor(ContextCompat.getColor(context, R.color.text_secondary))
                setBackgroundColor(ContextCompat.getColor(context, R.color.surface_2))
                setPadding(16, 12, 16, 12)
            })

            // Timeline section
            container.addView(createSectionHeader("Event Timeline (${trace.events.size} events)"))

            if (trace.events.isEmpty()) {
                container.addView(TextView(context).apply {
                    text = "No events recorded."
                    textSize = 12f
                    setTextColor(ContextCompat.getColor(context, R.color.text_tertiary))
                })
            } else {
                for ((index, event) in trace.events.withIndex()) {
                    container.addView(createTimelineEvent(index, event, trace.createdAtMs))
                }
            }
        }

        scrollView.addView(container)

        return MaterialAlertDialogBuilder(context)
            .setTitle("Message Trace")
            .setView(scrollView)
            .setPositiveButton("Close", null)
            .create()
    }

    private fun createSectionHeader(title: String): TextView {
        return TextView(requireContext()).apply {
            text = title
            textSize = 14f
            setTypeface(null, Typeface.BOLD)
            setPadding(0, 24, 0, 8)
            setTextColor(ContextCompat.getColor(requireContext(), R.color.accent))
        }
    }

    private fun createInfoRow(label: String, value: String): TextView {
        return TextView(requireContext()).apply {
            val ssb = SpannableStringBuilder()
            ssb.append("$label: ", StyleSpan(Typeface.BOLD), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            ssb.append(value)
            text = ssb
            textSize = 13f
            setPadding(0, 4, 0, 4)
        }
    }

    private fun createColoredInfoRow(label: String, value: String, color: Int): TextView {
        return TextView(requireContext()).apply {
            val ssb = SpannableStringBuilder()
            ssb.append("$label: ", StyleSpan(Typeface.BOLD), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            val start = ssb.length
            ssb.append(value)
            ssb.setSpan(ForegroundColorSpan(color), start, ssb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            ssb.setSpan(StyleSpan(Typeface.BOLD), start, ssb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            text = ssb
            textSize = 13f
            setPadding(0, 4, 0, 4)
        }
    }

    private fun createTimelineEvent(index: Int, event: MessageTraceStore.TraceEvent, baseTime: Long): TextView {
        val relativeMs = event.timestampMs - baseTime
        val relativeStr = if (relativeMs >= 0) "+${relativeMs}ms" else "${relativeMs}ms"

        val eventIcon = when (event.eventType) {
            MessageTraceStore.EventType.TX_QUEUED -> "📤"
            MessageTraceStore.EventType.TX_SENT -> "➡️"
            MessageTraceStore.EventType.TX_ACK -> "✓"
            MessageTraceStore.EventType.TX_TIMEOUT -> "⏱️"
            MessageTraceStore.EventType.TX_RETRY -> "🔄"
            MessageTraceStore.EventType.TX_FAILED -> "✗"
            MessageTraceStore.EventType.RX_RECEIVED -> "📥"
            MessageTraceStore.EventType.RX_DECRYPTED -> "🔓"
            MessageTraceStore.EventType.RX_DECRYPT_FAIL -> "🔒"
            MessageTraceStore.EventType.ROUTED -> "↔️"
            MessageTraceStore.EventType.HANDSHAKE -> "🤝"
            MessageTraceStore.EventType.ERROR -> "⚠️"
        }

        val eventColor = when (event.eventType) {
            MessageTraceStore.EventType.TX_ACK, MessageTraceStore.EventType.RX_RECEIVED, MessageTraceStore.EventType.RX_DECRYPTED ->
                ContextCompat.getColor(requireContext(), R.color.status_ok)
            MessageTraceStore.EventType.TX_FAILED, MessageTraceStore.EventType.RX_DECRYPT_FAIL, MessageTraceStore.EventType.ERROR ->
                ContextCompat.getColor(requireContext(), R.color.status_err)
            MessageTraceStore.EventType.TX_TIMEOUT, MessageTraceStore.EventType.TX_RETRY ->
                ContextCompat.getColor(requireContext(), R.color.status_warn)
            else -> ContextCompat.getColor(requireContext(), R.color.text_tertiary)
        }

        return TextView(requireContext()).apply {
            val ssb = SpannableStringBuilder()

            // Timestamp
            ssb.append(timeFmt.format(Date(event.timestampMs)))
            ssb.append(" ($relativeStr) ")

            // Icon + event type
            val typeStart = ssb.length
            ssb.append("$eventIcon ${event.eventType.name}")
            ssb.setSpan(ForegroundColorSpan(eventColor), typeStart, ssb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)

            // Detail
            if (event.detail.isNotEmpty()) {
                ssb.append("\n    ")
                ssb.append(event.detail)
            }

            text = ssb
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setPadding(0, 6, 0, 6)
        }
    }
}
