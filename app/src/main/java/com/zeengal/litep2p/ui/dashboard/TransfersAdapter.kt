package com.zeengal.litep2p.ui.dashboard

import android.graphics.BitmapFactory
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.button.MaterialButton
import com.zeengal.litep2p.R
import com.zeengal.litep2p.TransferStore
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Renders one file-transfer event per row: direction, file name/size, live
 * progress + throughput, and context actions (Accept/Decline for offers, Open
 * for completed inbound images, Cancel for running transfers).
 */
class TransfersAdapter(
    private var items: List<TransferStore.TransferEvent> = emptyList()
) : RecyclerView.Adapter<TransfersAdapter.Holder>() {

    private companion object {
        private const val TAG = "TransfersAdapter"
    }

    var onAccept: ((TransferStore.TransferEvent) -> Unit)? = null
    var onDecline: ((TransferStore.TransferEvent) -> Unit)? = null
    var onOpen: ((TransferStore.TransferEvent) -> Unit)? = null
    var onCancel: ((TransferStore.TransferEvent) -> Unit)? = null

    private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.US)

    class Holder(view: View) : RecyclerView.ViewHolder(view) {
        val thumb: ImageView = view.findViewById(R.id.transferThumb)
        val title: TextView = view.findViewById(R.id.transferTitle)
        val sub: TextView = view.findViewById(R.id.transferSub)
        val progress: ProgressBar = view.findViewById(R.id.transferProgress)
        val progressLabel: TextView = view.findViewById(R.id.transferProgressLabel)
        val acceptButton: MaterialButton = view.findViewById(R.id.transferAcceptButton)
        val declineButton: MaterialButton = view.findViewById(R.id.transferDeclineButton)
        val openButton: MaterialButton = view.findViewById(R.id.transferOpenButton)
        val cancelButton: MaterialButton = view.findViewById(R.id.transferCancelButton)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
        val v = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_transfer, parent, false)
        return Holder(v)
    }

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val e = items[position]

        holder.title.text = "${e.fileName}  ·  ${formatBytes(e.sizeBytes)}"

        holder.sub.text = subText(e)

        // Direction indicator; swap in a real thumbnail for completed inbound images.
        holder.thumb.setImageResource(
            if (e.direction == TransferStore.TransferDirection.IN) R.drawable.ic_message
            else R.drawable.ic_send
        )
        if (e.direction == TransferStore.TransferDirection.IN &&
            e.status == TransferStore.TransferStatus.COMPLETED &&
            e.savePath != null
        ) {
            loadThumbnail(holder.thumb, File(e.savePath))
        }

        val running = e.status == TransferStore.TransferStatus.RUNNING
        holder.progress.visibility = if (running) View.VISIBLE else View.GONE
        holder.progressLabel.visibility = if (running) View.VISIBLE else View.GONE
        if (running) {
            holder.progress.progress = e.progressPercent.toInt().coerceIn(0, 100)
            holder.progressLabel.text = String.format(
                Locale.US, "%.0f%%  ·  %s/s",
                e.progressPercent.coerceIn(0f, 100f),
                formatBytes(e.bytesPerSec.toLong())
            )
        }

        val offered = e.status == TransferStore.TransferStatus.OFFERED &&
            e.direction == TransferStore.TransferDirection.IN
        holder.acceptButton.visibility = if (offered) View.VISIBLE else View.GONE
        holder.declineButton.visibility = if (offered) View.VISIBLE else View.GONE

        val canOpen = e.direction == TransferStore.TransferDirection.IN &&
            e.status == TransferStore.TransferStatus.COMPLETED &&
            e.savePath != null &&
            File(e.savePath).exists()
        holder.openButton.visibility = if (canOpen) View.VISIBLE else View.GONE

        holder.cancelButton.visibility = if (running) View.VISIBLE else View.GONE

        holder.acceptButton.setOnClickListener { onAccept?.invoke(e) }
        holder.declineButton.setOnClickListener { onDecline?.invoke(e) }
        holder.openButton.setOnClickListener { onOpen?.invoke(e) }
        holder.cancelButton.setOnClickListener { onCancel?.invoke(e) }
    }

    override fun getItemCount(): Int = items.size

    fun submit(newItems: List<TransferStore.TransferEvent>) {
        items = newItems
        notifyDataSetChanged()
    }

    private fun subText(e: TransferStore.TransferEvent): String {
        val time = timeFmt.format(Date(e.timestampMs))
        val dir = if (e.direction == TransferStore.TransferDirection.IN) "IN " else "OUT"
        val status = when (e.status) {
            TransferStore.TransferStatus.OFFERED -> "offered"
            TransferStore.TransferStatus.RUNNING -> "transferring"
            TransferStore.TransferStatus.COMPLETED -> "completed"
            TransferStore.TransferStatus.FAILED -> "failed"
            TransferStore.TransferStatus.DECLINED -> "declined"
            TransferStore.TransferStatus.CANCELLED -> "cancelled"
        }
        val peer = shortId(e.peerId)
        val error = if (e.error != null && e.status == TransferStore.TransferStatus.FAILED) {
            "  ·  ${e.error}"
        } else {
            ""
        }
        return "$time  [$dir]  $peer  ·  $status$error"
    }

    private fun shortId(id: String): String = if (id.length > 12) id.take(12) + "…" else id

    /** In-place, memory-light thumbnail decode for received images. */
    private fun loadThumbnail(iv: ImageView, file: File) {
        if (!file.exists() || !file.isFile) return
        try {
            val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeFile(file.absolutePath, bounds)
            if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return
            var sample = 1
            while (bounds.outWidth / sample > 96 && bounds.outHeight / sample > 96) sample *= 2
            val opts = BitmapFactory.Options().apply { inSampleSize = sample }
            val bmp = BitmapFactory.decodeFile(file.absolutePath, opts) ?: return
            iv.setImageBitmap(bmp)
        } catch (t: Throwable) {
            Log.w(TAG, "Thumbnail decode failed for ${file.name}: ${t.message}")
        }
    }

    private fun formatBytes(n: Long): String = when {
        n >= 1024L * 1024L -> String.format(Locale.US, "%.1f MB", n / (1024.0 * 1024.0))
        n >= 1024L -> String.format(Locale.US, "%.1f KB", n / 1024.0)
        else -> "$n B"
    }
}