package com.zeengal.litep2p.ui.dashboard

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import android.widget.Toast
import androidx.core.content.FileProvider
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.button.MaterialButton
import com.zeengal.litep2p.R
import com.zeengal.litep2p.TransferStore
import com.zeengal.litep2p.core.EngineResult
import java.io.File

/**
 * Files tab: a live view of the engine's file-transfer activity.
 *
 * Inbound offers show Accept/Decline inline, running transfers show progress +
 * throughput, and completed inbound images show a thumbnail with an Open action
 * (viewed through the app's FileProvider).
 */
class TransfersFragment : Fragment() {

    private lateinit var adapter: TransfersAdapter
    private var emptyState: View? = null
    private var countText: TextView? = null

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val root = inflater.inflate(R.layout.fragment_transfers, container, false)

        countText = root.findViewById(R.id.transferCountText)

        val list = root.findViewById<RecyclerView>(R.id.transfersRecycler)
        list.layoutManager = LinearLayoutManager(requireContext())

        adapter = TransfersAdapter()
        adapter.onAccept = { ev -> accept(ev) }
        adapter.onDecline = { ev -> decline(ev) }
        adapter.onCancel = { ev -> cancel(ev) }
        adapter.onOpen = { ev -> openReceivedFile(ev) }

        root.findViewById<MaterialButton>(R.id.clearTransfersButton).setOnClickListener {
            TransferStore.clear()
        }

        list.adapter = adapter
        return root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        emptyState = view.findViewById(R.id.transfersEmptyState)

        TransferStore.transferEvents.observe(viewLifecycleOwner) { events ->
            adapter.submit(events)
            countText?.text = events.size.toString()
            emptyState?.visibility = if (events.isEmpty()) View.VISIBLE else View.GONE
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        countText = null
        emptyState = null
    }

    private fun accept(ev: TransferStore.TransferEvent) {
        val rc = TransferStore.acceptOffer(ev)
        val msg = if (rc == EngineResult.OK) {
            "Accepting ${ev.fileName}…"
        } else {
            "Accept failed: $rc (peer offline or transfer expired)"
        }
        Toast.makeText(requireContext(), msg, Toast.LENGTH_SHORT).show()
    }

    private fun decline(ev: TransferStore.TransferEvent) {
        val rc = TransferStore.declineOffer(ev)
        Toast.makeText(
            requireContext(),
            if (rc == EngineResult.OK) "Declined ${ev.fileName}" else "Decline failed: $rc",
            Toast.LENGTH_SHORT
        ).show()
    }

    private fun cancel(ev: TransferStore.TransferEvent) {
        val rc = TransferStore.cancelTransfer(ev)
        Toast.makeText(
            requireContext(),
            if (rc == EngineResult.OK) "Cancelling ${ev.fileName}…" else "Cancel failed: $rc",
            Toast.LENGTH_SHORT
        ).show()
    }

    /** Opens a completed inbound image with the system viewer (FileProvider). */
    private fun openReceivedFile(ev: TransferStore.TransferEvent) {
        val path = ev.savePath
        if (path.isNullOrBlank()) return
        val file = File(path)
        if (!file.exists() || !file.isFile) {
            Toast.makeText(requireContext(), "Received file is missing: $path", Toast.LENGTH_LONG).show()
            return
        }
        val context = requireContext()
        val uri: Uri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            file
        )
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "image/*")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        runCatching { startActivity(intent) }
            .onFailure {
                Toast.makeText(context, "No app available to open the image", Toast.LENGTH_SHORT).show()
            }
    }
}