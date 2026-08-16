package com.zeengal.litep2p.core

/**
 * An incoming file-transfer offer, reported via
 * [LiteP2PListener.onFileTransferOffered].
 *
 * The offer/accept model guarantees that **nothing is written to disk** until
 * the receiver explicitly calls [LiteP2P.acceptFileTransfer] with a save path
 * (or [LiteP2P.declineFileTransfer] to refuse it).
 */
data class FileTransferOffer(
    /** Stable id identifying the transfer on both sender and receiver. */
    val transferId: String,
    /** Peer id of the sender. */
    val peerId: String,
    /** File name as advertised by the sender (not a path). */
    val fileName: String,
    /** Total size of the file in bytes. */
    val sizeBytes: Long
)
