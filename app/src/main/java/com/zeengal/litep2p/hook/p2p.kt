package com.zeengal.litep2p.hook

object P2P {
    init { System.loadLibrary("litep2p") }

    external fun init()
    external fun startServer(port: Int)
    external fun connect(ip: String, port: Int)
    external fun sendMessage(peerId: String, data: ByteArray)
    external fun stop()

    // UI-facing callback - must exist and be static
    @JvmStatic
    fun onPeersUpdated(peers: Array<com.zeengal.litep2p.PeerInfo>) {
        // This is called from native threads; post to main thread / LiveData
        // Example:
        // runOnUiThread { /* update UI */ }
    }
}