package com.zeengal.litep2p

data class PeerInfo(
    val id: String,
    val ip: String,
    val port: Int,
    val latency: Int,
    val connected: Boolean,
    val networkId: String,
    // Peer FSM state from native engine (e.g., DISCOVERED/CONNECTING/CONNECTED/HANDSHAKING/READY).
    // This helps the UI reflect timely progress even when `connected` is false (e.g., Noise sessions
    // only become fully usable at READY).
    val fsmState: String,
    // Connection path - detailed info on HOW the connection was established:
    //   - "LAN"        : Direct connection over local network (private IPs)
    //   - "WAN_DIRECT" : Direct P2P via hole punching (NAT traversal succeeded)
    //   - "TURN"       : Traffic routed through TURN relay server
    //   - "SIGNALING"  : Handshake relayed via signaling server (AP isolation)
    //   - "UNKNOWN"    : Not connected or path not determined
    val connectionType: String
)
