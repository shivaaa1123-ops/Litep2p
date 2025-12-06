package com.zeengal.litep2p

data class PeerInfo(
    val id: String,
    val ip: String,
    val port: Int,
    val latency: Int,
    val connected: Boolean
)