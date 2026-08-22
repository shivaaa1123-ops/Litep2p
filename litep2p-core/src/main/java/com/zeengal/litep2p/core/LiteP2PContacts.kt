package com.zeengal.litep2p.core

/**
 * Phase 13 offline QR contact exchange (signalling.md Phase 4, "LPQ1").
 *
 * A contact card is a base64url blob containing the peer's id, preferred
 * endpoint, optional signaling address, an Ed25519 public key and a detached
 * signature over the body. Scanning one verifies it and seeds the engine's
 * routing directory (discovery cascade tier 1 for that peer thereafter).
 *
 * ```kotlin
 * val qrText  = LiteP2PContacts.buildMyContactQr()      // render as QR
 * val contact = LiteP2PContacts.parseContactQr(scanned) // null if tampered
 * ```
 */
object LiteP2PContacts {

    /** Verified contact card fields (from [parseContactQr]). */
    data class Contact(
        val peerId: String,
        val endpoint: String,
        val signalingAddress: String,
        val signerPublicKeyHex: String,
    ) {
        val ok: Boolean get() = peerId.isNotEmpty()
    }

    /**
     * Builds this device's signed contact payload (QR text). The signing
     * keypair is created once per install and persisted next to the identity.
     * Returns null when the engine has not been started yet.
     */
    @JvmStatic
    fun buildMyContactQr(): String? = runCatching {
        LiteP2PNative.nativeContactsBuild()
    }.getOrNull()

    /**
     * Verifies + parses a scanned payload. Tampered/malformed input returns
     * null; valid input ALSO seeds the native routing directory so the next
     * connect resolves from cache.
     */
    @JvmStatic
    fun parseContactQr(qrText: String): Contact? {
        val json = runCatching { LiteP2PNative.nativeContactsParse(qrText) }
            .getOrNull() ?: return null
        return runCatching {
            val o = org.json.JSONObject(json)
            Contact(
                peerId = o.optString("peer_id"),
                endpoint = o.optString("endpoint"),
                signalingAddress = o.optString("signaling"),
                signerPublicKeyHex = o.optString("signer_pk"),
            )
        }.getOrNull()?.takeIf { it.ok }
    }
}