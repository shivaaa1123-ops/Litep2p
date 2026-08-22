package com.zeengal.litep2p.core

import android.util.Log

/**
 * Phase 13 push lifecycle bridge (signalling.md §4).
 *
 * The SDK deliberately carries **no Firebase dependency** — the host app owns
 * its FirebaseMessagingService and forwards events here. This keeps the AAR
 * lightweight and Play-policy friendly while giving the engine the out-of-band
 * wake channel (discovery cascade tier 3).
 *
 * App-side wiring:
 * ```kotlin
 * class MyFirebaseMessagingService : FirebaseMessagingService() {
 *     override fun onNewToken(token: String) = LiteP2PPush.onNewToken(token)
 *     override fun onMessageReceived(msg: RemoteMessage) {
 *         msg.data["lp"]?.let { LiteP2PPush.onPayload(it) }
 *     }
 * }
 * ```
 *
 * The engine can also request an outbound push to a peer (NAT candidate
 * exchange); register [triggerListener] to actually send it through your
 * Firebase admin backend. Payload format is documented in docs/api-spec.md.
 */
object LiteP2PPush {

    private const val TAG = "LiteP2P_Push"

    /**
     * Called by the engine when it needs a push delivered to [peerId]
     * (engine thread). [candidatesJson] is a flat JSON array of endpoints.
     * Return/behavior is app-owned (usually: POST to your FCM admin relay).
     */
    @Volatile
    var triggerListener: ((peerId: String, candidatesJson: String) -> Unit)? =
        null

    /** Forward a refreshed FCM registration token into the engine. */
    @JvmStatic
    fun onNewToken(token: String): EngineResult =
        EngineResult.fromCode(runCatching {
            LiteP2PNative.nativePushTokenUpdate(token)
        }.getOrDefault(EngineResult.INTERNAL.code))

    /**
     * Forward an inbound FCM data payload (the string your app received;
     * schema in api-spec.md). Seeds the routing directory with NAT candidates.
     */
    @JvmStatic
    fun onPayload(json: String): EngineResult =
        EngineResult.fromCode(runCatching {
            LiteP2PNative.nativePushPayload(json)
        }.getOrDefault(EngineResult.INTERNAL.code))

    internal fun dispatchTrigger(peerId: String, candidatesJson: String) {
        runCatching { triggerListener?.invoke(peerId, candidatesJson) }
            .onFailure { Log.w(TAG, "push trigger dispatch failed: ${it.message}") }
    }
}