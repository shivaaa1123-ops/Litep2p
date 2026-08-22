package com.zeengal.litep2p.core

import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow

/**
 * Network OS object runtime — public Kotlin surface (Phase 12, master doc
 * §54/§55/§95).
 *
 * Thin by contract: this object only marshals calls across JNI and exposes
 * engine events as a cold-collect [SharedFlow]. ALL routing, replication,
 * dedup and delivery policy enforcement lives in the native runtime.
 *
 * Delivery state changes arrive on engine threads as flat JSON lines
 * (`{"type","kind","peer","at_ms","data"}`); collect [deliveryEvents] to
 * observe them.
 */
object NetworkOs {

    /** Per-send delivery policy (§55). Unsafe values are clamped natively. */
    data class DeliveryPolicy(
        val ttlMs: Long = 3_600_000L,
        val priority: Int = 64,
        val minRemoteCopies: Int = 0,
        val desiredRemoteCopies: Int = 2,
        val requireReceipt: Boolean = true,
        val allowStoreAndForward: Boolean = true,
        val maxPayloadBytes: Int = 262_144,
    )

    /** Per-namespace registration policy (§53). */
    data class NamespacePolicy(
        val namespaceId: String,
        val quotaBytes: Long = 16L * 1024 * 1024,
        val priorityCeiling: Int = 200,
        val maxObjectBytes: Int = 1 shl 20,
        val allowCarrier: Boolean = true,
        val protocolVersion: Int = 1,
    )

    private val _deliveryEvents =
        MutableSharedFlow<String>(extraBufferCapacity = 64)

    /**
     * Delivery/diagnostic events from the Network OS runtime (engine threads).
     * Each element is one flat JSON event line; never blocks the emitter.
     */
    val deliveryEvents: SharedFlow<String> = _deliveryEvents.asSharedFlow()

    /** Wire protocol version of this build (negotiated per connection). */
    val wireProtocolVersion: Int get() = LiteP2PNative.nosWireProtocolVersion()

    /** Register or replace a namespace policy (values clamped natively). */
    fun registerNamespace(policy: NamespacePolicy): EngineResult =
        EngineResult.fromCode(
            LiteP2PNative.nosRegisterNamespace(
                policy.namespaceId, policy.quotaBytes, policy.priorityCeiling,
                policy.maxObjectBytes, policy.allowCarrier,
                policy.protocolVersion))

    /**
     * Sign + publish an object addressed to [destination]. Returns OK with the
     * hex ObjectId in [SendResult.objectId] on acceptance. Accepted is NOT
     * delivered — collect [deliveryEvents] for final state.
     */
    fun send(
        destination: String,
        namespaceId: String,
        payload: ByteArray,
        policy: DeliveryPolicy = DeliveryPolicy(),
    ): SendResult {
        if (destination.isEmpty() || namespaceId.isEmpty()) {
            return SendResult(EngineResult.INVALID_ARG, "")
        }
        val codeOut = IntArray(1)
        val id = LiteP2PNative.nosSend(
            destination, namespaceId, payload, policy.ttlMs,
            policy.priority, policy.minRemoteCopies,
            policy.desiredRemoteCopies, policy.requireReceipt,
            policy.allowStoreAndForward, policy.maxPayloadBytes, codeOut)
        val result = EngineResult.fromCode(codeOut[0])
        return SendResult(result, if (result == EngineResult.OK) id else "")
    }

    /** Cancel a not-yet-delivered object. */
    fun cancel(objectId: String): EngineResult =
        EngineResult.fromCode(LiteP2PNative.nosCancel(objectId))

    /** Delivery status JSON for one object (null when not runnable). */
    fun status(objectId: String): String? =
        LiteP2PNative.nosStatus(objectId)

    /** Public diagnostics snapshot JSON (versions/fingerprint/counters). */
    fun diagnostics(): String? = LiteP2PNative.nosDiagnostics()

    internal fun dispatchDeliveryEvent(json: String) {
        _deliveryEvents.tryEmit(json)
    }
}

/** Result of [NetworkOs.send]: code plus hex ObjectId when OK. */
data class SendResult(val result: EngineResult, val objectId: String) {
    val ok: Boolean get() = result == EngineResult.OK
}
