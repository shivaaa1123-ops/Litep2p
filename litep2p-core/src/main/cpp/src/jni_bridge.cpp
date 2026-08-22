/*
 * jni_bridge.cpp — Phase 3 Android binding layer for LiteP2P.
 *
 * This file is the ONLY place that knows about both JNI and the LiteP2P engine.
 * Every Java_com_zeengal_litep2p_core_LiteP2PNative_* entry point is a thin
 * wrapper over the public C ABI (include/litep2p.h); the bridge no longer owns
 * or touches a SessionManager. Engine ownership lives in litep2p_c_api.cpp.
 *
 * Event flow (native -> Java):
 *   - litep2p_set_callbacks() registers C ABI callbacks here; they forward
 *     lifecycle / peers / messages / telemetry into
 *     com.zeengal.litep2p.core.NativeEvents.
 *   - The engine's log stream (logger.cpp) and the app-level ACK path
 *     (message_handler.cpp) still emit through the sendToLogUI /
 *     sendMessageAckToUI hooks declared in jni_bridge.h, which forward into
 *     the same NativeEvents surface.
 *
 * JNI discipline (api-spec.md §7.2): every potentially-throwing JNI call is
 * followed by ExceptionCheck/ExceptionClear so no pending exception ever leaks
 * across the boundary.
 */

#include "jni_bridge.h"
#include "jni_helpers.h"
#include "logger.h"
#include "litep2p.h"
#include "anomaly_reporter.h"

#include <jni.h>
#include <signal.h>

#include <atomic>
#include <mutex>
#include <string>
#include <vector>

#ifdef __ANDROID__
#include <android/log.h>
#endif

namespace {

std::string jstring_to_utf8(JNIEnv* env, jstring s) {
    if (!env || !s) return {};
    const char* chars = env->GetStringUTFChars(s, nullptr);
    if (!chars) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return {};
    }
    std::string out(chars);
    env->ReleaseStringUTFChars(s, chars);
    return out;
}

void clear_any_exception(JNIEnv* env) {
    if (env && env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
}

} // namespace

// ---------------------------------------------------------------------------
// JNI callback surface.
//
// All native->Java events are routed through a single core class,
// com.zeengal.litep2p.core.NativeEvents, which forwards them to LiteP2P
// listeners. This decouples the binding layer from any consumer (app) classes.
//
// PeerInfo is constructed reflectively (com.zeengal.litep2p.core.PeerInfo)
// with its stable 8-argument constructor.
// ---------------------------------------------------------------------------
static jclass g_eventsClass = nullptr;
static jmethodID g_onPeersUpdated = nullptr;
// Phase 12: Network OS delivery/diagnostic events (optional convenience).
static jmethodID g_onNosDeliveryEvent = nullptr;
static jmethodID g_onEngineStartComplete = nullptr;
static jmethodID g_onEngineStopComplete = nullptr;
static jmethodID g_onMessageReceived = nullptr;
static jmethodID g_addLogMethod = nullptr;
static jmethodID g_addTelemetryJsonMethod = nullptr;
static jmethodID g_onAckReceivedMethod = nullptr;
static jmethodID g_onOverlayDeliveryMethod = nullptr;
static jmethodID g_onFileTransferOfferedMethod = nullptr;
static jmethodID g_onTransferProgressMethod = nullptr;
static jmethodID g_onTransferCompletedMethod = nullptr;
// Voice call callbacks (offer/state/frame).
static jmethodID g_onVoiceCallOfferedMethod = nullptr;
static jmethodID g_onVoiceCallStateMethod = nullptr;
static jmethodID g_onVoiceFrameMethod = nullptr;
// v0.4 callbacks (reliable send / presence / ping / lookup / invite).
static jmethodID g_onDeliveryStatusMethod = nullptr;
static jmethodID g_onPresenceMethod = nullptr;
static jmethodID g_onPingResultMethod = nullptr;
static jmethodID g_onLookupResultMethod = nullptr;
static jmethodID g_onInviteReceivedMethod = nullptr;
static jclass g_peerInfoClass = nullptr;
static jmethodID g_peerInfoCtor = nullptr;

namespace {

std::mutex g_jni_cache_mutex;
bool g_jni_cache_initialized = false;

void safeDeleteGlobalRef(JNIEnv* env, jobject& ref) {
    if (env && ref) {
        env->DeleteGlobalRef(ref);
        ref = nullptr;
    }
}

} // namespace

// ---------------------------------------------------------------------------
// C ABI event callbacks -> NativeEvents (registered in nativeInit).
//
// These run on engine threads; getJNIEnv() attaches the thread to the VM.
// The C ABI guarantees buffer validity for the duration of each call.
// ---------------------------------------------------------------------------
namespace {

void cabi_on_engine_started(void* /*user_data*/) {
    JNIEnv* env = getJNIEnv();
    if (!env || !g_eventsClass || !g_onEngineStartComplete) return;
    env->CallStaticVoidMethod(g_eventsClass, g_onEngineStartComplete);
    if (env->ExceptionCheck()) {
        nativeLog("JNI_BRIDGE: Exception calling NativeEvents.onEngineStartComplete");
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
}

void cabi_on_engine_stopped(void* /*user_data*/) {
    JNIEnv* env = getJNIEnv();
    if (!env || !g_eventsClass || !g_onEngineStopComplete) return;
    env->CallStaticVoidMethod(g_eventsClass, g_onEngineStopComplete);
    if (env->ExceptionCheck()) {
        nativeLog("JNI_BRIDGE: Exception calling NativeEvents.onEngineStopComplete");
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
}

// Phase 12: Network OS delivery/diagnostic event → NativeEvents.
void cabi_on_nos_delivery_event(const char* json, void* /*user*/) {
    JNIEnv* env = getJNIEnv();
    if (!env || !g_eventsClass || !g_onNosDeliveryEvent || !json) return;
    jstring jjson = env->NewStringUTF(json);
    if (!jjson) return;
    env->CallStaticVoidMethod(g_eventsClass, g_onNosDeliveryEvent, jjson);
    env->DeleteLocalRef(jjson);
    if (env->ExceptionCheck()) {
        nativeLog("JNI_BRIDGE: Exception calling NativeEvents.onNosDeliveryEvent");
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
}

void cabi_on_peers_changed(void* /*user_data*/, const litep2p_peer_info_t* peers,
                           uint32_t count) {
    JNIEnv* env = getJNIEnv();
    if (!env) {
        nativeLog("JNI_ERROR: Failed to get JNIEnv in cabi_on_peers_changed");
        return;
    }
    if (!g_eventsClass || !g_onPeersUpdated || !g_peerInfoClass || !g_peerInfoCtor) {
        nativeLog("JNI_ERROR: JNI references not initialized in cabi_on_peers_changed");
        return;
    }

    jobjectArray arr = env->NewObjectArray((jsize)count, g_peerInfoClass, nullptr);
    if (!arr) {
        nativeLog("JNI_ERROR: Failed to create peer array");
        clear_any_exception(env);
        return;
    }

    for (uint32_t i = 0; i < count; ++i) {
        const litep2p_peer_info_t& p = peers[i];

        jstring jid = env->NewStringUTF(p.peer_id);
        jstring jip = env->NewStringUTF(p.ip);
        jstring jnetworkId = env->NewStringUTF(p.network_id);
        jstring jFsmState = env->NewStringUTF(p.fsm_state);
        jstring jConnectionType = env->NewStringUTF(p.connection_path);
        if (!jid || !jip || !jnetworkId || !jFsmState || !jConnectionType) {
            nativeLog("JNI_ERROR: Failed to create jstrings for peer " + std::string(p.peer_id));
            clear_any_exception(env);
            if (jid) env->DeleteLocalRef(jid);
            if (jip) env->DeleteLocalRef(jip);
            if (jnetworkId) env->DeleteLocalRef(jnetworkId);
            if (jFsmState) env->DeleteLocalRef(jFsmState);
            if (jConnectionType) env->DeleteLocalRef(jConnectionType);
            env->DeleteLocalRef(arr);
            return;
        }

        jobject obj = env->NewObject(
            g_peerInfoClass,
            g_peerInfoCtor,
            jid,
            jip,
            (jint)p.port,
            (jint)p.latency,
            (jboolean)(p.connected != 0),
            jnetworkId,
            jFsmState,
            jConnectionType,
            (jlong)p.last_seen_ms);

        env->DeleteLocalRef(jid);
        env->DeleteLocalRef(jip);
        env->DeleteLocalRef(jnetworkId);
        env->DeleteLocalRef(jFsmState);
        env->DeleteLocalRef(jConnectionType);

        if (!obj) {
            nativeLog("JNI_ERROR: Failed to create PeerInfo for peer " + std::string(p.peer_id));
            clear_any_exception(env);
            env->DeleteLocalRef(arr);
            return;
        }

        env->SetObjectArrayElement(arr, (jsize)i, obj);
        env->DeleteLocalRef(obj);
        if (env->ExceptionCheck()) {
            nativeLog("JNI_ERROR: Failed to set peer array element for " + std::string(p.peer_id));
            env->ExceptionDescribe();
            env->ExceptionClear();
            env->DeleteLocalRef(arr);
            return;
        }
    }

    env->CallStaticVoidMethod(g_eventsClass, g_onPeersUpdated, arr);
    if (env->ExceptionCheck()) {
        nativeLog("JNI_ERROR: Exception calling NativeEvents.onPeersUpdated");
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
    env->DeleteLocalRef(arr);
}

void cabi_on_message_received(void* /*user_data*/, const char* peer_id,
                              const uint8_t* data, uint32_t len) {
    JNIEnv* env = getJNIEnv();
    if (!env || !g_eventsClass || !g_onMessageReceived) return;

    jstring jPeerId = env->NewStringUTF(peer_id ? peer_id : "");
    jbyteArray jMessage = env->NewByteArray((jsize)len);
    if (!jPeerId || !jMessage) {
        clear_any_exception(env);
        if (jPeerId) env->DeleteLocalRef(jPeerId);
        if (jMessage) env->DeleteLocalRef(jMessage);
        return;
    }
    if (len > 0 && data) {
        env->SetByteArrayRegion(jMessage, 0, (jsize)len, reinterpret_cast<const jbyte*>(data));
    }

    env->CallStaticVoidMethod(g_eventsClass, g_onMessageReceived, jPeerId, jMessage);
    if (env->ExceptionCheck()) {
        nativeLog("JNI_BRIDGE: Exception calling NativeEvents.onMessageReceived");
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
    env->DeleteLocalRef(jPeerId);
    env->DeleteLocalRef(jMessage);
}

void cabi_on_log(void* /*user_data*/, int level, const char* line) {
    // The engine log stream routes through sendToLogUI (logger.cpp) with the
    // real level; this forwarder exists for ABI completeness.
    if (line) sendToLogUI(level, line);
}

void cabi_on_telemetry(void* /*user_data*/, const char* json) {
    if (json) sendTelemetryToUI(json);
}

void cabi_on_overlay_delivery(void* /*user_data*/, const char* frame_id, int delivered) {
    JNIEnv* env = getJNIEnv();
    if (!env || !g_eventsClass || !g_onOverlayDeliveryMethod) return;

    jstring jFrameId = env->NewStringUTF(frame_id ? frame_id : "");
    if (!jFrameId) {
        clear_any_exception(env);
        return;
    }
    env->CallStaticVoidMethod(g_eventsClass, g_onOverlayDeliveryMethod, jFrameId,
                              delivered != 0 ? JNI_TRUE : JNI_FALSE);
    if (env->ExceptionCheck()) {
        nativeLog("JNI_BRIDGE: Exception calling NativeEvents.onOverlayDelivery");
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
    env->DeleteLocalRef(jFrameId);
}

// ---------------------------------------------------------------------------
// v0.4 C ABI callbacks -> NativeEvents (reliable send / presence / ping /
// lookup / invite). Each runs on an engine thread; getJNIEnv() attaches it.
// ---------------------------------------------------------------------------
void cabi_on_delivery_status(void* /*user_data*/, const char* msg_id, int status,
                             const char* reason) {
    JNIEnv* env = getJNIEnv();
    if (!env || !g_eventsClass || !g_onDeliveryStatusMethod) return;
    jstring jMsgId = env->NewStringUTF(msg_id ? msg_id : "");
    jstring jReason = env->NewStringUTF(reason ? reason : "");
    if (!jMsgId || !jReason) {
        clear_any_exception(env);
        if (jMsgId) env->DeleteLocalRef(jMsgId);
        if (jReason) env->DeleteLocalRef(jReason);
        return;
    }
    env->CallStaticVoidMethod(g_eventsClass, g_onDeliveryStatusMethod, jMsgId,
                              (jint)status, jReason);
    if (env->ExceptionCheck()) {
        nativeLog("JNI_BRIDGE: Exception calling NativeEvents.onDeliveryStatus");
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
    env->DeleteLocalRef(jMsgId);
    env->DeleteLocalRef(jReason);
}

void cabi_on_presence(void* /*user_data*/, const char* peer_id, int online,
                      int64_t last_seen_ms) {
    JNIEnv* env = getJNIEnv();
    if (!env || !g_eventsClass || !g_onPresenceMethod) return;
    jstring jPeerId = env->NewStringUTF(peer_id ? peer_id : "");
    if (!jPeerId) {
        clear_any_exception(env);
        return;
    }
    env->CallStaticVoidMethod(g_eventsClass, g_onPresenceMethod, jPeerId,
                              online != 0 ? JNI_TRUE : JNI_FALSE, (jlong)last_seen_ms);
    if (env->ExceptionCheck()) {
        nativeLog("JNI_BRIDGE: Exception calling NativeEvents.onPresence");
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
    env->DeleteLocalRef(jPeerId);
}

void cabi_on_ping_result(void* /*user_data*/, const char* peer_id, int64_t rtt_ms) {
    JNIEnv* env = getJNIEnv();
    if (!env || !g_eventsClass || !g_onPingResultMethod) return;
    jstring jPeerId = env->NewStringUTF(peer_id ? peer_id : "");
    if (!jPeerId) {
        clear_any_exception(env);
        return;
    }
    env->CallStaticVoidMethod(g_eventsClass, g_onPingResultMethod, jPeerId, (jlong)rtt_ms);
    if (env->ExceptionCheck()) {
        nativeLog("JNI_BRIDGE: Exception calling NativeEvents.onPingResult");
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
    env->DeleteLocalRef(jPeerId);
}

void cabi_on_lookup_result(void* /*user_data*/, const char* alias, const char* peer_id,
                           int online, int64_t last_seen_ms) {
    JNIEnv* env = getJNIEnv();
    if (!env || !g_eventsClass || !g_onLookupResultMethod) return;
    jstring jAlias = env->NewStringUTF(alias ? alias : "");
    jstring jPeerId = env->NewStringUTF(peer_id ? peer_id : "");
    if (!jAlias || !jPeerId) {
        clear_any_exception(env);
        if (jAlias) env->DeleteLocalRef(jAlias);
        if (jPeerId) env->DeleteLocalRef(jPeerId);
        return;
    }
    env->CallStaticVoidMethod(g_eventsClass, g_onLookupResultMethod, jAlias, jPeerId,
                              online != 0 ? JNI_TRUE : JNI_FALSE, (jlong)last_seen_ms);
    if (env->ExceptionCheck()) {
        nativeLog("JNI_BRIDGE: Exception calling NativeEvents.onLookupResult");
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
    env->DeleteLocalRef(jAlias);
    env->DeleteLocalRef(jPeerId);
}

void cabi_on_invite_received(void* /*user_data*/, const char* from_peer_id) {
    JNIEnv* env = getJNIEnv();
    if (!env || !g_eventsClass || !g_onInviteReceivedMethod) return;
    jstring jFrom = env->NewStringUTF(from_peer_id ? from_peer_id : "");
    if (!jFrom) {
        clear_any_exception(env);
        return;
    }
    env->CallStaticVoidMethod(g_eventsClass, g_onInviteReceivedMethod, jFrom);
    if (env->ExceptionCheck()) {
        nativeLog("JNI_BRIDGE: Exception calling NativeEvents.onInviteReceived");
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
    env->DeleteLocalRef(jFrom);
}

void cabi_on_file_transfer_offered(void* /*user_data*/, const litep2p_file_offer_t* offer) {
    JNIEnv* env = getJNIEnv();
    if (!env || !g_eventsClass || !g_onFileTransferOfferedMethod || !offer) return;

    jstring jId = env->NewStringUTF(offer->transfer_id);
    if (!jId) {
        clear_any_exception(env);
        return;
    }
    jstring jPeer = env->NewStringUTF(offer->peer_id);
    if (!jPeer) {
        env->DeleteLocalRef(jId);
        clear_any_exception(env);
        return;
    }
    jstring jName = env->NewStringUTF(offer->file_name);
    if (!jName) {
        env->DeleteLocalRef(jId);
        env->DeleteLocalRef(jPeer);
        clear_any_exception(env);
        return;
    }
    env->CallStaticVoidMethod(g_eventsClass, g_onFileTransferOfferedMethod,
                              jId, jPeer, jName, static_cast<jlong>(offer->size_bytes));
    if (env->ExceptionCheck()) {
        nativeLog("JNI_BRIDGE: Exception calling NativeEvents.onFileTransferOffered");
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
    env->DeleteLocalRef(jId);
    env->DeleteLocalRef(jPeer);
    env->DeleteLocalRef(jName);
}

void cabi_on_transfer_progress(void* /*user_data*/, const char* transfer_id,
                               float progress_percent, float bytes_per_sec) {
    JNIEnv* env = getJNIEnv();
    if (!env || !g_eventsClass || !g_onTransferProgressMethod || !transfer_id) return;

    jstring jId = env->NewStringUTF(transfer_id);
    if (!jId) {
        clear_any_exception(env);
        return;
    }
    env->CallStaticVoidMethod(g_eventsClass, g_onTransferProgressMethod,
                              jId, static_cast<jfloat>(progress_percent),
                              static_cast<jfloat>(bytes_per_sec));
    if (env->ExceptionCheck()) {
        nativeLog("JNI_BRIDGE: Exception calling NativeEvents.onTransferProgress");
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
    env->DeleteLocalRef(jId);
}

void cabi_on_transfer_completed(void* /*user_data*/, const char* transfer_id,
                                int success, const char* error) {
    JNIEnv* env = getJNIEnv();
    if (!env || !g_eventsClass || !g_onTransferCompletedMethod || !transfer_id) return;

    jstring jId = env->NewStringUTF(transfer_id);
    if (!jId) {
        clear_any_exception(env);
        return;
    }
    jstring jError = error ? env->NewStringUTF(error) : nullptr;
    if (error && !jError) {
        env->DeleteLocalRef(jId);
        clear_any_exception(env);
        return;
    }
    env->CallStaticVoidMethod(g_eventsClass, g_onTransferCompletedMethod,
                              jId, success ? JNI_TRUE : JNI_FALSE, jError);
    if (env->ExceptionCheck()) {
        nativeLog("JNI_BRIDGE: Exception calling NativeEvents.onTransferCompleted");
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
    if (jError) env->DeleteLocalRef(jError);
    env->DeleteLocalRef(jId);
}

void cabi_on_voice_call_offered(void* /*user_data*/, const litep2p_voice_offer_t* offer) {
    JNIEnv* env = getJNIEnv();
    if (!env || !g_eventsClass || !g_onVoiceCallOfferedMethod || !offer) return;

    jstring jId = env->NewStringUTF(offer->call_id);
    if (!jId) {
        clear_any_exception(env);
        return;
    }
    jstring jPeer = env->NewStringUTF(offer->peer_id);
    if (!jPeer) {
        env->DeleteLocalRef(jId);
        clear_any_exception(env);
        return;
    }
    jstring jCodec = env->NewStringUTF(offer->codec);
    if (!jCodec) {
        env->DeleteLocalRef(jId);
        env->DeleteLocalRef(jPeer);
        clear_any_exception(env);
        return;
    }
    env->CallStaticVoidMethod(g_eventsClass, g_onVoiceCallOfferedMethod,
                              jId, jPeer, jCodec,
                              static_cast<jint>(offer->sample_rate),
                              static_cast<jint>(offer->channels),
                              static_cast<jint>(offer->frame_ms));
    if (env->ExceptionCheck()) {
        nativeLog("JNI_BRIDGE: Exception calling NativeEvents.onVoiceCallOffered");
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
    env->DeleteLocalRef(jId);
    env->DeleteLocalRef(jPeer);
    env->DeleteLocalRef(jCodec);
}

void cabi_on_voice_call_state(void* /*user_data*/, const char* call_id,
                              const char* peer_id, int state, const char* detail) {
    JNIEnv* env = getJNIEnv();
    if (!env || !g_eventsClass || !g_onVoiceCallStateMethod || !call_id || !peer_id) return;

    jstring jId = env->NewStringUTF(call_id);
    if (!jId) {
        clear_any_exception(env);
        return;
    }
    jstring jPeer = env->NewStringUTF(peer_id);
    if (!jPeer) {
        env->DeleteLocalRef(jId);
        clear_any_exception(env);
        return;
    }
    jstring jDetail = detail ? env->NewStringUTF(detail) : nullptr;
    if (detail && !jDetail) {
        env->DeleteLocalRef(jId);
        env->DeleteLocalRef(jPeer);
        clear_any_exception(env);
        return;
    }
    env->CallStaticVoidMethod(g_eventsClass, g_onVoiceCallStateMethod,
                              jId, jPeer, static_cast<jint>(state), jDetail);
    if (env->ExceptionCheck()) {
        nativeLog("JNI_BRIDGE: Exception calling NativeEvents.onVoiceCallStateChanged");
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
    if (jDetail) env->DeleteLocalRef(jDetail);
    env->DeleteLocalRef(jId);
    env->DeleteLocalRef(jPeer);
}

void cabi_on_voice_frame(void* /*user_data*/, const char* call_id,
                         const char* peer_id, const uint8_t* data, uint32_t len) {
    JNIEnv* env = getJNIEnv();
    if (!env || !g_eventsClass || !g_onVoiceFrameMethod || !call_id || !peer_id) return;

    jstring jId = env->NewStringUTF(call_id);
    if (!jId) {
        clear_any_exception(env);
        return;
    }
    jstring jPeer = env->NewStringUTF(peer_id);
    if (!jPeer) {
        env->DeleteLocalRef(jId);
        clear_any_exception(env);
        return;
    }
    jbyteArray jData = env->NewByteArray(static_cast<jsize>(len));
    if (!jData) {
        env->DeleteLocalRef(jId);
        env->DeleteLocalRef(jPeer);
        clear_any_exception(env);
        return;
    }
    if (len > 0) {
        env->SetByteArrayRegion(jData, 0, static_cast<jsize>(len),
                                reinterpret_cast<const jbyte*>(data));
    }
    env->CallStaticVoidMethod(g_eventsClass, g_onVoiceFrameMethod, jId, jPeer, jData);
    if (env->ExceptionCheck()) {
        nativeLog("JNI_BRIDGE: Exception calling NativeEvents.onVoiceFrameReceived");
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
    env->DeleteLocalRef(jData);
    env->DeleteLocalRef(jId);
    env->DeleteLocalRef(jPeer);
}

void register_cabi_callbacks() {
    litep2p_callbacks_t cb{};
    cb.struct_size = sizeof(litep2p_callbacks_t);
    cb.user_data = nullptr;
    cb.on_engine_started = cabi_on_engine_started;
    cb.on_engine_stopped = cabi_on_engine_stopped;
    cb.on_peers_changed = cabi_on_peers_changed;
    cb.on_message_received = cabi_on_message_received;
    cb.on_log = cabi_on_log;
    cb.on_telemetry = cabi_on_telemetry;
    cb.on_overlay_delivery = cabi_on_overlay_delivery;
    // v0.4 callbacks (reliable send / presence / ping / lookup / invite).
    cb.on_delivery_status = cabi_on_delivery_status;
    cb.on_presence = cabi_on_presence;
    cb.on_ping_result = cabi_on_ping_result;
    cb.on_lookup_result = cabi_on_lookup_result;
    cb.on_invite_received = cabi_on_invite_received;

    const litep2p_result_t rc = litep2p_set_callbacks(&cb);
    if (rc != LITEP2P_OK) {
        nativeLog("JNI_BRIDGE: litep2p_set_callbacks failed: " +
                  std::string(litep2p_result_string(rc)));
    }

    // Phase 12: Network OS delivery/diagnostic event callback (independent of
    // litep2p_callbacks_t; registration itself never touches the engine).
    litep2p_nos_set_delivery_event_cb(cabi_on_nos_delivery_event, nullptr);

    // File-transfer offer/progress/completion callbacks (offer/accept model).
    litep2p_transfer_callbacks_t tc{};
    tc.struct_size = sizeof(litep2p_transfer_callbacks_t);
    tc.user_data = nullptr;
    tc.on_file_transfer_offered = cabi_on_file_transfer_offered;
    tc.on_progress = cabi_on_transfer_progress;
    tc.on_completed = cabi_on_transfer_completed;

    const litep2p_result_t trc = litep2p_set_transfer_callbacks(&tc);
    if (trc != LITEP2P_OK) {
        nativeLog("JNI_BRIDGE: litep2p_set_transfer_callbacks failed: " +
                  std::string(litep2p_result_string(trc)));
    }

    // Voice-call offer/state/frame callbacks.
    litep2p_voice_callbacks_t vc{};
    vc.struct_size = sizeof(litep2p_voice_callbacks_t);
    vc.user_data = nullptr;
    vc.on_voice_call_offered = cabi_on_voice_call_offered;
    vc.on_voice_call_state = cabi_on_voice_call_state;
    vc.on_voice_frame = cabi_on_voice_frame;

    const litep2p_result_t vrc = litep2p_set_voice_call_callbacks(&vc);
    if (vrc != LITEP2P_OK) {
        nativeLog("JNI_BRIDGE: litep2p_set_voice_call_callbacks failed: " +
                  std::string(litep2p_result_string(vrc)));
    }
}

} // namespace

// ---------------------------------------------------------------------------
// Library load/unload
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    (void)reserved;

    // Ignore SIGPIPE to prevent process termination on socket write errors.
    signal(SIGPIPE, SIG_IGN);
    // Ignore SIGUSR1 to survive interruption signals (used by test suites).
    signal(SIGUSR1, SIG_IGN);

    jni_helpers_on_load(vm);
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT void JNICALL JNI_OnUnload(JavaVM* vm, void* reserved) {
    (void)reserved;
    // Release cached global refs while the VM is still available. The engine
    // itself is process-wide and dies with the process; a forced shutdown here
    // could block VM teardown.
    jni_helpers_on_unload(vm);
}


// ---------------------------------------------------------------------------
// JNI entry points — lifecycle (thin wrappers over the C ABI).
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_nativeInit(
    JNIEnv* env, jobject /*thiz*/,
    jstring peerId, jstring commsMode, jint listenPort,
    jstring filesDir, jstring configPath,
    jboolean enableEncryption, jboolean enableDiscovery, jboolean enableFileTransfer,
    jboolean telemetryEnabled, jint telemetryIntervalMs, jboolean singleThreadMode) {

    // Cache JNI class/method references before the engine can emit anything.
    if (!jniBridgeInit(env)) {
        nativeLog("JNI_BRIDGE: FATAL - JNI bridge initialization failed in nativeInit");
        clear_any_exception(env);
        return (jint)LITEP2P_ERR_INTERNAL;
    }

    // Register the C ABI event callbacks (idempotent; safe to re-register).
    register_cabi_callbacks();

    litep2p_config_t cfg;
    litep2p_config_init(&cfg);

    const std::string peer_id = jstring_to_utf8(env, peerId);
    const std::string comms_mode = jstring_to_utf8(env, commsMode);
    const std::string files_dir = jstring_to_utf8(env, filesDir);
    const std::string config_path = jstring_to_utf8(env, configPath);

    cfg.peer_id = peer_id.empty() ? nullptr : peer_id.c_str();
    cfg.comms_mode = comms_mode.empty() ? "AUTO" : comms_mode.c_str();
    cfg.listen_port = listenPort;
    cfg.files_dir = files_dir.empty() ? nullptr : files_dir.c_str();
    cfg.config_path = config_path.empty() ? nullptr : config_path.c_str();
    cfg.enable_encryption = enableEncryption ? 1 : 0;
    cfg.enable_discovery = enableDiscovery ? 1 : 0;
    cfg.enable_file_transfer = enableFileTransfer ? 1 : 0;
    cfg.telemetry_enabled = telemetryEnabled ? 1 : 0;
    cfg.telemetry_interval_ms = telemetryIntervalMs;
    cfg.single_thread_mode = singleThreadMode ? 1 : 0;

    const litep2p_result_t rc = litep2p_init(&cfg);
    nativeLog("JNI_BRIDGE: litep2p_init -> " + std::string(litep2p_result_string(rc)));
    return (jint)rc;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_nativeStart(JNIEnv* env, jobject /*thiz*/) {
    (void)env;
    nativeLog("JNI_BRIDGE: litep2p_start requested");
    // litep2p_start() blocks until the engine is up; completion is also
    // delivered via on_engine_started -> NativeEvents.onEngineStartComplete.
    const litep2p_result_t rc = litep2p_start();
    nativeLog("JNI_BRIDGE: litep2p_start -> " + std::string(litep2p_result_string(rc)));
    return (jint)rc;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_nativeStop(JNIEnv* env, jobject /*thiz*/) {
    (void)env;
    nativeLog("JNI_BRIDGE: litep2p_stop requested");
    const litep2p_result_t rc = litep2p_stop();
    return (jint)rc;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_nativeShutdown(JNIEnv* env, jobject /*thiz*/) {
    (void)env;
    nativeLog("JNI_BRIDGE: litep2p_shutdown requested");
    const litep2p_result_t rc = litep2p_shutdown();
    return (jint)rc;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_nativeGetState(JNIEnv* env, jobject /*thiz*/) {
    (void)env;
    return (jint)litep2p_get_state();
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_nativeGetPeerId(JNIEnv* env, jobject /*thiz*/) {
    char buf[256] = {0};
    const litep2p_result_t rc = litep2p_get_peer_id(buf, sizeof(buf));
    if (rc < 0) {
        return env->NewStringUTF("");
    }
    return env->NewStringUTF(buf);
}

// Push platform device info (brand/model/os/abi as a JSON object string) into
// the AnomalyReporter so incident files carry the device that experienced the
// anomaly (field-data collection). No-op on engines without the reporter.
extern "C" JNIEXPORT void JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_nativeSetAnomalyDeviceInfo(JNIEnv* env, jobject /*thiz*/, jstring json) {
    if (json == nullptr) return;
    const char* cstr = env->GetStringUTFChars(json, nullptr);
    if (cstr == nullptr) return;
    AnomalyReporter::getInstance().setDeviceInfo(std::string(cstr));
    env->ReleaseStringUTFChars(json, cstr);
}

// Resolved incidents directory (or empty when the reporter is disabled).
extern "C" JNIEXPORT jstring JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_nativeGetAnomalyDirectory(JNIEnv* env, jobject /*thiz*/) {
    return env->NewStringUTF(AnomalyReporter::getInstance().directory().c_str());
}


// ---------------------------------------------------------------------------
// JNI entry points — peer operations, messaging, security.
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_connect(JNIEnv* env, jobject /*thiz*/, jstring peerId) {
    const std::string peer_id = jstring_to_utf8(env, peerId);
    if (peer_id.empty()) return (jint)LITEP2P_ERR_INVALID_ARG;
    nativeLog("JNI_BRIDGE: connect requested for " + peer_id);
    return (jint)litep2p_connect(peer_id.c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_addPeer(JNIEnv* env, jobject /*thiz*/,
                                                    jstring peerId, jstring networkId) {
    const std::string peer_id = jstring_to_utf8(env, peerId);
    const std::string network_id = jstring_to_utf8(env, networkId);
    if (peer_id.empty()) return (jint)LITEP2P_ERR_INVALID_ARG;
    return (jint)litep2p_add_peer(peer_id.c_str(),
                                  network_id.empty() ? nullptr : network_id.c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_disconnect(JNIEnv* env, jobject /*thiz*/, jstring peerId) {
    const std::string peer_id = jstring_to_utf8(env, peerId);
    if (peer_id.empty()) return (jint)LITEP2P_ERR_INVALID_ARG;
    return (jint)litep2p_disconnect(peer_id.c_str());
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_isPeerConnected(JNIEnv* env, jobject /*thiz*/, jstring peerId) {
    const std::string peer_id = jstring_to_utf8(env, peerId);
    if (peer_id.empty()) return JNI_FALSE;
    int connected = 0;
    const litep2p_result_t rc = litep2p_peer_is_connected(peer_id.c_str(), &connected);
    return (rc == LITEP2P_OK && connected != 0) ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_sendMessage(JNIEnv* env, jobject /*thiz*/,
                                                        jstring peerId, jbyteArray message) {
    const std::string peer_id = jstring_to_utf8(env, peerId);
    if (peer_id.empty()) return (jint)LITEP2P_ERR_INVALID_ARG;
    if (!message) return (jint)LITEP2P_ERR_INVALID_ARG;

    jsize len = env->GetArrayLength(message);
    jbyte* elements = env->GetByteArrayElements(message, nullptr);
    if (!elements) {
        clear_any_exception(env);
        return (jint)LITEP2P_ERR_INTERNAL;
    }

    const litep2p_result_t rc = litep2p_send(
        peer_id.c_str(), reinterpret_cast<const uint8_t*>(elements), (uint32_t)len);
    env->ReleaseByteArrayElements(message, elements, JNI_ABORT);
    return (jint)rc;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_localPublicKeyHex(JNIEnv* env, jobject /*thiz*/) {
    char buf[128] = {0};
    const litep2p_result_t rc = litep2p_get_local_public_key(buf, sizeof(buf));
    if (rc != LITEP2P_OK) {
        return env->NewStringUTF("");
    }
    return env->NewStringUTF(buf);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_registerPeerKey(JNIEnv* env, jobject /*thiz*/,
                                                            jstring peerId, jstring publicKeyHex) {
    const std::string peer_id = jstring_to_utf8(env, peerId);
    const std::string key_hex = jstring_to_utf8(env, publicKeyHex);
    if (peer_id.empty() || key_hex.empty()) return (jint)LITEP2P_ERR_INVALID_ARG;
    return (jint)litep2p_register_peer_key(peer_id.c_str(), key_hex.c_str());
}


// ---------------------------------------------------------------------------
// JNI entry points — proxy, environment hints, diagnostics.
// ---------------------------------------------------------------------------
extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_nativeConfigureProxy(JNIEnv* env, jobject /*thiz*/,
                                                                 jboolean enableGateway,
                                                                 jboolean enableClient) {
    (void)env;
    // Map the harness's boolean toggles onto the C ABI string-role model.
    const char* role = "off";
    if (enableGateway == JNI_TRUE && enableClient == JNI_TRUE) {
        role = "both";
    } else if (enableGateway == JNI_TRUE) {
        role = "gateway";
    } else if (enableClient == JNI_TRUE) {
        role = "client";
    }
    nativeLog(std::string("JNI_BRIDGE: set_proxy_role(") + role + ")");
    return (jint)litep2p_set_proxy_role(role);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_setSystemNetworkInfo(JNIEnv* env, jobject /*thiz*/,
                                                                 jboolean isWiFi,
                                                                 jboolean isNetworkAvailable) {
    (void)env;
    return (jint)litep2p_set_network_info(isWiFi == JNI_TRUE ? 1 : 0,
                                          isNetworkAvailable == JNI_TRUE ? 1 : 0);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_setBatteryLevel(JNIEnv* env, jobject /*thiz*/,
                                                            jint percent, jboolean isCharging) {
    (void)env;
    return (jint)litep2p_set_battery_level(percent, isCharging == JNI_TRUE ? 1 : 0);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_setReconnectMode(JNIEnv* env, jobject /*thiz*/, jstring mode) {
    const std::string m = jstring_to_utf8(env, mode);
    if (m.empty()) return (jint)LITEP2P_ERR_INVALID_ARG;
    return (jint)litep2p_set_reconnect_mode(m.c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_setLogLevel(JNIEnv* env, jobject /*thiz*/, jint level) {
    (void)env;
    return (jint)litep2p_set_log_level(level);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_telemetrySnapshot(JNIEnv* env, jobject /*thiz*/) {
    char* json = nullptr;
    const litep2p_result_t rc = litep2p_telemetry_snapshot(&json);
    if (rc != LITEP2P_OK || !json) {
        return env->NewStringUTF("");
    }
    jstring result = env->NewStringUTF(json);
    litep2p_free(json);
    return result;
}

// ---------------------------------------------------------------------------
// JNI entry points — backpressure metrics (v0.4).
// ---------------------------------------------------------------------------

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_pendingSendCount(JNIEnv* env, jobject /*thiz*/) {
    (void)env;
    return (jint)litep2p_pending_send_count();
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_reliablePendingCount(JNIEnv* env, jobject /*thiz*/) {
    (void)env;
    return (jint)litep2p_reliable_pending_count();
}


// ---------------------------------------------------------------------------
// JNI reference caching.
// ---------------------------------------------------------------------------
bool jniBridgeInit(JNIEnv* env) {
    if (!env) return false;

    std::lock_guard<std::mutex> lock(g_jni_cache_mutex);
    if (g_jni_cache_initialized) {
        return true;
    }

    nativeLog("JNI_BRIDGE: Caching class references (init-once)...");

    // NativeEvents class (required) — the single JNI->Kotlin callback surface.
    jclass localEventsClass = env->FindClass("com/zeengal/litep2p/core/NativeEvents");
    if (!localEventsClass) {
        nativeLog("JNI_BRIDGE: Failed to find NativeEvents class");
        clear_any_exception(env);
        return false;
    }
    jclass newEventsClass = (jclass)env->NewGlobalRef(localEventsClass);
    env->DeleteLocalRef(localEventsClass);
    if (!newEventsClass) {
        nativeLog("JNI_BRIDGE: Failed to create global ref for NativeEvents class");
        return false;
    }

    jmethodID newOnPeersUpdated =
        env->GetStaticMethodID(newEventsClass, "onPeersUpdated",
                               "([Lcom/zeengal/litep2p/core/PeerInfo;)V");
    jmethodID newOnEngineStartComplete =
        env->GetStaticMethodID(newEventsClass, "onEngineStartComplete", "()V");
    jmethodID newOnEngineStopComplete =
        env->GetStaticMethodID(newEventsClass, "onEngineStopComplete", "()V");
    jmethodID newOnMessageReceived =
        env->GetStaticMethodID(newEventsClass, "onMessageReceived", "(Ljava/lang/String;[B)V");
    jmethodID newAddLogMethod =
        env->GetStaticMethodID(newEventsClass, "addLog", "(ILjava/lang/String;)V");

    if (!newOnPeersUpdated || !newOnEngineStartComplete || !newOnEngineStopComplete ||
        !newOnMessageReceived || !newAddLogMethod) {
        nativeLog("JNI_BRIDGE: Failed to resolve required NativeEvents methods");
        clear_any_exception(env);
        safeDeleteGlobalRef(env, (jobject&)newEventsClass);
        return false;
    }

    // Telemetry + ACK callbacks are optional conveniences; missing methods only
    // disable those UI features, never the engine.
    jmethodID newAddTelemetryJsonMethod =
        env->GetStaticMethodID(newEventsClass, "addTelemetryJson", "(Ljava/lang/String;)V");
    if (!newAddTelemetryJsonMethod) {
        nativeLog("JNI_BRIDGE: NativeEvents.addTelemetryJson not found (telemetry UI disabled)");
        clear_any_exception(env);
    }
    jmethodID newOnAckReceivedMethod =
        env->GetStaticMethodID(newEventsClass, "onAckReceived", "(Ljava/lang/String;JJ)V");
    if (!newOnAckReceivedMethod) {
        nativeLog("JNI_BRIDGE: NativeEvents.onAckReceived not found (ACK tracing disabled)");
        clear_any_exception(env);
    }
    jmethodID newOnOverlayDeliveryMethod =
        env->GetStaticMethodID(newEventsClass, "onOverlayDelivery",
                               "(Ljava/lang/String;Z)V");
    if (!newOnOverlayDeliveryMethod) {
        nativeLog("JNI_BRIDGE: NativeEvents.onOverlayDelivery not found (overlay UI disabled)");
        clear_any_exception(env);
    }
    // Phase 12 (optional): Network OS delivery/diagnostic event surface.
    jmethodID newOnNosDeliveryEventMethod =
        env->GetStaticMethodID(newEventsClass, "onNosDeliveryEvent",
                               "(Ljava/lang/String;)V");
    if (!newOnNosDeliveryEventMethod) {
        nativeLog("JNI_BRIDGE: NativeEvents.onNosDeliveryEvent not found (NOS events disabled)");
        clear_any_exception(env);
    }
    if (!newOnOverlayDeliveryMethod) {
        nativeLog("JNI_BRIDGE: NativeEvents.onOverlayDelivery not found (overlay ACK UI disabled)");
        clear_any_exception(env);
    }
    // File-transfer callbacks are optional conveniences too; missing methods
    // only disable the file-transfer UI, never the engine.
    jmethodID newOnFileTransferOfferedMethod =
        env->GetStaticMethodID(newEventsClass, "onFileTransferOffered",
                               "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J)V");
    if (!newOnFileTransferOfferedMethod) {
        nativeLog("JNI_BRIDGE: NativeEvents.onFileTransferOffered not found (file transfer UI disabled)");
        clear_any_exception(env);
    }
    jmethodID newOnTransferProgressMethod =
        env->GetStaticMethodID(newEventsClass, "onTransferProgress",
                               "(Ljava/lang/String;FF)V");
    if (!newOnTransferProgressMethod) {
        nativeLog("JNI_BRIDGE: NativeEvents.onTransferProgress not found (file transfer UI disabled)");
        clear_any_exception(env);
    }
    jmethodID newOnTransferCompletedMethod =
        env->GetStaticMethodID(newEventsClass, "onTransferCompleted",
                               "(Ljava/lang/String;ZLjava/lang/String;)V");
    if (!newOnTransferCompletedMethod) {
        nativeLog("JNI_BRIDGE: NativeEvents.onTransferCompleted not found (file transfer UI disabled)");
        clear_any_exception(env);
    }

    // Voice call callbacks (optional; missing methods only disable the call UI).
    jmethodID newOnVoiceCallOfferedMethod =
        env->GetStaticMethodID(newEventsClass, "onVoiceCallOffered",
                               "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;III)V");
    if (!newOnVoiceCallOfferedMethod) {
        nativeLog("JNI_BRIDGE: NativeEvents.onVoiceCallOffered not found (voice call UI disabled)");
        clear_any_exception(env);
    }
    jmethodID newOnVoiceCallStateMethod =
        env->GetStaticMethodID(newEventsClass, "onVoiceCallStateChanged",
                               "(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)V");
    if (!newOnVoiceCallStateMethod) {
        nativeLog("JNI_BRIDGE: NativeEvents.onVoiceCallStateChanged not found (voice call UI disabled)");
        clear_any_exception(env);
    }
    jmethodID newOnVoiceFrameMethod =
        env->GetStaticMethodID(newEventsClass, "onVoiceFrameReceived",
                               "(Ljava/lang/String;Ljava/lang/String;[B)V");
    if (!newOnVoiceFrameMethod) {
        nativeLog("JNI_BRIDGE: NativeEvents.onVoiceFrameReceived not found (voice call UI disabled)");
        clear_any_exception(env);
    }

    // v0.4 callbacks are optional conveniences; missing methods only disable
    // those features, never the engine.
    jmethodID newOnDeliveryStatusMethod =
        env->GetStaticMethodID(newEventsClass, "onDeliveryStatus",
                               "(Ljava/lang/String;ILjava/lang/String;)V");
    if (!newOnDeliveryStatusMethod) {
        nativeLog("JNI_BRIDGE: NativeEvents.onDeliveryStatus not found (reliable-send UI disabled)");
        clear_any_exception(env);
    }
    jmethodID newOnPresenceMethod =
        env->GetStaticMethodID(newEventsClass, "onPresence", "(Ljava/lang/String;ZJ)V");
    if (!newOnPresenceMethod) {
        nativeLog("JNI_BRIDGE: NativeEvents.onPresence not found (presence UI disabled)");
        clear_any_exception(env);
    }
    jmethodID newOnPingResultMethod =
        env->GetStaticMethodID(newEventsClass, "onPingResult", "(Ljava/lang/String;J)V");
    if (!newOnPingResultMethod) {
        nativeLog("JNI_BRIDGE: NativeEvents.onPingResult not found (ping UI disabled)");
        clear_any_exception(env);
    }
    jmethodID newOnLookupResultMethod =
        env->GetStaticMethodID(newEventsClass, "onLookupResult",
                               "(Ljava/lang/String;Ljava/lang/String;ZJ)V");
    if (!newOnLookupResultMethod) {
        nativeLog("JNI_BRIDGE: NativeEvents.onLookupResult not found (directory UI disabled)");
        clear_any_exception(env);
    }
    jmethodID newOnInviteReceivedMethod =
        env->GetStaticMethodID(newEventsClass, "onInviteReceived", "(Ljava/lang/String;)V");
    if (!newOnInviteReceivedMethod) {
        nativeLog("JNI_BRIDGE: NativeEvents.onInviteReceived not found (invite UI disabled)");
        clear_any_exception(env);
    }

    // PeerInfo class (required).
    jclass localPeerInfoClass = env->FindClass("com/zeengal/litep2p/core/PeerInfo");
    if (!localPeerInfoClass) {
        nativeLog("JNI_BRIDGE: Failed to find PeerInfo class");
        clear_any_exception(env);
        safeDeleteGlobalRef(env, (jobject&)newEventsClass);
        return false;
    }
    jclass newPeerInfoClass = (jclass)env->NewGlobalRef(localPeerInfoClass);
    env->DeleteLocalRef(localPeerInfoClass);
    if (!newPeerInfoClass) {
        nativeLog("JNI_BRIDGE: Failed to create global ref for PeerInfo class");
        safeDeleteGlobalRef(env, (jobject&)newEventsClass);
        return false;
    }
    jmethodID newPeerInfoCtor = env->GetMethodID(
        newPeerInfoClass, "<init>",
        "(Ljava/lang/String;Ljava/lang/String;IIZLjava/lang/String;Ljava/lang/String;"
        "Ljava/lang/String;J)V");
    if (!newPeerInfoCtor) {
        nativeLog("JNI_BRIDGE: Failed to get PeerInfo constructor method ID");
        clear_any_exception(env);
        safeDeleteGlobalRef(env, (jobject&)newEventsClass);
        safeDeleteGlobalRef(env, (jobject&)newPeerInfoClass);
        return false;
    }

    // Drop any stale refs before publishing the new set.
    safeDeleteGlobalRef(env, (jobject&)g_eventsClass);
    safeDeleteGlobalRef(env, (jobject&)g_peerInfoClass);

    g_eventsClass = newEventsClass;
    g_peerInfoClass = newPeerInfoClass;
    g_onPeersUpdated = newOnPeersUpdated;
    g_onEngineStartComplete = newOnEngineStartComplete;
    g_onEngineStopComplete = newOnEngineStopComplete;
    g_onMessageReceived = newOnMessageReceived;
    g_peerInfoCtor = newPeerInfoCtor;
    g_addLogMethod = newAddLogMethod;
    g_addTelemetryJsonMethod = newAddTelemetryJsonMethod;
    g_onAckReceivedMethod = newOnAckReceivedMethod;
    g_onOverlayDeliveryMethod = newOnOverlayDeliveryMethod;
    g_onNosDeliveryEvent = newOnNosDeliveryEventMethod;
    g_onFileTransferOfferedMethod = newOnFileTransferOfferedMethod;
    g_onTransferProgressMethod = newOnTransferProgressMethod;
    g_onTransferCompletedMethod = newOnTransferCompletedMethod;
    g_onVoiceCallOfferedMethod = newOnVoiceCallOfferedMethod;
    g_onVoiceCallStateMethod = newOnVoiceCallStateMethod;
    g_onVoiceFrameMethod = newOnVoiceFrameMethod;
    g_onDeliveryStatusMethod = newOnDeliveryStatusMethod;
    g_onPresenceMethod = newOnPresenceMethod;
    g_onPingResultMethod = newOnPingResultMethod;
    g_onLookupResultMethod = newOnLookupResultMethod;
    g_onInviteReceivedMethod = newOnInviteReceivedMethod;

    g_jni_cache_initialized = true;
    nativeLog("JNI_BRIDGE: Initialization complete.");
    return true;
}


void jniBridgeCleanup(JNIEnv* env) {
    if (!env) {
        env = getJNIEnv();
    }

    std::lock_guard<std::mutex> lock(g_jni_cache_mutex);

    safeDeleteGlobalRef(env, (jobject&)g_eventsClass);
    safeDeleteGlobalRef(env, (jobject&)g_peerInfoClass);

    g_onPeersUpdated = nullptr;
    g_onEngineStartComplete = nullptr;
    g_onEngineStopComplete = nullptr;
    g_onMessageReceived = nullptr;
    g_peerInfoCtor = nullptr;
    g_addLogMethod = nullptr;
    g_addTelemetryJsonMethod = nullptr;
    g_onAckReceivedMethod = nullptr;
    g_onOverlayDeliveryMethod = nullptr;
    g_onFileTransferOfferedMethod = nullptr;
    g_onTransferProgressMethod = nullptr;
    g_onTransferCompletedMethod = nullptr;
    g_onVoiceCallOfferedMethod = nullptr;
    g_onVoiceCallStateMethod = nullptr;
    g_onVoiceFrameMethod = nullptr;
    g_onDeliveryStatusMethod = nullptr;
    g_onPresenceMethod = nullptr;
    g_onPingResultMethod = nullptr;
    g_onLookupResultMethod = nullptr;
    g_onInviteReceivedMethod = nullptr;

    g_jni_cache_initialized = false;
}

// ---------------------------------------------------------------------------
// Engine hook implementations (declared in jni_bridge.h, called from the
// engine's logger / telemetry / message-handler on engine threads).
// ---------------------------------------------------------------------------
void sendToLogUI(const std::string& message) {
    sendToLogUI(1 /* INFO */, message);
}

void sendToLogUI(int level, const std::string& message) {
    JNIEnv* env = getJNIEnv();
    if (!env || !g_eventsClass || !g_addLogMethod) return;
    jstring jmsg = env->NewStringUTF(message.c_str());
    if (!jmsg) {
        clear_any_exception(env);
        return;
    }
    env->CallStaticVoidMethod(g_eventsClass, g_addLogMethod, static_cast<jint>(level), jmsg);
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
    env->DeleteLocalRef(jmsg);
}

void sendTelemetryToUI(const std::string& telemetry_json) {
    JNIEnv* env = getJNIEnv();
    if (!env || !g_eventsClass || !g_addTelemetryJsonMethod) return;
    jstring jjson = env->NewStringUTF(telemetry_json.c_str());
    if (!jjson) {
        clear_any_exception(env);
        return;
    }
    env->CallStaticVoidMethod(g_eventsClass, g_addTelemetryJsonMethod, jjson);
    if (env->ExceptionCheck()) {
        // Best-effort: do not crash the engine if the UI side is missing/broken.
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
    env->DeleteLocalRef(jjson);
}

void sendMessageAckToUI(const std::string& msg_id, int64_t sent_ts_ms, int64_t recv_ts_ms) {
    JNIEnv* env = getJNIEnv();
    if (!env || !g_eventsClass || !g_onAckReceivedMethod) return;

    jstring jMsgId = env->NewStringUTF(msg_id.c_str());
    if (!jMsgId) {
        clear_any_exception(env);
        return;
    }
    env->CallStaticVoidMethod(g_eventsClass, g_onAckReceivedMethod, jMsgId,
                              static_cast<jlong>(sent_ts_ms), static_cast<jlong>(recv_ts_ms));
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
    env->DeleteLocalRef(jMsgId);
}

// ---------------------------------------------------------------------------
// JNI entry points — overlay / multi-hop routing (Phase C1).
// ---------------------------------------------------------------------------

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_nativeSetOverlayRelayEnabled(
    JNIEnv* env, jobject /*thiz*/, jboolean enabled) {
    (void)env;
    return (jint)litep2p_set_overlay_relay_enabled(enabled ? 1 : 0);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_sendOverlay(
    JNIEnv* env, jobject /*thiz*/, jstring peerId, jbyteArray data,
    jboolean wantAck, jboolean viaMailbox) {
    const std::string peer_id = jstring_to_utf8(env, peerId);
    if (peer_id.empty() || !data) return env->NewStringUTF("");

    jsize len = env->GetArrayLength(data);
    jbyte* elements = env->GetByteArrayElements(data, nullptr);
    if (!elements) {
        clear_any_exception(env);
        return env->NewStringUTF("");
    }

    char frame_id[33] = {0};
    const litep2p_result_t rc = litep2p_send_overlay(
        peer_id.c_str(),
        reinterpret_cast<const uint8_t*>(elements), static_cast<uint32_t>(len),
        wantAck ? 1 : 0, viaMailbox ? 1 : 0,
        frame_id, sizeof(frame_id));

    env->ReleaseByteArrayElements(data, elements, JNI_ABORT);
    if (rc != LITEP2P_OK) {
        nativeLog("JNI_BRIDGE: sendOverlay failed: " + std::string(litep2p_result_string(rc)));
        return env->NewStringUTF("");
    }
    return env->NewStringUTF(frame_id);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_pickupMailbox(
    JNIEnv* env, jobject /*thiz*/, jstring relayPeerId) {
    const std::string relay = jstring_to_utf8(env, relayPeerId);
    if (relay.empty()) return (jint)LITEP2P_ERR_INVALID_ARG;
    return (jint)litep2p_overlay_pickup_mailbox(relay.c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_registerRelay(
    JNIEnv* env, jobject /*thiz*/, jstring peerId, jint capacity, jint maxHops,
    jboolean persistent) {
    const std::string peer_id = jstring_to_utf8(env, peerId);
    if (peer_id.empty()) return (jint)LITEP2P_ERR_INVALID_ARG;
    return (jint)litep2p_overlay_register_relay(peer_id.c_str(), capacity, maxHops,
                                                persistent ? 1 : 0);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_registerPeerSigningKey(
    JNIEnv* env, jobject /*thiz*/, jstring peerId, jstring publicKeyHex) {
    const std::string peer_id = jstring_to_utf8(env, peerId);
    const std::string key_hex = jstring_to_utf8(env, publicKeyHex);
    if (peer_id.empty() || key_hex.empty()) return (jint)LITEP2P_ERR_INVALID_ARG;
    return (jint)litep2p_overlay_register_peer_signing_key(peer_id.c_str(), key_hex.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_overlayStats(JNIEnv* env, jobject /*thiz*/) {
    char* json = nullptr;
    const litep2p_result_t rc = litep2p_overlay_stats(&json);
    if (rc != LITEP2P_OK || !json) return env->NewStringUTF("");
    jstring out = env->NewStringUTF(json);
    litep2p_free(json);
    return out;
}

// ---------------------------------------------------------------------------
// JNI entry points — v0.4: reliable messaging / presence / directory / invite.
// ---------------------------------------------------------------------------

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_sendReliable(
    JNIEnv* env, jobject /*thiz*/, jstring peerId, jstring msgId, jbyteArray data,
    jint maxRetries, jint retryTimeoutMs) {
    const std::string peer_id = jstring_to_utf8(env, peerId);
    const std::string msg_id = jstring_to_utf8(env, msgId);
    if (peer_id.empty() || msg_id.empty() || !data) return (jint)LITEP2P_ERR_INVALID_ARG;

    jsize len = env->GetArrayLength(data);
    jbyte* elements = env->GetByteArrayElements(data, nullptr);
    if (!elements) {
        clear_any_exception(env);
        return (jint)LITEP2P_ERR_INTERNAL;
    }
    const litep2p_result_t rc = litep2p_send_reliable(
        peer_id.c_str(), msg_id.c_str(),
        reinterpret_cast<const uint8_t*>(elements), static_cast<uint32_t>(len),
        maxRetries, static_cast<uint32_t>(retryTimeoutMs));
    env->ReleaseByteArrayElements(data, elements, JNI_ABORT);
    return (jint)rc;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_cancelReliable(JNIEnv* env, jobject /*thiz*/,
                                                           jstring msgId) {
    const std::string msg_id = jstring_to_utf8(env, msgId);
    if (msg_id.empty()) return (jint)LITEP2P_ERR_INVALID_ARG;
    return (jint)litep2p_reliable_cancel(msg_id.c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_ping(JNIEnv* env, jobject /*thiz*/,
                                                 jstring peerId, jint timeoutMs) {
    const std::string peer_id = jstring_to_utf8(env, peerId);
    if (peer_id.empty()) return (jint)LITEP2P_ERR_INVALID_ARG;
    return (jint)litep2p_ping(peer_id.c_str(), static_cast<uint32_t>(timeoutMs));
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_subscribePresence(JNIEnv* env, jobject /*thiz*/,
                                                              jobjectArray peerIds) {
    if (!peerIds) return (jint)LITEP2P_ERR_INVALID_ARG;
    const jsize count = env->GetArrayLength(peerIds);
    if (count <= 0) return (jint)LITEP2P_ERR_INVALID_ARG;

    std::vector<std::string> ids;
    std::vector<const char*> c_ids;
    ids.reserve(static_cast<size_t>(count));
    c_ids.reserve(static_cast<size_t>(count));
    for (jsize i = 0; i < count; ++i) {
        auto elem = (jstring)env->GetObjectArrayElement(peerIds, i);
        if (!elem) continue;
        ids.push_back(jstring_to_utf8(env, elem));
        env->DeleteLocalRef(elem);
    }
    for (const auto& s : ids) c_ids.push_back(s.c_str());
    if (c_ids.empty()) return (jint)LITEP2P_ERR_INVALID_ARG;
    return (jint)litep2p_subscribe_presence(c_ids.data(),
                                            static_cast<uint32_t>(c_ids.size()));
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_registerAlias(JNIEnv* env, jobject /*thiz*/,
                                                          jstring aliasHash) {
    const std::string alias = jstring_to_utf8(env, aliasHash);
    if (alias.empty()) return (jint)LITEP2P_ERR_INVALID_ARG;
    return (jint)litep2p_register_alias(alias.c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_lookupPeer(JNIEnv* env, jobject /*thiz*/,
                                                       jstring aliasHash) {
    const std::string alias = jstring_to_utf8(env, aliasHash);
    if (alias.empty()) return (jint)LITEP2P_ERR_INVALID_ARG;
    return (jint)litep2p_lookup_peer(alias.c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_invitePeer(JNIEnv* env, jobject /*thiz*/,
                                                       jstring peerId) {
    const std::string peer_id = jstring_to_utf8(env, peerId);
    if (peer_id.empty()) return (jint)LITEP2P_ERR_INVALID_ARG;
    return (jint)litep2p_invite_peer(peer_id.c_str());
}

// ---------------------------------------------------------------------------
// JNI entry points — file transfer (offer/accept model, Phase C: Kotlin API).
// ---------------------------------------------------------------------------

extern "C" JNIEXPORT jstring JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_sendFile(
    JNIEnv* env, jobject /*thiz*/, jstring peerId, jstring filePath, jint priority) {
    const std::string peer_id = jstring_to_utf8(env, peerId);
    const std::string file_path = jstring_to_utf8(env, filePath);
    if (peer_id.empty() || file_path.empty()) return env->NewStringUTF("");

    char transfer_id[64] = {0};
    const litep2p_result_t rc = litep2p_send_file(
        peer_id.c_str(), file_path.c_str(), static_cast<int>(priority),
        transfer_id, sizeof(transfer_id));
    if (rc != LITEP2P_OK) {
        nativeLog("JNI_BRIDGE: sendFile failed: " + std::string(litep2p_result_string(rc)));
        return env->NewStringUTF("");
    }
    return env->NewStringUTF(transfer_id);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_acceptFileTransfer(
    JNIEnv* env, jobject /*thiz*/, jstring transferId, jstring savePath) {
    const std::string transfer_id = jstring_to_utf8(env, transferId);
    const std::string save_path = jstring_to_utf8(env, savePath);
    if (transfer_id.empty() || save_path.empty()) return (jint)LITEP2P_ERR_INVALID_ARG;
    return (jint)litep2p_accept_file_transfer(transfer_id.c_str(), save_path.c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_declineFileTransfer(
    JNIEnv* env, jobject /*thiz*/, jstring transferId) {
    const std::string transfer_id = jstring_to_utf8(env, transferId);
    if (transfer_id.empty()) return (jint)LITEP2P_ERR_INVALID_ARG;
    return (jint)litep2p_decline_file_transfer(transfer_id.c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_pauseTransfer(
    JNIEnv* env, jobject /*thiz*/, jstring transferId) {
    const std::string transfer_id = jstring_to_utf8(env, transferId);
    if (transfer_id.empty()) return (jint)LITEP2P_ERR_INVALID_ARG;
    return (jint)litep2p_pause_transfer(transfer_id.c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_resumeTransfer(
    JNIEnv* env, jobject /*thiz*/, jstring transferId) {
    const std::string transfer_id = jstring_to_utf8(env, transferId);
    if (transfer_id.empty()) return (jint)LITEP2P_ERR_INVALID_ARG;
    return (jint)litep2p_resume_transfer(transfer_id.c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_cancelTransfer(
    JNIEnv* env, jobject /*thiz*/, jstring transferId) {
    const std::string transfer_id = jstring_to_utf8(env, transferId);
    if (transfer_id.empty()) return (jint)LITEP2P_ERR_INVALID_ARG;
    return (jint)litep2p_cancel_transfer(transfer_id.c_str());
}

// ---------------------------------------------------------------------------
// JNI entry points — voice calls (realtime audio).
// ---------------------------------------------------------------------------

extern "C" JNIEXPORT jstring JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_startVoiceCall(
    JNIEnv* env, jobject /*thiz*/, jstring peerId, jstring codec,
    jint sampleRate, jint channels, jint frameMs) {
    const std::string peer_id = jstring_to_utf8(env, peerId);
    const std::string codec_name = jstring_to_utf8(env, codec);
    if (peer_id.empty() || codec_name.empty()) return env->NewStringUTF("");

    char call_id[64] = {0};
    const litep2p_result_t rc = litep2p_start_voice_call(
        peer_id.c_str(), codec_name.c_str(),
        static_cast<uint16_t>(sampleRate), static_cast<uint8_t>(channels),
        static_cast<uint8_t>(frameMs), call_id, sizeof(call_id));
    if (rc != LITEP2P_OK) {
        nativeLog("JNI_BRIDGE: startVoiceCall failed: " +
                  std::string(litep2p_result_string(rc)));
        return env->NewStringUTF("");
    }
    return env->NewStringUTF(call_id);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_acceptVoiceCall(
    JNIEnv* env, jobject /*thiz*/, jstring callId) {
    const std::string call_id = jstring_to_utf8(env, callId);
    if (call_id.empty()) return (jint)LITEP2P_ERR_INVALID_ARG;
    return (jint)litep2p_accept_voice_call(call_id.c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_declineVoiceCall(
    JNIEnv* env, jobject /*thiz*/, jstring callId) {
    const std::string call_id = jstring_to_utf8(env, callId);
    if (call_id.empty()) return (jint)LITEP2P_ERR_INVALID_ARG;
    return (jint)litep2p_decline_voice_call(call_id.c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_endVoiceCall(
    JNIEnv* env, jobject /*thiz*/, jstring callId) {
    const std::string call_id = jstring_to_utf8(env, callId);
    if (call_id.empty()) return (jint)LITEP2P_ERR_INVALID_ARG;
    return (jint)litep2p_end_voice_call(call_id.c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_sendVoiceFrame(
    JNIEnv* env, jobject /*thiz*/, jstring callId, jbyteArray data) {
    const std::string call_id = jstring_to_utf8(env, callId);
    if (call_id.empty()) return (jint)LITEP2P_ERR_INVALID_ARG;

    jsize len = data ? env->GetArrayLength(data) : 0;
    if (len <= 0) return (jint)LITEP2P_ERR_INVALID_ARG;
    std::vector<jbyte> buf(static_cast<size_t>(len));
    env->GetByteArrayRegion(data, 0, len, buf.data());
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return (jint)LITEP2P_ERR_INVALID_ARG;
    }
    return (jint)litep2p_send_voice_frame(
        call_id.c_str(), reinterpret_cast<const uint8_t*>(buf.data()),
        static_cast<uint32_t>(len));
}

// ---------------------------------------------------------------------------
// JNI entry point — feature detection.
// ---------------------------------------------------------------------------

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_nativeGetFeatureFlags(
    JNIEnv* env, jobject /*thiz*/) {
    (void)env;
    return (jint)litep2p_get_feature_flags();
}

/* ------------------------------------------------------------------------ */
/* Phase 12 — Network OS object runtime (litep2p_nos_* C ABI).               */
/* ------------------------------------------------------------------------ */

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_nosWireProtocolVersion(
    JNIEnv* /*env*/, jobject /*thiz*/) {
    return (jint)litep2p_wire_protocol_version();
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_nosRegisterNamespace(
    JNIEnv* env, jobject /*thiz*/, jstring namespaceId, jlong quotaBytes,
    jint priorityCeiling, jint maxObjectBytes, jboolean allowCarrier,
    jint protocolVersion) {
    litep2p_namespace_policy_t ns{};
    const std::string ns_id = jstring_to_utf8(env, namespaceId);
    ns.namespace_id = ns_id.c_str();
    if (!ns.namespace_id) return (jint)LITEP2P_ERR_INVALID_ARG;
    ns.quota_bytes = (uint64_t)quotaBytes;
    ns.priority_ceiling = (uint32_t)priorityCeiling;
    ns.max_object_bytes = (uint32_t)maxObjectBytes;
    ns.allow_carrier = allowCarrier != JNI_FALSE;
    ns.protocol_version = (uint8_t)protocolVersion;
    return (jint)litep2p_nos_register_namespace(&ns);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_nosSend(
    JNIEnv* env, jobject /*thiz*/, jstring destination, jstring namespaceId,
    jbyteArray payload, jlong ttlMs, jint priority, jint minRemoteCopies,
    jint desiredRemoteCopies, jboolean requireReceipt,
    jboolean allowStoreAndForward, jint maxPayloadBytes, jintArray resultOut) {
    const std::string dest = jstring_to_utf8(env, destination);
    const std::string ns = jstring_to_utf8(env, namespaceId);

    litep2p_delivery_policy_t policy{};
    policy.ttl_ms = (int64_t)ttlMs;
    policy.priority = (int32_t)priority;
    policy.min_remote_copies = (uint8_t)std::min(4, std::max(0, (int)minRemoteCopies));
    policy.desired_remote_copies =
        (uint8_t)std::min(4, std::max(0, (int)desiredRemoteCopies));
    policy.require_receipt = 1;                    /* v1 contract: receipts on */
    policy.allow_store_and_forward = allowStoreAndForward != JNI_FALSE ? 1 : 0;
    policy.max_payload_bytes =
        maxPayloadBytes > 0 ? (uint32_t)maxPayloadBytes : (16u << 20);

    jint rc = (jint)LITEP2P_ERR_INVALID_ARG;
    jstring result = nullptr;

    if (dest.empty() || ns.empty() || !payload) {
        if (resultOut) env->SetIntArrayRegion(resultOut, 0, 1, &rc);
        return env->NewStringUTF("");
    }
    const jsize len = env->GetArrayLength(payload);
    std::vector<uint8_t> bytes;
    bytes.reserve((size_t)len);
    jbyte* elems = env->GetByteArrayElements(payload, nullptr);
    if (elems) {
        bytes.assign(elems, elems + len);
        env->ReleaseByteArrayElements(payload, elems, JNI_ABORT);
    }

    char object_id[128] = {0};
    const litep2p_result_t lrc = litep2p_nos_send(
        dest.c_str(), ns.c_str(),
        bytes.empty() ? nullptr : bytes.data(), (uint32_t)bytes.size(),
        &policy, object_id, sizeof(object_id));
    rc = (jint)lrc;
    result = env->NewStringUTF(lrc == LITEP2P_OK ? object_id : "");
    if (resultOut) env->SetIntArrayRegion(resultOut, 0, 1, &rc);
    return result;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_nosCancel(
    JNIEnv* env, jobject /*thiz*/, jstring objectId) {
    const std::string id = jstring_to_utf8(env, objectId);
    if (id.empty()) return (jint)LITEP2P_ERR_INVALID_ARG;
    return (jint)litep2p_nos_cancel(id.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_nosStatus(
    JNIEnv* env, jobject /*thiz*/, jstring objectId) {
    const std::string id = jstring_to_utf8(env, objectId);
    if (id.empty()) return nullptr;
    char* json = nullptr;
    if (litep2p_nos_status(id.c_str(), &json) != LITEP2P_OK || !json) {
        if (json) litep2p_free(json);
        return nullptr;
    }
    jstring out = env->NewStringUTF(json);
    litep2p_free(json);
    return out;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_zeengal_litep2p_core_LiteP2PNative_nosDiagnostics(
    JNIEnv* env, jobject /*thiz*/) {
    char* json = nullptr;
    if (litep2p_nos_diagnostics(&json) != LITEP2P_OK || !json) {
        if (json) litep2p_free(json);
        return nullptr;
    }
    jstring out = env->NewStringUTF(json);
    litep2p_free(json);
    return out;
}


