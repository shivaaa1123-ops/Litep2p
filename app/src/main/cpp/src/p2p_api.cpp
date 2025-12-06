// p2p_api.cpp
#include <jni.h>
#include <android/log.h>
#include <vector>
#include <mutex>
#include "jni_glue.h"
#include "p2p_api.h"     // prototypes for JNI functions (optional)
#include "peer.h"
#include "peer_manager.h"
#include "discovery.h"
#include "logger.h"      // nativeLog()

// NOTE: This file intentionally DOES NOT re-define globals or helper functions
// that are already defined in other compilation units (jni_helpers.cpp, jni_glue.cpp, etc).
// Instead it declares them as extern to avoid duplicate symbol/linker errors.

// -----------------------------------------------------------------------------
// extern symbols expected to be defined elsewhere in your native codebase
// -----------------------------------------------------------------------------
extern JavaVM* g_vm; // if you keep this global in jni_helpers.cpp
extern JNIEnv* getJNIEnv(); // helper defined in jni_helpers.cpp
extern PeerManager g_peerManager; // defined elsewhere (peer_manager.cpp)
extern Discovery* getGlobalDiscoveryInstance(); // accessor that returns the global discovery instance
extern void sendPeersToUI(const std::vector<Peer>& peers); // optional helper defined elsewhere
extern void nativeLog(const std::string& s); // logger helper

// Protect callback setup with mutex (local to this TU)
static std::mutex g_initMutex;

// Cache Java class + method ID for P2P callbacks (kept as globals here as references)
static jclass g_p2pClass = nullptr;
static jmethodID g_onPeersUpdated = nullptr;

// -----------------------------------------------------------------------------
// Utility: safe NewStringUTF wrapper (returns local jstring, null on failure)
// -----------------------------------------------------------------------------
static jstring safeNewStringUTF(JNIEnv* env, const char* s) {
    if (!env) return nullptr;
    return env->NewStringUTF(s ? s : "");
}

// -----------------------------------------------------------------------------
// JNI: com.zeengal.litep2p.hook.P2P.init()
//   - Called from Java/Kotlin to initialize native P2P engine glue.
// -----------------------------------------------------------------------------
extern "C"
JNIEXPORT void JNICALL
Java_com_zeengal_litep2p_hook_P2P_init(JNIEnv* env, jclass clazz) {
    std::lock_guard<std::mutex> lock(g_initMutex);

    // Store JavaVM if not stored (some modules expect g_vm to be filled by jni_helpers)
    if (!g_vm) {
        env->GetJavaVM(&g_vm);
    }

    // Keep a global ref to the P2P class so we can call static callbacks later
    if (g_p2pClass == nullptr) {
        g_p2pClass = reinterpret_cast<jclass>(env->NewGlobalRef(clazz));
    }

    // Find static method: onPeersUpdated([Lcom/zeengal/litep2p/PeerInfo;)V
    if (g_onPeersUpdated == nullptr) {
        g_onPeersUpdated = env->GetStaticMethodID(
                clazz,
                "onPeersUpdated",
                "([Lcom/zeengal/litep2p/PeerInfo;)V"
        );
        if (!g_onPeersUpdated) {
            nativeLog("p2p_api.init: ERROR: cannot find P2P.onPeersUpdated");
            // keep going — higher-level code may still work
        }
    }

    // Wire native components' callbacks to sendPeersToUI (extern function).
    // We assume g_peerManager and discovery instance exist and have setCallback methods.

    try {
        // PeerManager callback -> sendPeersToUI
        g_peerManager.setCallback([](const std::vector<Peer>& peers) {
            try {
                sendPeersToUI(peers);
            } catch (...) {
                nativeLog("p2p_api.init: peerManager callback threw");
            }
        });

        // Discovery callback -> send single peer via sendPeersToUI
        Discovery* disc = getGlobalDiscoveryInstance();
        if (disc) {
            disc->setCallback([](const Peer& p) {
                try {
                    sendPeersToUI(std::vector<Peer>{p});
                } catch (...) {
                    nativeLog("p2p_api.init: discovery callback threw");
                }
            });
        } else {
            nativeLog("p2p_api.init: discovery instance is null");
        }
    } catch (...) {
        nativeLog("p2p_api.init: failed to set callbacks");
    }

    nativeLog("p2p_api: P2P initialized");
}

// -----------------------------------------------------------------------------
// JNI: com.zeengal.litep2p.hook.P2P.startServer(int port)
// -----------------------------------------------------------------------------
extern "C"
JNIEXPORT void JNICALL
Java_com_zeengal_litep2p_hook_P2P_startServer(JNIEnv* /*env*/, jclass /*clazz*/, jint port) {
    nativeLog("p2p_api: startServer called");
    try {
        g_peerManager.startServer(static_cast<int>(port));
        Discovery* disc = getGlobalDiscoveryInstance();
        if (disc) disc->start(static_cast<int>(port));
    } catch (...) {
        nativeLog("p2p_api: startServer caught exception");
    }
}

// -----------------------------------------------------------------------------
// JNI: com.zeengal.litep2p.hook.P2P.connect(String ip, int port)
// -----------------------------------------------------------------------------
extern "C"
JNIEXPORT void JNICALL
Java_com_zeengal_litep2p_hook_P2P_connect(JNIEnv* env, jclass /*clazz*/, jstring jip, jint port) {
    if (!jip) {
        nativeLog("p2p_api.connect: ip string is null");
        return;
    }
    const char* ip = env->GetStringUTFChars(jip, nullptr);
    if (!ip) {
        nativeLog("p2p_api.connect: GetStringUTFChars failed");
        return;
    }

    nativeLog(std::string("p2p_api: connect to ") + ip + ":" + std::to_string(port));
    try {
        g_peerManager.connect(ip, static_cast<int>(port));
    } catch (...) {
        nativeLog("p2p_api.connect: exception while connecting");
    }

    env->ReleaseStringUTFChars(jip, ip);
}

// -----------------------------------------------------------------------------
// JNI: com.zeengal.litep2p.hook.P2P.sendMessage(String peerId, byte[] data)
// -----------------------------------------------------------------------------
extern "C"
JNIEXPORT void JNICALL
Java_com_zeengal_litep2p_hook_P2P_sendMessage(JNIEnv* env, jclass /*clazz*/,
                                              jstring jpeerId, jbyteArray jdata) {
    if (!jpeerId || !jdata) {
        nativeLog("p2p_api.sendMessage: null arg");
        return;
    }

    const char* peerId = env->GetStringUTFChars(jpeerId, nullptr);
    if (!peerId) {
        nativeLog("p2p_api.sendMessage: GetStringUTFChars failed");
        return;
    }

    jsize len = env->GetArrayLength(jdata);
    std::vector<uint8_t> buf;
    buf.resize((size_t)len);
    if (len > 0) {
        env->GetByteArrayRegion(jdata, 0, len, reinterpret_cast<jbyte*>(buf.data()));
    }

    try {
        g_peerManager.send(peerId, buf);
    } catch (...) {
        nativeLog("p2p_api.sendMessage: exception while sending");
    }

    env->ReleaseStringUTFChars(jpeerId, peerId);
}

// -----------------------------------------------------------------------------
// JNI: com.zeengal.litep2p.hook.P2P.stop()
// -----------------------------------------------------------------------------
extern "C"
JNIEXPORT void JNICALL
Java_com_zeengal_litep2p_hook_P2P_stop(JNIEnv* env, jclass /*clazz*/) {
    nativeLog("p2p_api: stop called");
    try {
        Discovery* disc = getGlobalDiscoveryInstance();
        if (disc) disc->stop();
        g_peerManager.stop();
    } catch (...) {
        nativeLog("p2p_api.stop: exception while stopping");
    }

    // Clean up global refs if any
    if (g_p2pClass) {
        env->DeleteGlobalRef(g_p2pClass);
        g_p2pClass = nullptr;
    }
}

// -----------------------------------------------------------------------------
// JNI: com.zeengal.litep2p.MainActivity.nativeStartLiteP2P()
//   - Implemented so MainActivity.nativeStartLiteP2P() will exist for app.
// -----------------------------------------------------------------------------
extern "C"
JNIEXPORT jstring JNICALL
Java_com_zeengal_litep2p_MainActivity_nativeStartLiteP2P(JNIEnv* env, jobject /*thiz*/) {
    nativeLog("nativeStartLiteP2P called from MainActivity");

    // Example behaviour: start peer server on default port and discovery
    const int defaultPort = 9999;
    try {
        g_peerManager.startServer(defaultPort);
        Discovery* disc = getGlobalDiscoveryInstance();
        if (disc) disc->start(defaultPort);
    } catch (...) {
        nativeLog("nativeStartLiteP2P: exception starting engine");
        return safeNewStringUTF(env, "Error");
    }

    return safeNewStringUTF(env, "Started");
}

// -----------------------------------------------------------------------------
// JNI: com.zeengal.litep2p.MainActivity.nativeStopLiteP2P()
// -----------------------------------------------------------------------------
extern "C"
JNIEXPORT void JNICALL
Java_com_zeengal_litep2p_MainActivity_nativeStopLiteP2P(JNIEnv* /*env*/, jobject /*thiz*/) {
    nativeLog("nativeStopLiteP2P called from MainActivity");
    try {
        Discovery* disc = getGlobalDiscoveryInstance();
        if (disc) disc->stop();
        g_peerManager.stop();
    } catch (...) {
        nativeLog("nativeStopLiteP2P: exception stopping engine");
    }
}