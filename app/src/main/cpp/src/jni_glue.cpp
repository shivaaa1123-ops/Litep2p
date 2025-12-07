
#include "jni_glue.h"
#include "jni_helpers.h"
#include "logger.h"
#include <android/log.h>

static jclass g_p2pClass = nullptr;
static jmethodID g_onPeersUpdated = nullptr;

// --- FIX: Add global references for PeerInfo ---
static jclass g_peerInfoClass = nullptr;
static jmethodID g_peerInfoCtor = nullptr;

bool jniGlueInit(JNIEnv* env) {
    nativeLog("JNI_GLUE: Initializing and caching class references...");
    
    // Cache P2P class and method
    jclass localP2pClass = env->FindClass("com/zeengal/litep2p/hook/P2P");
    if (!localP2pClass) {
        nativeLog("JNI_GLUE: FATAL - Could not find P2P class during init.");
        return false;
    }
    g_p2pClass = (jclass)env->NewGlobalRef(localP2pClass);
    env->DeleteLocalRef(localP2pClass);

    g_onPeersUpdated = env->GetStaticMethodID(g_p2pClass, "onPeersUpdated", "([Lcom/zeengal/litep2p/PeerInfo;)V");
    if (!g_onPeersUpdated) {
        nativeLog("JNI_GLUE: FATAL - Could not find onPeersUpdated method during init.");
        return false;
    }

    // --- FIX: Cache PeerInfo class and constructor ---
    jclass localPeerInfoClass = env->FindClass("com/zeengal/litep2p/PeerInfo");
    if (!localPeerInfoClass) {
        nativeLog("JNI_GLUE: FATAL - Could not find PeerInfo class during init.");
        return false;
    }
    g_peerInfoClass = (jclass)env->NewGlobalRef(localPeerInfoClass);
    env->DeleteLocalRef(localPeerInfoClass);

    g_peerInfoCtor = env->GetMethodID(g_peerInfoClass, "<init>", "(Ljava/lang/String;Ljava/lang/String;IIZ)V");
    if (!g_peerInfoCtor) {
        nativeLog("JNI_GLUE: FATAL - Could not find PeerInfo constructor during init.");
        return false;
    }

    nativeLog("JNI_GLUE: Initialization complete. All references cached.");
    return true;
}

void jniGlueCleanup(JNIEnv* env) {
    if (g_p2pClass) {
        env->DeleteGlobalRef(g_p2pClass);
        g_p2pClass = nullptr;
    }
    if (g_peerInfoClass) {
        env->DeleteGlobalRef(g_peerInfoClass);
        g_peerInfoClass = nullptr;
    }
}

void sendPeersToUI(const std::vector<Peer>& peers) {
    JNIEnv* env = getJNIEnv();
    if (!env) {
        nativeLog("JNI_GLUE: ERROR - JNIEnv not found for sendPeersToUI");
        return;
    }
    
    // --- FIX: Check all cached references ---
    if (!g_p2pClass || !g_onPeersUpdated || !g_peerInfoClass || !g_peerInfoCtor) {
        nativeLog("JNI_GLUE: ERROR - JNI references not initialized.");
        return;
    }

    // --- FIX: Use the cached class reference ---
    jobjectArray arr = env->NewObjectArray((jsize)peers.size(), g_peerInfoClass, nullptr);
    if (!arr) {
        nativeLog("JNI_GLUE: ERROR - Failed to create PeerInfo array");
        return;
    }

    for (size_t i = 0; i < peers.size(); ++i) {
        const Peer& p = peers[i];
        jstring jid = env->NewStringUTF(p.id.c_str());
        jstring jip = env->NewStringUTF(p.ip.c_str());

        // --- FIX: Use the cached constructor method ID ---
        jobject obj = env->NewObject(g_peerInfoClass, g_peerInfoCtor, jid, jip, (jint)p.port, (jint)p.latency, (jboolean)p.connected);
        if (!obj) {
            nativeLog("JNI_GLUE: ERROR - Failed to create PeerInfo object for peer " + p.id);
            env->DeleteLocalRef(jid);
            env->DeleteLocalRef(jip);
            continue;
        }

        env->SetObjectArrayElement(arr, (jsize)i, obj);

        env->DeleteLocalRef(jid);
        env->DeleteLocalRef(jip);
        env->DeleteLocalRef(obj);
    }

    env->CallStaticVoidMethod(g_p2pClass, g_onPeersUpdated, arr);
    env->DeleteLocalRef(arr);
}
