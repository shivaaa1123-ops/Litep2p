#include "jni_glue.h"
#include "jni_helpers.h"
#include "logger.h"
#include <android/log.h>
#include <string>

static jclass g_p2pClass = nullptr;       // global ref to com.zeengal.litep2p.P2P class
static jmethodID g_onPeersUpdated = nullptr;

bool jniGlueInit(JNIEnv* env, jclass p2pClass) {
    if (!env || !p2pClass) {
        nativeLog("jniGlueInit: invalid args");
        return false;
    }

    // Keep a global ref to the class (we call static method on it)
    g_p2pClass = reinterpret_cast<jclass>(env->NewGlobalRef(p2pClass));
    if (!g_p2pClass) {
        nativeLog("jniGlueInit: NewGlobalRef failed");
        return false;
    }

    loggerSetJavaVM(vm);

    g_onPeersUpdated = env->GetStaticMethodID(
            p2pClass,
            "onPeersUpdated",
            "([Lcom/zeengal/litep2p/PeerInfo;)V"
    );

    if (!g_onPeersUpdated) {
        nativeLog("jniGlueInit: failed to find onPeersUpdated");
        env->DeleteGlobalRef(g_p2pClass);
        g_p2pClass = nullptr;
        return false;
    }

    nativeLog("jniGlueInit: OK");
    return true;
}

void jniGlueCleanup(JNIEnv* env) {
    if (!env) return;
    if (g_p2pClass) {
        env->DeleteGlobalRef(g_p2pClass);
        g_p2pClass = nullptr;
    }
    g_onPeersUpdated = nullptr;
    nativeLog("jniGlueCleanup: cleaned");
}

void sendPeersToUI(const std::vector<Peer>& peers) {
    JNIEnv* env = getJNIEnv();
    if (!env) {
        nativeLog("sendPeersToUI: cannot get JNIEnv");
        return;
    }

    if (!g_p2pClass || !g_onPeersUpdated) {
        nativeLog("sendPeersToUI: JNI not initialized");
        return;
    }

    // Find PeerInfo class and ctor
    jclass peerInfoCls = env->FindClass("com/zeengal/litep2p/PeerInfo");
    if (!peerInfoCls) {
        nativeLog("sendPeersToUI: cannot find PeerInfo class");
        return;
    }

    jmethodID ctor = env->GetMethodID(peerInfoCls, "<init>",
                                      "(Ljava/lang/String;Ljava/lang/String;IIZ)V");
    if (!ctor) {
        nativeLog("sendPeersToUI: cannot find PeerInfo ctor");
        env->DeleteLocalRef(peerInfoCls);
        return;
    }

    jobjectArray arr = env->NewObjectArray(static_cast<jsize>(peers.size()), peerInfoCls, nullptr);
    for (size_t i = 0; i < peers.size(); ++i) {
        const Peer& p = peers[i];
        jstring jid = env->NewStringUTF(p.id.c_str());
        jstring jip = env->NewStringUTF(p.ip.c_str());

        jobject obj = env->NewObject(peerInfoCls, ctor,
                                     jid, jip,
                                     (jint)p.port,
                                     (jint)p.latency,
                                     (jboolean)p.connected);
        env->SetObjectArrayElement(arr, (jsize)i, obj);

        env->DeleteLocalRef(jid);
        env->DeleteLocalRef(jip);
        env->DeleteLocalRef(obj);
    }

    env->CallStaticVoidMethod(g_p2pClass, g_onPeersUpdated, arr);

    env->DeleteLocalRef(arr);
    env->DeleteLocalRef(peerInfoCls);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    g_vm = vm;
    return JNI_VERSION_1_6;
}