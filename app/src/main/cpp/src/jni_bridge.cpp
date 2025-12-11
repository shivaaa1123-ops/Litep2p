
#include "jni_bridge.h"
#include "jni_helpers.h"
#include "logger.h"
#include "session_manager.h"
#include "constants.h"
#include <android/log.h>
// #include <openssl/evp.h>  // Disabled: Crypto functionality disabled
// #include <openssl/rand.h>

// Crypto functionality disabled - messages pass through unencrypted
std::string encrypt_message(const std::string& message) {
    nativeLog("Crypto Warning: Encryption disabled - message passed through");
    return message;
}

std::string decrypt_message(const std::string& message) {
    nativeLog("Crypto Warning: Decryption disabled - message passed through");
    return message;
}

std::string encrypt_message_udp(const std::string& message) {
    return encrypt_message(message);
}

std::string decrypt_message_udp(const std::string& message) {
    return decrypt_message(message);
}

static SessionManager g_sessionManager;

static jclass g_p2pClass = nullptr;
static jmethodID g_onPeersUpdated = nullptr;
static jclass g_peerInfoClass = nullptr;
static jmethodID g_peerInfoCtor = nullptr;
static jclass g_loggerClass = nullptr;
static jmethodID g_addLogMethod = nullptr;

extern "C" JNIEXPORT jstring JNICALL
Java_com_zeengal_litep2p_MainActivity_nativeStartLiteP2PWithPeerId(JNIEnv* env, jobject /* this */, jstring commsMode, jstring peerId) {
    nativeLog("NATIVE: Starting LiteP2P engine...");
    
    if (!jniBridgeInit(env)) {
        nativeLog("NATIVE: FATAL - JNI Bridge initialization failed.");
        if (env->ExceptionCheck()) env->ExceptionClear();
        return env->NewStringUTF("JNI Bridge Init Failed");
    }

    const char* commsModeStr = env->GetStringUTFChars(commsMode, nullptr);
    if (commsModeStr == nullptr) {
        nativeLog("NATIVE: Failed to get comms mode string");
        if (env->ExceptionCheck()) env->ExceptionClear();
        return env->NewStringUTF("Failed to get comms mode");
    }
    std::string commsModeCpp(commsModeStr);
    env->ReleaseStringUTFChars(commsMode, commsModeStr);

    const char* peerIdStr = env->GetStringUTFChars(peerId, nullptr);
    if (peerIdStr == nullptr) {
        nativeLog("NATIVE: Failed to get peer ID string");
        if (env->ExceptionCheck()) env->ExceptionClear();
        return env->NewStringUTF("Failed to get peer ID");
    }
    std::string peerIdCpp(peerIdStr);
    env->ReleaseStringUTFChars(peerId, peerIdStr);

    int port = DEFAULT_SERVER_PORT; 
    g_sessionManager.start(port, [](const std::vector<Peer>& peers) {
        nativeLog("SESSION_CB: Peer list updated with " + std::to_string(peers.size()) + " peers. Calling sendPeersToUI.");
        sendPeersToUI(peers);
    }, commsModeCpp, peerIdCpp);

    nativeLog("NATIVE: LiteP2P engine started successfully.");
    return env->NewStringUTF("OK");
}

extern "C" JNIEXPORT void JNICALL
Java_com_zeengal_litep2p_MainActivity_nativeStopLiteP2P(JNIEnv* env, jobject /* this */) {
    nativeLog("NATIVE: Stopping LiteP2P engine...");
    
    g_sessionManager.stop();
    
    detachJNIEnv();

    jniBridgeCleanup(env);
    
    nativeLog("NATIVE: LiteP2P engine stopped.");
}

extern "C" JNIEXPORT void JNICALL
Java_com_zeengal_litep2p_hook_P2P_connect(JNIEnv* env, jclass /* clazz */, jstring peerId) {
    const char* peerIdStr = env->GetStringUTFChars(peerId, nullptr);
    if (peerIdStr == nullptr) return;
    std::string peerIdCpp(peerIdStr);
    env->ReleaseStringUTFChars(peerId, peerIdStr);
    
    nativeLog("NATIVE: UI requested connection to " + peerIdCpp);
    nativeLog("CONNECT_COMMAND: User clicked on peer '" + peerIdCpp + "' - initiating connection");
    g_sessionManager.connectToPeer(peerIdCpp);
}

extern "C" JNIEXPORT void JNICALL
Java_com_zeengal_litep2p_hook_P2P_sendMessage(JNIEnv* env, jclass /* clazz */, jstring peerId, jbyteArray message) {
    const char* peerIdStr = env->GetStringUTFChars(peerId, nullptr);
    if (peerIdStr == nullptr) return;
    std::string peerIdCpp(peerIdStr);
    env->ReleaseStringUTFChars(peerId, peerIdStr);

    jbyte* messageElements = env->GetByteArrayElements(message, nullptr);
    jsize messageLength = env->GetArrayLength(message);
    if (messageElements == nullptr) return;
    std::string messageCpp((char*)messageElements, messageLength);
    env->ReleaseByteArrayElements(message, messageElements, JNI_ABORT);

    g_sessionManager.sendMessageToPeer(peerIdCpp, messageCpp);
}

bool jniBridgeInit(JNIEnv* env) {
    nativeLog("JNI_BRIDGE: Caching class references...");
    jclass localP2pClass = env->FindClass("com/zeengal/litep2p/hook/P2P");
    if (!localP2pClass) return false;
    g_p2pClass = (jclass)env->NewGlobalRef(localP2pClass);
    env->DeleteLocalRef(localP2pClass);
    g_onPeersUpdated = env->GetStaticMethodID(g_p2pClass, "onPeersUpdated", "([Lcom/zeengal/litep2p/PeerInfo;)V");
    if (!g_onPeersUpdated) return false;
    jclass localPeerInfoClass = env->FindClass("com/zeengal/litep2p/PeerInfo");
    if (!localPeerInfoClass) return false;
    g_peerInfoClass = (jclass)env->NewGlobalRef(localPeerInfoClass);
    env->DeleteLocalRef(localPeerInfoClass);
    g_peerInfoCtor = env->GetMethodID(g_peerInfoClass, "<init>", "(Ljava/lang/String;Ljava/lang/String;IIZLjava/lang/String;)V");
    if (!g_peerInfoCtor) return false;
    jclass localLoggerClass = env->FindClass("com/zeengal/litep2p/LiteP2PLogger");
    if (!localLoggerClass) return false;
    g_loggerClass = (jclass)env->NewGlobalRef(localLoggerClass);
    env->DeleteLocalRef(localLoggerClass);
    g_addLogMethod = env->GetStaticMethodID(g_loggerClass, "addLog", "(Ljava/lang/String;)V");
    if (!g_addLogMethod) return false;
    nativeLog("JNI_BRIDGE: Initialization complete.");
    return true;
}

void jniBridgeCleanup(JNIEnv* env) {
    if (g_p2pClass) env->DeleteGlobalRef(g_p2pClass);
    if (g_peerInfoClass) env->DeleteGlobalRef(g_peerInfoClass);
    if (g_loggerClass) env->DeleteGlobalRef(g_loggerClass);
    g_p2pClass = nullptr; g_peerInfoClass = nullptr; g_loggerClass = nullptr;
}

void sendPeersToUI(const std::vector<Peer>& peers) {
    JNIEnv* env = getJNIEnv();
    if (!env) {
        nativeLog("JNI_ERROR: Failed to get JNIEnv in sendPeersToUI. Is the thread attached?");
        return;
    }
    if (!g_p2pClass || !g_onPeersUpdated || !g_peerInfoClass || !g_peerInfoCtor) {
        nativeLog("JNI_ERROR: JNI references are not initialized in sendPeersToUI.");
        return;
    }

    nativeLog("JNI_BRIDGE: Preparing to send " + std::to_string(peers.size()) + " peers to UI.");

    jobjectArray arr = env->NewObjectArray((jsize)peers.size(), g_peerInfoClass, nullptr);
    if (!arr) {
        nativeLog("JNI_ERROR: Failed to create NewObjectArray for peers.");
        return;
    }

    for (size_t i = 0; i < peers.size(); ++i) {
        const Peer& p = peers[i];
        jstring jid = env->NewStringUTF(p.id.c_str());
        jstring jip = env->NewStringUTF(p.ip.c_str());
        jstring jnetworkId = env->NewStringUTF(p.network_id.c_str());
        jobject obj = env->NewObject(g_peerInfoClass, g_peerInfoCtor, jid, jip, (jint)p.port, (jint)p.latency, (jboolean)p.connected, jnetworkId);
        env->SetObjectArrayElement(arr, (jsize)i, obj);
        env->DeleteLocalRef(jid); env->DeleteLocalRef(jip); env->DeleteLocalRef(jnetworkId); env->DeleteLocalRef(obj);
    }

    nativeLog("JNI_BRIDGE: Calling onPeersUpdated on the UI thread.");
    env->CallStaticVoidMethod(g_p2pClass, g_onPeersUpdated, arr);
    env->DeleteLocalRef(arr);
}

void sendToLogUI(const std::string& message) {
    JNIEnv* env = getJNIEnv();
    if (!env || !g_loggerClass || !g_addLogMethod) return;
    jstring jmsg = env->NewStringUTF(message.c_str());
    env->CallStaticVoidMethod(g_loggerClass, g_addLogMethod, jmsg);
    env->DeleteLocalRef(jmsg);
}
