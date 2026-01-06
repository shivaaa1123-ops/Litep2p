#include "jni_bridge.h"
#include "jni_helpers.h"
#include "logger.h"
#include "session_manager.h"
#include "constants.h"
#include <android/log.h>
#include "send_peer.h"

static SessionManager g_sessionManager;
static JavaVM* g_javaVM = nullptr;

static jclass g_mainActivityClass = nullptr;
static jmethodID g_onEngineStopComplete = nullptr;
static jclass g_p2pClass = nullptr;
static jmethodID g_onPeersUpdated = nullptr;
static jclass g_peerInfoClass = nullptr;
static jmethodID g_peerInfoCtor = nullptr;
static jclass g_loggerClass = nullptr;
static jmethodID g_addLogMethod = nullptr;

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    g_javaVM = vm;
    return JNI_VERSION_1_6;
}

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
        sendPeersToUI(peers);
    }, commsModeCpp, peerIdCpp);

    nativeLog("NATIVE: LiteP2P engine started successfully.");
    return env->NewStringUTF("OK");
}

extern "C" JNIEXPORT void JNICALL
Java_com_zeengal_litep2p_MainActivity_nativeConfigureProxy(JNIEnv* env, jobject /* this */, jboolean enableGateway, jboolean enableClient) {
    (void)env;
#if ENABLE_PROXY_MODULE
    proxy::ProxySettings s;
    s.enable_gateway = (enableGateway == JNI_TRUE);
    s.enable_client = (enableClient == JNI_TRUE);
    g_sessionManager.configure_proxy(s);
    nativeLog(std::string("NATIVE: Proxy configured (gateway=") + (s.enable_gateway ? "true" : "false") +
              ", client=" + (s.enable_client ? "true" : "false") + ")");
#else
    (void)enableGateway;
    (void)enableClient;
    nativeLog("NATIVE: Proxy configure requested, but proxy module not compiled");
#endif
}

extern "C" JNIEXPORT void JNICALL
Java_com_zeengal_litep2p_MainActivity_nativeStopLiteP2P(JNIEnv* env, jobject /* this */) {
    nativeLog("NATIVE: Stopping LiteP2P engine asynchronously...");
    
    g_sessionManager.stopAsync([]() {
        // Direct Android log to test if callback is executed
        __android_log_print(ANDROID_LOG_INFO, "LiteP2P_Native", "TEST: Async stop callback executed");
        
        nativeLog("NATIVE: Async stop complete. Notifying UI...");
        JNIEnv* env = nullptr;
        bool attached = false;
        
        // Check if JVM is still valid
        if (!g_javaVM) {
            nativeLog("NATIVE: ERROR - JVM not available for stop callback.");
            __android_log_print(ANDROID_LOG_ERROR, "LiteP2P_Native", "TEST: JVM not available for stop callback.");
            return;
        }
        
        // Try to get or attach JNIEnv
        jint result = g_javaVM->GetEnv((void**)&env, JNI_VERSION_1_6);
        if (result == JNI_EDETACHED) {
            if (g_javaVM->AttachCurrentThread(&env, nullptr) == JNI_OK) {
                attached = true;
                nativeLog("NATIVE: Thread attached to JVM for stop callback.");
                __android_log_print(ANDROID_LOG_INFO, "LiteP2P_Native", "TEST: Thread attached to JVM for stop callback.");
            } else {
                nativeLog("NATIVE: ERROR - Failed to attach thread to JVM for stop callback.");
                __android_log_print(ANDROID_LOG_ERROR, "LiteP2P_Native", "TEST: Failed to attach thread to JVM for stop callback.");
                return;
            }
        } else if (result != JNI_OK) {
            nativeLog("NATIVE: ERROR - Failed to get JNI environment for stop callback.");
            __android_log_print(ANDROID_LOG_ERROR, "LiteP2P_Native", "TEST: Failed to get JNI environment for stop callback. Result: %d", result);
            return;
        }

        // Validate all required references before calling
        nativeLog("NATIVE: Validating JNI references before callback...");
        __android_log_print(ANDROID_LOG_INFO, "LiteP2P_Native", "TEST: Validating JNI references before callback...");
        if (env && g_mainActivityClass && g_onEngineStopComplete) {
            nativeLog("NATIVE: All JNI references valid. Calling onEngineStopComplete on UI thread...");
            __android_log_print(ANDROID_LOG_INFO, "LiteP2P_Native", "TEST: All JNI references valid. Calling onEngineStopComplete on UI thread...");
            env->CallStaticVoidMethod(g_mainActivityClass, g_onEngineStopComplete);
            
            // Check for Java exceptions
            if (env->ExceptionCheck()) {
                nativeLog("NATIVE: EXCEPTION occurred in onEngineStopComplete callback.");
                __android_log_print(ANDROID_LOG_ERROR, "LiteP2P_Native", "TEST: EXCEPTION occurred in onEngineStopComplete callback.");
                env->ExceptionDescribe();
                env->ExceptionClear();
            } else {
                nativeLog("NATIVE: onEngineStopComplete callback executed successfully.");
                __android_log_print(ANDROID_LOG_INFO, "LiteP2P_Native", "TEST: onEngineStopComplete callback executed successfully.");
            }
        } else {
            nativeLog("NATIVE: ERROR - JNI references not valid for stop callback.");
            __android_log_print(ANDROID_LOG_ERROR, "LiteP2P_Native", "TEST: ERROR - JNI references not valid for stop callback.");
            if (!env) {
                nativeLog("NATIVE: env is null");
                __android_log_print(ANDROID_LOG_ERROR, "LiteP2P_Native", "TEST: env is null");
            }
            if (!g_mainActivityClass) {
                nativeLog("NATIVE: g_mainActivityClass is null");
                __android_log_print(ANDROID_LOG_ERROR, "LiteP2P_Native", "TEST: g_mainActivityClass is null");
            }
            if (!g_onEngineStopComplete) {
                nativeLog("NATIVE: g_onEngineStopComplete is null");
                __android_log_print(ANDROID_LOG_ERROR, "LiteP2P_Native", "TEST: g_onEngineStopComplete is null");
            }
        }

        // Detach if we attached
        if (attached) {
            g_javaVM->DetachCurrentThread();
            nativeLog("NATIVE: Thread detached from JVM after stop callback.");
            __android_log_print(ANDROID_LOG_INFO, "LiteP2P_Native", "TEST: Thread detached from JVM after stop callback.");
        }
        
        nativeLog("NATIVE: Stop callback processing complete.");
        __android_log_print(ANDROID_LOG_INFO, "LiteP2P_Native", "TEST: Stop callback processing complete.");
    });
}

extern "C" JNIEXPORT void JNICALL
Java_com_zeengal_litep2p_hook_P2P_connect(JNIEnv* env, jclass /* clazz */, jstring peerId) {
    const char* peerIdStr = env->GetStringUTFChars(peerId, nullptr);
    if (peerIdStr == nullptr) return;
    std::string peerIdCpp(peerIdStr);
    env->ReleaseStringUTFChars(peerId, peerIdStr);
    
    nativeLog("NATIVE: UI requested connection to " + peerIdCpp);
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
    jclass localMainActivityClass = env->FindClass("com/zeengal/litep2p/MainActivity");
    if (!localMainActivityClass) return false;
    g_mainActivityClass = (jclass)env->NewGlobalRef(localMainActivityClass);
    env->DeleteLocalRef(localMainActivityClass);
    g_onEngineStopComplete = env->GetStaticMethodID(g_mainActivityClass, "onEngineStopComplete", "()V");
    if (!g_onEngineStopComplete) return false;
    
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
    if (g_mainActivityClass) env->DeleteGlobalRef(g_mainActivityClass);
    if (g_p2pClass) env->DeleteGlobalRef(g_p2pClass);
    if (g_peerInfoClass) env->DeleteGlobalRef(g_peerInfoClass);
    if (g_loggerClass) env->DeleteGlobalRef(g_loggerClass);
    g_mainActivityClass = nullptr; g_p2pClass = nullptr; g_peerInfoClass = nullptr; g_loggerClass = nullptr;
}
void sendPeersToUI(const std::vector<Peer>& peers) {
    JNIEnv* env = getJNIEnv(g_javaVM);
    if (!env || !g_p2pClass || !g_onPeersUpdated || !g_peerInfoClass || !g_peerInfoCtor) return;
    jobjectArray arr = env->NewObjectArray((jsize)peers.size(), g_peerInfoClass, nullptr);
    if (!arr) return;
    for (size_t i = 0; i < peers.size(); ++i) {
        const Peer& p = peers[i];
        jstring jid = env->NewStringUTF(p.id.c_str());
        jstring jip = env->NewStringUTF(p.ip.c_str());
        jstring jnetworkId = env->NewStringUTF(p.network_id.c_str());
        jobject obj = env->NewObject(g_peerInfoClass, g_peerInfoCtor, jid, jip, (jint)p.port, (jint)p.latency, (jboolean)p.connected, jnetworkId);
        env->SetObjectArrayElement(arr, (jsize)i, obj);
        env->DeleteLocalRef(jid); env->DeleteLocalRef(jip); env->DeleteLocalRef(jnetworkId); env->DeleteLocalRef(obj);
    }
    env->CallStaticVoidMethod(g_p2pClass, g_onPeersUpdated, arr);
    env->DeleteLocalRef(arr);
}
void sendToLogUI(const std::string& message) {
    JNIEnv* env = getJNIEnv(g_javaVM);
    if (!env || !g_loggerClass || !g_addLogMethod) return;
    jstring jmsg = env->NewStringUTF(message.c_str());
    env->CallStaticVoidMethod(g_loggerClass, g_addLogMethod, jmsg);
    env->DeleteLocalRef(jmsg);
}

void setLogLevel(int level) {
    // Convert integer level to LogLevel enum
    LogLevel logLevel;
    switch (level) {
        case 0:
            logLevel = LogLevel::DEBUG;
            break;
        case 1:
            logLevel = LogLevel::INFO;
            break;
        case 2:
            logLevel = LogLevel::WARNING;
            break;
        default:
            logLevel = LogLevel::INFO;
            break;
    }
    set_log_level(logLevel);
}

// NAT Traversal and Reconnect Policy APIs
extern "C" JNIEXPORT void JNICALL
Java_com_zeengal_litep2p_hook_P2P_setLogLevel(JNIEnv* env, jclass /* clazz */, jint level) {
    setLogLevel((int)level);
}

extern "C" JNIEXPORT void JNICALL
Java_com_zeengal_litep2p_hook_P2P_setSystemBatteryLevel(JNIEnv* env, jclass /* clazz */, jint batteryPercent, jboolean isCharging) {
    nativeLog("NATIVE: Battery level update - " + std::to_string(batteryPercent) + "%, charging: " + 
             (isCharging ? "true" : "false"));
    g_sessionManager.set_battery_level((int)batteryPercent, (bool)isCharging);
}

extern "C" JNIEXPORT void JNICALL
Java_com_zeengal_litep2p_hook_P2P_setSystemNetworkInfo(JNIEnv* env, jclass /* clazz */, jboolean isWiFi, jboolean isNetworkAvailable) {
    nativeLog("NATIVE: Network info update - WiFi: " + (isWiFi ? std::string("true") : std::string("false")) + 
             ", Available: " + (isNetworkAvailable ? std::string("true") : std::string("false")));
    g_sessionManager.set_network_info((bool)isWiFi, (bool)isNetworkAvailable);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_zeengal_litep2p_hook_P2P_getReconnectStatus(JNIEnv* env, jclass /* clazz */) {
    std::string status = g_sessionManager.get_reconnect_status_json();
    nativeLog("NATIVE: Reconnect status requested - " + status);
    return env->NewStringUTF(status.c_str());
}
