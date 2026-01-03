
#include "jni_bridge.h"
#include "jni_helpers.h"
#include "logger.h"
#include "session_manager.h"
#include "constants.h"
#include "crypto_utils.h"
#include "config_manager.h"
#include <jni.h>
#include <thread>
#include <future>
#include <mutex>
#include <atomic>
#include <signal.h>

#if ENABLE_PROXY_MODULE
#include "proxy_endpoint.h"
#endif

#ifdef __ANDROID__
#include <android/log.h>
#endif

// #include <openssl/evp.h>  // Disabled: Crypto functionality disabled
// #include <openssl/rand.h>

/*
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
*/

static SessionManager g_sessionManager;

#ifdef __ANDROID__
namespace {

std::string jstring_to_utf8(JNIEnv* env, jstring s) {
    if (!env || !s) return {};
    const char* chars = env->GetStringUTFChars(s, nullptr);
    if (!chars) return {};
    std::string out(chars);
    env->ReleaseStringUTFChars(s, chars);
    return out;
}

void maybe_configure_peer_db_path_from_files_dir(JNIEnv* env, jobject activity) {
    if (!env || !activity) return;

    ConfigManager& cfg = ConfigManager::getInstance();
    if (!cfg.isPeerDbEnabled()) return;
    if (!cfg.getPeerDbPath().empty()) return;

    jclass activity_cls = env->GetObjectClass(activity);
    if (!activity_cls) return;

    jmethodID mid_get_files_dir = env->GetMethodID(activity_cls, "getFilesDir", "()Ljava/io/File;");
    if (!mid_get_files_dir) {
        env->DeleteLocalRef(activity_cls);
        return;
    }

    jobject files_dir_file = env->CallObjectMethod(activity, mid_get_files_dir);
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
    }

    if (!files_dir_file) {
        env->DeleteLocalRef(activity_cls);
        return;
    }

    jclass file_cls = env->GetObjectClass(files_dir_file);
    if (!file_cls) {
        env->DeleteLocalRef(files_dir_file);
        env->DeleteLocalRef(activity_cls);
        return;
    }

    jmethodID mid_get_abs_path = env->GetMethodID(file_cls, "getAbsolutePath", "()Ljava/lang/String;");
    if (!mid_get_abs_path) {
        env->DeleteLocalRef(file_cls);
        env->DeleteLocalRef(files_dir_file);
        env->DeleteLocalRef(activity_cls);
        return;
    }

    jstring dir_str = static_cast<jstring>(env->CallObjectMethod(files_dir_file, mid_get_abs_path));
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
    }

    const std::string dir = jstring_to_utf8(env, dir_str);
    if (!dir.empty()) {
        const std::string db_path = dir + "/litep2p_peers.sqlite";
        cfg.setValueAtPath({"storage", "peer_db", "path"}, db_path);
        nativeLog("NATIVE: Peer DB path set to " + db_path);
    }

    if (dir_str) env->DeleteLocalRef(dir_str);
    env->DeleteLocalRef(file_cls);
    env->DeleteLocalRef(files_dir_file);
    env->DeleteLocalRef(activity_cls);
}

void maybe_configure_noise_keystore_path_from_files_dir(JNIEnv* env, jobject activity) {
    if (!env || !activity) return;

    ConfigManager& cfg = ConfigManager::getInstance();
    if (!cfg.isNoiseNKEnabled()) return;

    const std::string current = cfg.getKeyStorePath();
    // If the user explicitly configured a path, honor it.
    // Otherwise, replace the default "keystore" (relative, may be unwritable on Android)
    // with an app-private filesDir-based path.
    if (!current.empty() && current != "keystore") {
        return;
    }

    jclass activity_cls = env->GetObjectClass(activity);
    if (!activity_cls) return;

    jmethodID mid_get_files_dir = env->GetMethodID(activity_cls, "getFilesDir", "()Ljava/io/File;");
    if (!mid_get_files_dir) {
        env->DeleteLocalRef(activity_cls);
        return;
    }

    jobject files_dir_file = env->CallObjectMethod(activity, mid_get_files_dir);
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
    }

    if (!files_dir_file) {
        env->DeleteLocalRef(activity_cls);
        return;
    }

    jclass file_cls = env->GetObjectClass(files_dir_file);
    if (!file_cls) {
        env->DeleteLocalRef(files_dir_file);
        env->DeleteLocalRef(activity_cls);
        return;
    }

    jmethodID mid_get_abs_path = env->GetMethodID(file_cls, "getAbsolutePath", "()Ljava/lang/String;");
    if (!mid_get_abs_path) {
        env->DeleteLocalRef(file_cls);
        env->DeleteLocalRef(files_dir_file);
        env->DeleteLocalRef(activity_cls);
        return;
    }

    jstring dir_str = static_cast<jstring>(env->CallObjectMethod(files_dir_file, mid_get_abs_path));
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
    }

    const std::string dir = jstring_to_utf8(env, dir_str);
    if (!dir.empty()) {
        const std::string key_store_dir = dir + "/keystore";
        cfg.setValueAtPath({"security", "noise_nk_protocol", "key_store_path"}, key_store_dir);
        nativeLog("NATIVE: Noise keystore path set to " + key_store_dir);
    }

    if (dir_str) env->DeleteLocalRef(dir_str);
    env->DeleteLocalRef(file_cls);
    env->DeleteLocalRef(files_dir_file);
    env->DeleteLocalRef(activity_cls);
}

} // namespace
#endif

// ----------------------------------------------------------------------------
// Java hook utilities (P2P.* JNI surface)
// ----------------------------------------------------------------------------
namespace {
static void setLogLevelFromJava(int level) {
    LogLevel logLevel;
    switch (level) {
        case 0: logLevel = LogLevel::DEBUG; break;
        case 1: logLevel = LogLevel::INFO; break;
        case 2: logLevel = LogLevel::WARNING; break;
        case 3: logLevel = LogLevel::ERROR; break;
        default: logLevel = LogLevel::INFO; break;
    }
    set_log_level(logLevel);
}
} // namespace

// ----------------------------------------------------------------------------
// Engine lifecycle state guard (prevents start/stop races from UI)
// ----------------------------------------------------------------------------
namespace {
    enum class EngineLifecycleState : int {
        STOPPED = 0,
        STARTING = 1,
        RUNNING = 2,
        STOPPING = 3,
    };

    std::mutex g_engine_state_mutex;
    std::atomic<EngineLifecycleState> g_engine_state{EngineLifecycleState::STOPPED};

    const char* stateToString(EngineLifecycleState s) {
        switch (s) {
            case EngineLifecycleState::STOPPED: return "STOPPED";
            case EngineLifecycleState::STARTING: return "STARTING";
            case EngineLifecycleState::RUNNING: return "RUNNING";
            case EngineLifecycleState::STOPPING: return "STOPPING";
            default: return "UNKNOWN";
        }
    }
}

static jclass g_p2pClass = nullptr;
static jclass g_mainActivityClass = nullptr;
static jmethodID g_onPeersUpdated = nullptr;
static jmethodID g_onEngineStartComplete = nullptr;
static jmethodID g_onEngineStopComplete = nullptr;
static jmethodID g_onMessageReceived = nullptr;
static jclass g_peerInfoClass = nullptr;
static jmethodID g_peerInfoCtor = nullptr;
static jclass g_loggerClass = nullptr;
static jmethodID g_addLogMethod = nullptr;

namespace {
    std::mutex g_jni_cache_mutex;
    bool g_jni_cache_initialized = false;

    void safeDeleteGlobalRef(JNIEnv* env, jobject& ref) {
        if (env && ref) {
            env->DeleteGlobalRef(ref);
            ref = nullptr;
        }
    }
}

// JNI_OnLoad is called when the native library is loaded by the JVM
// This is the perfect place to set up signal handlers (similar to main() for desktop)
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    (void)reserved;

    // Ignore SIGPIPE to prevent process termination on socket write errors
    signal(SIGPIPE, SIG_IGN);
    // Ignore SIGUSR1 to survive interruption signals (used by test suites)
    signal(SIGUSR1, SIG_IGN);

    // Store JavaVM and prepare helper utilities.
    jni_helpers_on_load(vm);
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT void JNICALL JNI_OnUnload(JavaVM* vm, void* reserved) {
    (void)reserved;
    jni_helpers_on_unload(vm);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_zeengal_litep2p_MainActivity_nativeStartLiteP2PWithPeerId(JNIEnv* env, jobject thiz, jstring commsMode, jstring peerId) {
    nativeLog("NATIVE: Starting LiteP2P engine...");

    {
        std::lock_guard<std::mutex> lock(g_engine_state_mutex);
        const EngineLifecycleState cur = g_engine_state.load(std::memory_order_acquire);
        if (cur != EngineLifecycleState::STOPPED) {
            const std::string msg = std::string("BUSY_") + stateToString(cur);
            nativeLog("NATIVE: Start rejected - engine state is " + std::string(stateToString(cur)));
            return env->NewStringUTF(msg.c_str());
        }
        g_engine_state.store(EngineLifecycleState::STARTING, std::memory_order_release);
    }
    
    if (!jniBridgeInit(env)) {
        nativeLog("NATIVE: FATAL - JNI Bridge initialization failed.");
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        return env->NewStringUTF("JNI Bridge Init Failed");
    }

    const char* commsModeStr = env->GetStringUTFChars(commsMode, nullptr);
    if (commsModeStr == nullptr) {
        nativeLog("NATIVE: Failed to get comms mode string");
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        return env->NewStringUTF("Failed to get comms mode");
    }
    std::string commsModeCpp(commsModeStr);
    env->ReleaseStringUTFChars(commsMode, commsModeStr);

    const char* peerIdStr = env->GetStringUTFChars(peerId, nullptr);
    if (peerIdStr == nullptr) {
        nativeLog("NATIVE: Failed to get peer ID string");
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        return env->NewStringUTF("Failed to get peer ID");
    }
    std::string peerIdCpp(peerIdStr);
    env->ReleaseStringUTFChars(peerId, peerIdStr);

#ifdef __ANDROID__
    // If peer DB is enabled but no explicit path is configured, inject a safe default
    // using the app-private files directory.
    maybe_configure_peer_db_path_from_files_dir(env, thiz);

    // Similarly, ensure the Noise key store path is writable and stable so local identity
    // does not change across process restarts.
    maybe_configure_noise_keystore_path_from_files_dir(env, thiz);
#endif

    int port = DEFAULT_SERVER_PORT;
    g_sessionManager.start(port, [](const std::vector<Peer>& peers) {
        nativeLog("SESSION_CB: Peer list updated with " + std::to_string(peers.size()) + " peers. Calling sendPeersToUI.");
        sendPeersToUI(peers);
    }, commsModeCpp, peerIdCpp);
    
    // Set up message received callback
    // This callback is invoked whenever a peer sends an APPLICATION_DATA message
    // Complete message flow:
    // 1. Sender: User sends message via UI → JNI bridge → SessionManager.sendMessageToPeer()
    // 2. Sender: Message pushed to event queue → EventManager processes it
    // 3. Sender: MessageHandler batches and sends via TCP
    // 4. Receiver: TCP layer receives data → SessionManager.onData() pushes DataReceivedEvent
    // 5. Receiver: EventManager processes event → MessageHandler decodes message
    // 6. Receiver: APPLICATION_DATA identified → message callback invoked with (peer_id, message)
    // 7. UI: Application receives message via callback and displays it
    g_sessionManager.setMessageReceivedCallback([](const std::string& peer_id, const std::string& message) {
        nativeLog("JNI_BRIDGE: Message received from peer " + peer_id + ", message length=" + std::to_string(message.length()));
        nativeLog("JNI_BRIDGE: Message content: " + message);
        
        // Forward message to UI callback - post to Java for UI display
        JNIEnv* cbEnv = getJNIEnv();
        if (cbEnv && g_p2pClass && g_onMessageReceived) {
            // Create Java string for peer ID
            jstring jPeerId = cbEnv->NewStringUTF(peer_id.c_str());
            // Create Java byte array for message
            const char* msgBytes = message.c_str();
            jbyteArray jMessage = cbEnv->NewByteArray(message.length());
            if (jMessage) {
                cbEnv->SetByteArrayRegion(jMessage, 0, message.length(), (jbyte*)msgBytes);
                // Call P2P.onMessageReceived(peerId, messageBytes)
                cbEnv->CallStaticVoidMethod(g_p2pClass, g_onMessageReceived, jPeerId, jMessage);
                if (cbEnv->ExceptionCheck()) {
                    nativeLog("JNI_BRIDGE: Exception calling onMessageReceived callback");
                    cbEnv->ExceptionDescribe();
                    cbEnv->ExceptionClear();
                }
                cbEnv->DeleteLocalRef(jMessage);
            }
            if (jPeerId) {
                cbEnv->DeleteLocalRef(jPeerId);
            }
        } else {
            nativeLog("JNI_BRIDGE: Cannot invoke callback - env/class/method is null");
        }
    });
    
    // Check for exceptions after calling start
    if (env->ExceptionCheck()) {
        nativeLog("NATIVE: Exception occurred after calling sessionManager.start.");
        env->ExceptionDescribe();
        env->ExceptionClear();
        {
            std::lock_guard<std::mutex> lock(g_engine_state_mutex);
            g_engine_state.store(EngineLifecycleState::STOPPED, std::memory_order_release);
        }
        return env->NewStringUTF("Exception after sessionManager.start");
    }

    {
        std::lock_guard<std::mutex> lock(g_engine_state_mutex);
        g_engine_state.store(EngineLifecycleState::RUNNING, std::memory_order_release);
    }
    
    // Notify Java layer that start is complete
    // Try MainActivity first, then fall back to P2P
    JNIEnv* jniEnv = getJNIEnv();
    if (jniEnv) {
        bool calledMainActivity = false;
        if (g_mainActivityClass) {
            jmethodID mainActivityMethod = jniEnv->GetStaticMethodID(g_mainActivityClass, "onEngineStartComplete", "()V");
            if (mainActivityMethod) {
                jniEnv->CallStaticVoidMethod(g_mainActivityClass, mainActivityMethod);
                calledMainActivity = true;
                // Check for exceptions after calling the Java method
                if (jniEnv->ExceptionCheck()) {
                    nativeLog("NATIVE: Exception occurred when calling MainActivity.onEngineStartComplete.");
                    jniEnv->ExceptionDescribe();
                    jniEnv->ExceptionClear();
                }
            }
        }
        
        // Fall back to P2P if MainActivity method wasn't called
        if (!calledMainActivity && g_onEngineStartComplete) {
            if (g_p2pClass) {
                jniEnv->CallStaticVoidMethod(g_p2pClass, g_onEngineStartComplete);
                // Check for exceptions after calling the Java method
                if (jniEnv->ExceptionCheck()) {
                    nativeLog("NATIVE: Exception occurred when calling P2P.onEngineStartComplete.");
                    jniEnv->ExceptionDescribe();
                    jniEnv->ExceptionClear();
                }
            }
        }
    }

    nativeLog("NATIVE: LiteP2P engine started successfully.");
    return env->NewStringUTF("OK");
}

extern "C" JNIEXPORT void JNICALL
Java_com_zeengal_litep2p_MainActivity_nativeConfigureProxy(JNIEnv* /* env */, jobject /* this */, jboolean enableGateway, jboolean enableClient) {
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

    {
        std::lock_guard<std::mutex> lock(g_engine_state_mutex);
        const EngineLifecycleState cur = g_engine_state.load(std::memory_order_acquire);
        if (cur == EngineLifecycleState::STOPPED || cur == EngineLifecycleState::STOPPING) {
            nativeLog("NATIVE: Stop ignored - engine state is " + std::string(stateToString(cur)));
            return;
        }
        g_engine_state.store(EngineLifecycleState::STOPPING, std::memory_order_release);
    }

    // Use the stopAsync function which returns a future
    std::future<void> stopFuture = g_sessionManager.stopAsync();

    // Create a new thread to wait for the engine to stop and then notify the UI
    std::thread([](std::future<void> future) {
        future.wait(); // Wait for the stop operation to complete

        nativeLog("NATIVE: LiteP2P engine stopped.");

        {
            std::lock_guard<std::mutex> lock(g_engine_state_mutex);
            g_engine_state.store(EngineLifecycleState::STOPPED, std::memory_order_release);
        }

        // Notify Java layer that stop is complete
        // Try MainActivity first, then fall back to P2P
        JNIEnv* jniEnv = getJNIEnv();
        if (jniEnv) {
            bool calledMainActivity = false;
            if (g_mainActivityClass) {
                jmethodID mainActivityMethod = jniEnv->GetStaticMethodID(g_mainActivityClass, "onEngineStopComplete", "()V");
                if (mainActivityMethod) {
                    jniEnv->CallStaticVoidMethod(g_mainActivityClass, mainActivityMethod);
                    calledMainActivity = true;
                    // Check for exceptions after calling the Java method
                    if (jniEnv->ExceptionCheck()) {
                        nativeLog("NATIVE: Exception occurred when calling MainActivity.onEngineStopComplete.");
                        jniEnv->ExceptionDescribe();
                        jniEnv->ExceptionClear();
                    }
                }
            }

            // Fall back to P2P if MainActivity method wasn't called
            if (!calledMainActivity && g_onEngineStopComplete) {
                if (g_p2pClass) {
                    jniEnv->CallStaticVoidMethod(g_p2pClass, g_onEngineStopComplete);
                    // Check for exceptions after calling the Java method
                    if (jniEnv->ExceptionCheck()) {
                        nativeLog("NATIVE: Exception occurred when calling P2P.onEngineStopComplete.");
                        jniEnv->ExceptionDescribe();
                        jniEnv->ExceptionClear();
                    }
                }
            }
        }
    }, std::move(stopFuture)).detach();

    // Check for exceptions after calling stopAsync
    if (env->ExceptionCheck()) {
        nativeLog("NATIVE: Exception occurred after calling sessionManager.stopAsync.");
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_zeengal_litep2p_hook_P2P_connect(JNIEnv* env, jclass /* clazz */, jstring peerId) {
    const char* peerIdStr = env->GetStringUTFChars(peerId, nullptr);
    if (peerIdStr == nullptr) {
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        return;
    }
    std::string peerIdCpp(peerIdStr);
    env->ReleaseStringUTFChars(peerId, peerIdStr);
    
    nativeLog("NATIVE: UI requested connection to " + peerIdCpp);
    nativeLog("CONNECT_COMMAND: User clicked on peer '" + peerIdCpp + "' - initiating connection");
    g_sessionManager.connectToPeer(peerIdCpp);
    
    // Check for exceptions after calling connectToPeer
    if (env->ExceptionCheck()) {
        nativeLog("NATIVE: Exception occurred after calling sessionManager.connectToPeer.");
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_zeengal_litep2p_hook_P2P_setLogLevel(JNIEnv* env, jclass /* clazz */, jint level) {
    (void)env;
    setLogLevelFromJava(static_cast<int>(level));
}

extern "C" JNIEXPORT void JNICALL
Java_com_zeengal_litep2p_hook_P2P_setSystemNetworkInfo(JNIEnv* env, jclass /* clazz */, jboolean isWiFi, jboolean isNetworkAvailable) {
    (void)env;
    nativeLog("NATIVE: Network info update - WiFi: " + (isWiFi ? std::string("true") : std::string("false")) +
              ", Available: " + (isNetworkAvailable ? std::string("true") : std::string("false")));
    g_sessionManager.set_network_info(static_cast<bool>(isWiFi), static_cast<bool>(isNetworkAvailable));
}

extern "C" JNIEXPORT void JNICALL
Java_com_zeengal_litep2p_hook_P2P_sendMessage(JNIEnv* env, jclass /* clazz */, jstring peerId, jbyteArray message) {
    nativeLog("JNI: sendMessage called from UI");
    
    const char* peerIdStr = env->GetStringUTFChars(peerId, nullptr);
    if (peerIdStr == nullptr) {
        nativeLog("JNI: ERROR - Failed to get peerId from JNI");
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        return;
    }
    std::string peerIdCpp(peerIdStr);
    nativeLog("JNI: sendMessage for peer: " + peerIdCpp);
    env->ReleaseStringUTFChars(peerId, peerIdStr);

    jbyte* messageElements = env->GetByteArrayElements(message, nullptr);
    jsize messageLength = env->GetArrayLength(message);
    nativeLog("JNI: Message length: " + std::to_string(messageLength));
    if (messageElements == nullptr) {
        nativeLog("JNI: ERROR - Failed to get message bytes from JNI");
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        return;
    }
    std::string messageCpp((char*)messageElements, messageLength);
    env->ReleaseByteArrayElements(message, messageElements, JNI_ABORT);

    nativeLog("JNI: Calling g_sessionManager.sendMessageToPeer(" + peerIdCpp + ", msg_len=" + std::to_string(messageCpp.length()) + ")");
    g_sessionManager.sendMessageToPeer(peerIdCpp, messageCpp);
    nativeLog("JNI: sendMessageToPeer returned successfully");
    
    // Check for exceptions after calling sendMessageToPeer
    if (env->ExceptionCheck()) {
        nativeLog("NATIVE: Exception occurred after calling sessionManager.sendMessageToPeer.");
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
}

bool jniBridgeInit(JNIEnv* env) {
    if (!env) return false;

    std::lock_guard<std::mutex> lock(g_jni_cache_mutex);
    if (g_jni_cache_initialized) {
        return true;
    }

    nativeLog("JNI_BRIDGE: Caching class references (init-once)...");

    jclass newP2pClass = nullptr;
    jclass newMainActivityClass = nullptr;
    jclass newPeerInfoClass = nullptr;
    jclass newLoggerClass = nullptr;

    jmethodID newOnPeersUpdated = nullptr;
    jmethodID newOnEngineStartComplete = nullptr;
    jmethodID newOnEngineStopComplete = nullptr;
    jmethodID newOnMessageReceived = nullptr;
    jmethodID newPeerInfoCtor = nullptr;
    jmethodID newAddLogMethod = nullptr;

    // P2P class (required)
    jclass localP2pClass = env->FindClass("com/zeengal/litep2p/hook/P2P");
    if (!localP2pClass) {
        nativeLog("JNI_BRIDGE: Failed to find P2P class");
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        return false;
    }
    newP2pClass = (jclass)env->NewGlobalRef(localP2pClass);
    env->DeleteLocalRef(localP2pClass);
    if (!newP2pClass) {
        nativeLog("JNI_BRIDGE: Failed to create global ref for P2P class");
        return false;
    }

    newOnPeersUpdated = env->GetStaticMethodID(newP2pClass, "onPeersUpdated", "([Lcom/zeengal/litep2p/PeerInfo;)V");
    if (!newOnPeersUpdated) {
        nativeLog("JNI_BRIDGE: Failed to get onPeersUpdated method ID");
        safeDeleteGlobalRef(env, (jobject&)newP2pClass);
        return false;
    }

    // Optional engine state callbacks in P2P class (fallback)
    newOnEngineStartComplete = env->GetStaticMethodID(newP2pClass, "onEngineStartComplete", "()V");
    if (!newOnEngineStartComplete) {
        nativeLog("JNI_BRIDGE: onEngineStartComplete method not found in P2P class (this is OK)");
        if (env->ExceptionCheck()) env->ExceptionClear();
    }

    newOnEngineStopComplete = env->GetStaticMethodID(newP2pClass, "onEngineStopComplete", "()V");
    if (!newOnEngineStopComplete) {
        nativeLog("JNI_BRIDGE: onEngineStopComplete method not found in P2P class (this is OK)");
        if (env->ExceptionCheck()) env->ExceptionClear();
    }

    newOnMessageReceived = env->GetStaticMethodID(newP2pClass, "onMessageReceived", "(Ljava/lang/String;[B)V");
    if (!newOnMessageReceived) {
        nativeLog("JNI_BRIDGE: onMessageReceived method not found in P2P class");
        if (env->ExceptionCheck()) env->ExceptionClear();
    }

    // MainActivity class (optional)
    jclass localMainActivityClass = env->FindClass("com/zeengal/litep2p/MainActivity");
    if (localMainActivityClass) {
        newMainActivityClass = (jclass)env->NewGlobalRef(localMainActivityClass);
        env->DeleteLocalRef(localMainActivityClass);
        if (!newMainActivityClass) {
            nativeLog("JNI_BRIDGE: Failed to create global ref for MainActivity class");
        }
    } else {
        if (env->ExceptionCheck()) env->ExceptionClear();
    }

    // PeerInfo class (required)
    jclass localPeerInfoClass = env->FindClass("com/zeengal/litep2p/PeerInfo");
    if (!localPeerInfoClass) {
        nativeLog("JNI_BRIDGE: Failed to find PeerInfo class");
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        safeDeleteGlobalRef(env, (jobject&)newP2pClass);
        safeDeleteGlobalRef(env, (jobject&)newMainActivityClass);
        return false;
    }
    newPeerInfoClass = (jclass)env->NewGlobalRef(localPeerInfoClass);
    env->DeleteLocalRef(localPeerInfoClass);
    if (!newPeerInfoClass) {
        nativeLog("JNI_BRIDGE: Failed to create global ref for PeerInfo class");
        safeDeleteGlobalRef(env, (jobject&)newP2pClass);
        safeDeleteGlobalRef(env, (jobject&)newMainActivityClass);
        return false;
    }
    newPeerInfoCtor = env->GetMethodID(newPeerInfoClass, "<init>", "(Ljava/lang/String;Ljava/lang/String;IIZLjava/lang/String;)V");
    if (!newPeerInfoCtor) {
        nativeLog("JNI_BRIDGE: Failed to get PeerInfo constructor method ID");
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        safeDeleteGlobalRef(env, (jobject&)newP2pClass);
        safeDeleteGlobalRef(env, (jobject&)newMainActivityClass);
        safeDeleteGlobalRef(env, (jobject&)newPeerInfoClass);
        return false;
    }

    // Logger class (required)
    jclass localLoggerClass = env->FindClass("com/zeengal/litep2p/LiteP2PLogger");
    if (!localLoggerClass) {
        nativeLog("JNI_BRIDGE: Failed to find LiteP2PLogger class");
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        safeDeleteGlobalRef(env, (jobject&)newP2pClass);
        safeDeleteGlobalRef(env, (jobject&)newMainActivityClass);
        safeDeleteGlobalRef(env, (jobject&)newPeerInfoClass);
        return false;
    }
    newLoggerClass = (jclass)env->NewGlobalRef(localLoggerClass);
    env->DeleteLocalRef(localLoggerClass);
    if (!newLoggerClass) {
        nativeLog("JNI_BRIDGE: Failed to create global ref for LiteP2PLogger class");
        safeDeleteGlobalRef(env, (jobject&)newP2pClass);
        safeDeleteGlobalRef(env, (jobject&)newMainActivityClass);
        safeDeleteGlobalRef(env, (jobject&)newPeerInfoClass);
        return false;
    }
    newAddLogMethod = env->GetStaticMethodID(newLoggerClass, "addLog", "(Ljava/lang/String;)V");
    if (!newAddLogMethod) {
        nativeLog("JNI_BRIDGE: Failed to get addLog method ID");
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        safeDeleteGlobalRef(env, (jobject&)newP2pClass);
        safeDeleteGlobalRef(env, (jobject&)newMainActivityClass);
        safeDeleteGlobalRef(env, (jobject&)newPeerInfoClass);
        safeDeleteGlobalRef(env, (jobject&)newLoggerClass);
        return false;
    }

    // If we ever re-init (e.g., future code calls cleanup explicitly), drop existing refs first.
    safeDeleteGlobalRef(env, (jobject&)g_p2pClass);
    safeDeleteGlobalRef(env, (jobject&)g_mainActivityClass);
    safeDeleteGlobalRef(env, (jobject&)g_peerInfoClass);
    safeDeleteGlobalRef(env, (jobject&)g_loggerClass);

    g_p2pClass = newP2pClass;
    g_mainActivityClass = newMainActivityClass;
    g_peerInfoClass = newPeerInfoClass;
    g_loggerClass = newLoggerClass;

    g_onPeersUpdated = newOnPeersUpdated;
    g_onEngineStartComplete = newOnEngineStartComplete;
    g_onEngineStopComplete = newOnEngineStopComplete;
    g_onMessageReceived = newOnMessageReceived;
    g_peerInfoCtor = newPeerInfoCtor;
    g_addLogMethod = newAddLogMethod;

    g_jni_cache_initialized = true;
    nativeLog("JNI_BRIDGE: Initialization complete.");
    return true;
}

void jniBridgeCleanup(JNIEnv* env) {
    if (!env) {
        env = getJNIEnv();
    }

    std::lock_guard<std::mutex> lock(g_jni_cache_mutex);

    safeDeleteGlobalRef(env, (jobject&)g_p2pClass);
    safeDeleteGlobalRef(env, (jobject&)g_mainActivityClass);
    safeDeleteGlobalRef(env, (jobject&)g_peerInfoClass);
    safeDeleteGlobalRef(env, (jobject&)g_loggerClass);

    g_onPeersUpdated = nullptr;
    g_onEngineStartComplete = nullptr;
    g_onEngineStopComplete = nullptr;
    g_onMessageReceived = nullptr;
    g_peerInfoCtor = nullptr;
    g_addLogMethod = nullptr;

    g_jni_cache_initialized = false;
}

void sendPeersToUI(const std::vector<Peer>& peers) {
    nativeLog("JNI_BRIDGE: sendPeersToUI called with " + std::to_string(peers.size()) + " peers");
    
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
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        return;
    }

    for (size_t i = 0; i < peers.size(); ++i) {
        const Peer& p = peers[i];
        nativeLog("JNI_BRIDGE: Processing peer " + std::to_string(i) + " - ID: " + p.id + ", IP: " + p.ip + 
                  ", Port: " + std::to_string(p.port) + ", Network ID: " + p.network_id);
        
        jstring jid = env->NewStringUTF(p.id.c_str());
        if (!jid) {
            nativeLog("JNI_ERROR: Failed to create jstring for peer ID.");
            if (env->ExceptionCheck()) {
                env->ExceptionDescribe();
                env->ExceptionClear();
            }
            env->DeleteLocalRef(arr);
            return;
        }
        
        jstring jip = env->NewStringUTF(p.ip.c_str());
        if (!jip) {
            nativeLog("JNI_ERROR: Failed to create jstring for peer IP.");
            if (env->ExceptionCheck()) {
                env->ExceptionDescribe();
                env->ExceptionClear();
            }
            env->DeleteLocalRef(jid);
            env->DeleteLocalRef(arr);
            return;
        }
        
        jstring jnetworkId = env->NewStringUTF(p.network_id.c_str());
        if (!jnetworkId) {
            nativeLog("JNI_ERROR: Failed to create jstring for peer network ID.");
            if (env->ExceptionCheck()) {
                env->ExceptionDescribe();
                env->ExceptionClear();
            }
            env->DeleteLocalRef(jid);
            env->DeleteLocalRef(jip);
            env->DeleteLocalRef(arr);
            return;
        }
        
        // Check actual connection status from session manager
        nativeLog("JNI_BRIDGE: Calling g_sessionManager.isPeerConnected for peer: " + p.id);
        bool is_connected = g_sessionManager.isPeerConnected(p.id);
        nativeLog("JNI_BRIDGE: g_sessionManager.isPeerConnected returned " + std::to_string(is_connected) + " for peer: " + p.id);
        
        jobject obj = env->NewObject(g_peerInfoClass, g_peerInfoCtor, jid, jip, (jint)p.port, (jint)p.latency, (jboolean)is_connected, jnetworkId);
        if (!obj) {
            nativeLog("JNI_ERROR: Failed to create PeerInfo object for peer " + p.id);
            if (env->ExceptionCheck()) {
                env->ExceptionDescribe();
                env->ExceptionClear();
            }
            env->DeleteLocalRef(jid);
            env->DeleteLocalRef(jip);
            env->DeleteLocalRef(jnetworkId);
            env->DeleteLocalRef(arr);
            return;
        }
        
        env->SetObjectArrayElement(arr, (jsize)i, obj);
        if (env->ExceptionCheck()) {
            nativeLog("JNI_ERROR: Failed to set object array element for peer " + p.id);
            env->ExceptionDescribe();
            env->ExceptionClear();
            env->DeleteLocalRef(jid);
            env->DeleteLocalRef(jip);
            env->DeleteLocalRef(jnetworkId);
            env->DeleteLocalRef(obj);
            env->DeleteLocalRef(arr);
            return;
        }
        
        env->DeleteLocalRef(jid);
        env->DeleteLocalRef(jip);
        env->DeleteLocalRef(jnetworkId);
        env->DeleteLocalRef(obj);
    }

    nativeLog("JNI_BRIDGE: Calling onPeersUpdated on the UI thread.");
    env->CallStaticVoidMethod(g_p2pClass, g_onPeersUpdated, arr);
    
    // Check for exceptions after calling the Java method
    if (env->ExceptionCheck()) {
        nativeLog("JNI_ERROR: Exception occurred when calling onPeersUpdated.");
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
    
    env->DeleteLocalRef(arr);
    nativeLog("JNI_BRIDGE: sendPeersToUI finished");
}

void sendToLogUI(const std::string& message) {
    JNIEnv* env = getJNIEnv();
    if (!env || !g_loggerClass || !g_addLogMethod) return;
    jstring jmsg = env->NewStringUTF(message.c_str());
    env->CallStaticVoidMethod(g_loggerClass, g_addLogMethod, jmsg);
    env->DeleteLocalRef(jmsg);
}
