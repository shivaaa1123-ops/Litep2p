#include "logger.h"
#include "jni_bridge.h"
#include <mutex>
#include <random>
#include <algorithm>
#include <string>
#include <android/log.h> // --- Include the Android logging library ---

static std::string g_sessionId = "NO_SESSION";
static std::mutex g_logMutex;

std::string generate_session_id(size_t len) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    std::string tmp_s;
    tmp_s.reserve(len);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, sizeof(alphanum) - 2);

    for (size_t i = 0; i < len; ++i) {
        tmp_s += alphanum[distrib(gen)];
    }

    return tmp_s;
}

void setSessionId(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    g_sessionId = session_id;
}

void nativeLog(const std::string& message) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    std::string log_message = "[" + g_sessionId + "] " + message;
    
    // --- THIS IS THE FIX ---
    // 1. Send the log to Logcat.
    __android_log_print(ANDROID_LOG_INFO, "LiteP2P_Native", "%s", log_message.c_str());

    // 2. Also, send the log to the UI.
    sendToLogUI(log_message);
}
