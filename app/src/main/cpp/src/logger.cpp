#include "logger.h"
#include <mutex>
#include <android/log.h>

static JavaVM* g_vm = nullptr;
static jobject g_loggerTarget = nullptr;     // Global ref to MainActivity
static jmethodID g_onNativeLog = nullptr;    // MainActivity.onNativeLog(String)
static std::mutex g_mutex;

void loggerSetJavaVM(JavaVM* vm) {
    g_vm = vm;
}

void setLoggerTarget(JNIEnv* env, jobject activityObj) {
    std::lock_guard<std::mutex> lock(g_mutex);

    if (!g_vm) return;

    // Remove previous instance if exists
    if (g_loggerTarget) {
        env->DeleteGlobalRef(g_loggerTarget);
        g_loggerTarget = nullptr;
    }

    // Store new global ref
    g_loggerTarget = env->NewGlobalRef(activityObj);

    // Lookup onNativeLog(String)
    jclass cls = env->GetObjectClass(activityObj);
    g_onNativeLog = env->GetMethodID(cls, "onNativeLog", "(Ljava/lang/String;)V");

    if (!g_onNativeLog) {
        // If missing, log into Logcat but avoid recursion
        __android_log_print(ANDROID_LOG_ERROR, "LiteP2P",
                            "ERROR: MainActivity.onNativeLog(String) not found");
    }
}

void nativeLog(const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_mutex);

    if (!g_vm || !g_loggerTarget || !g_onNativeLog)
        return; // No logger registered yet

    JNIEnv* env = nullptr;
    jint res = g_vm->GetEnv((void**)&env, JNI_VERSION_1_6);

    if (res == JNI_EDETACHED) {
        if (g_vm->AttachCurrentThread(&env, nullptr) != JNI_OK)
            return;
    }

    jstring jmsg = env->NewStringUTF(msg.c_str());
    env->CallVoidMethod(g_loggerTarget, g_onNativeLog, jmsg);
    env->DeleteLocalRef(jmsg);
}