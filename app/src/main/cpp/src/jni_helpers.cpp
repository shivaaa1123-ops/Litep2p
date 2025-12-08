

#include "jni_helpers.h"
#include <android/log.h>
#include <thread>

JavaVM* g_vm = nullptr;

// Thread-local flag to track if thread was attached by us
static thread_local bool g_attached_by_get_env = false;

JNIEnv* getJNIEnv() {
    if (!g_vm) return nullptr;
    JNIEnv* env = nullptr;
    jint res = g_vm->GetEnv((void**)&env, JNI_VERSION_1_6);
    if (res == JNI_EDETACHED) {
        if (g_vm->AttachCurrentThread(&env, nullptr) != JNI_OK) return nullptr;
        g_attached_by_get_env = true;  // Mark that we attached this thread
    }
    return env;
}

// Call this when done with a JNIEnv obtained from getJNIEnv()
void detachJNIEnv() {
    if (g_vm && g_attached_by_get_env) {
        g_vm->DetachCurrentThread();
        g_attached_by_get_env = false;
    }
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    g_vm = vm;
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT void JNICALL JNI_OnUnload(JavaVM* vm, void*) {
    // Cleanup if needed
    g_vm = nullptr;
}
