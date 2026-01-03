

#include "jni_helpers.h"
#include "jni_bridge.h"
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

void jni_helpers_on_load(JavaVM* vm) {
    g_vm = vm;
}

void jni_helpers_on_unload(JavaVM* vm) {
    // Cleanup JNI global refs owned by the JNI bridge while the VM is still available.
    if (vm) {
        JNIEnv* env = nullptr;
        if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) == JNI_OK && env) {
            jniBridgeCleanup(env);
        }
    }
    g_vm = nullptr;
}
