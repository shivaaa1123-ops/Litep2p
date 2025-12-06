// jni_helpers.cpp
#include "jni_helpers.h"
#include <jni.h>
#include <android/log.h>

// DEFINE the global JVM pointer (exactly once!)
JavaVM* g_vm = nullptr;

// Get JNIEnv for current thread (attach if needed)
JNIEnv* getJNIEnv() {
    if (!g_vm) return nullptr;

    JNIEnv* env = nullptr;
    jint res = g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);

    if (res == JNI_EDETACHED) {
        JavaVMAttachArgs args;
        args.version = JNI_VERSION_1_6;
        args.name    = nullptr;
        args.group   = nullptr;

        if (g_vm->AttachCurrentThread(&env, &args) != JNI_OK) {
            __android_log_print(ANDROID_LOG_ERROR, "LiteP2P", "AttachCurrentThread failed");
            return nullptr;
        }
    }
    else if (res != JNI_OK) {
        return nullptr;
    }

    return env;
}