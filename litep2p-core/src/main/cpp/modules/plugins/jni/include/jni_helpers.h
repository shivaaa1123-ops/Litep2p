

#ifndef JNI_HELPERS_H
#define JNI_HELPERS_H
#include <jni.h>

extern JavaVM* g_vm;

// Library lifecycle hooks. Called by the single exported JNI_OnLoad/JNI_OnUnload.
void jni_helpers_on_load(JavaVM* vm);
void jni_helpers_on_unload(JavaVM* vm);
JNIEnv* getJNIEnv();
void detachJNIEnv();  // Call when done with JNIEnv to prevent resource leaks

#endif
