
#ifndef JNI_HELPERS_H
#define JNI_HELPERS_H

#include <jni.h>

/**
 * @file jni_helpers.h
 * @brief This file contains helper functions for working with JNI.
 */

/**
 * @brief Global JavaVM pointer.
 */
extern JavaVM* g_vm;

// Library lifecycle hooks. These are called by the single exported JNI_OnLoad/JNI_OnUnload
// implementation (see src/jni_bridge.cpp). They must NOT themselves be named JNI_OnLoad,
// otherwise the shared library will fail to link due to duplicate symbols.
void jni_helpers_on_load(JavaVM* vm);
void jni_helpers_on_unload(JavaVM* vm);

/**
 * @brief Gets the JNI environment for the current thread.
 * @return The JNI environment.
 */
JNIEnv* getJNIEnv();

/**
 * @brief Detaches the JNI environment from the current thread.
 */
void detachJNIEnv();

#endif
