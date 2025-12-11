
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
