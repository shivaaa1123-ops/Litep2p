// jni_helpers.h
#ifndef JNI_HELPERS_H
#define JNI_HELPERS_H

#include <jni.h>

extern JavaVM* g_vm;

JNIEnv* getJNIEnv();

#endif