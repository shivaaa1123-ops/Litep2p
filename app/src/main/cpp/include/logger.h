#pragma once
#include <string>
#include <jni.h>

// Called by MainActivity to register itself as log receiver
void setLoggerTarget(JNIEnv* env, jobject activityObj);

// Called internally by native code to send a log to UI
void nativeLog(const std::string& msg);

// Init function to store VM pointer
void loggerSetJavaVM(JavaVM* vm);