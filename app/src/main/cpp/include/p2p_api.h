#ifndef P2P_API_H
#define P2P_API_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

// JNI API exposed to Java/Kotlin (class com.zeengal.litep2p.hook.P2P)
JNIEXPORT void JNICALL Java_com_zeengal_litep2p_hook_P2P_init(JNIEnv*, jobject);
JNIEXPORT void JNICALL Java_com_zeengal_litep2p_hook_P2P_startServer(JNIEnv*, jobject, jint);
JNIEXPORT void JNICALL Java_com_zeengal_litep2p_hook_P2P_connect(JNIEnv*, jobject, jstring, jint);
JNIEXPORT void JNICALL Java_com_zeengal_litep2p_hook_P2P_sendMessage(JNIEnv*, jobject, jstring, jbyteArray);
JNIEXPORT void JNICALL Java_com_zeengal_litep2p_hook_P2P_stop(JNIEnv*, jobject);

#ifdef __cplusplus
}
#endif

#endif // P2P_API_H