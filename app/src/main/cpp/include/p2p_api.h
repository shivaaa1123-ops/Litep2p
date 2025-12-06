#ifndef P2P_API_H
#define P2P_API_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

// JNI API exposed to Java/Kotlin (class com.zeengal.litep2p.hook.P2P)
JNIEXPORT void JNICALL Java_com_zeengal_litep2p_hook_P2P_init(JNIEnv*, jclass);
JNIEXPORT void JNICALL Java_com_zeengal_litep2p_hook_P2P_startServer(JNIEnv*, jclass, jint);
JNIEXPORT void JNICALL Java_com_zeengal_litep2p_hook_P2P_connect(JNIEnv*, jclass, jstring, jint);
JNIEXPORT void JNICALL Java_com_zeengal_litep2p_hook_P2P_sendMessage(JNIEnv*, jclass, jstring, jbyteArray);
JNIEXPORT void JNICALL Java_com_zeengal_litep2p_hook_P2P_stop(JNIEnv*, jclass);

#ifdef __cplusplus
}
#endif

#endif // P2P_API_H