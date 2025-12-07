
#ifndef JNI_GLUE_H
#define JNI_GLUE_H

#include "peer.h"
#include <vector>
#include <jni.h>

// Functions to initialize and clean up the cached JNI references
bool jniGlueInit(JNIEnv* env);
void jniGlueCleanup(JNIEnv* env);

void sendPeersToUI(const std::vector<Peer>& peers);

#endif // JNI_GLUE_H
