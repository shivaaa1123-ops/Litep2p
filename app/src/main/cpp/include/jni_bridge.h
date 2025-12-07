
#ifndef JNI_BRIDGE_H
#define JNI_BRIDGE_H

#include "peer.h"
#include <vector>
#include <jni.h>
#include <string>

// Functions to initialize and clean up the cached JNI references
bool jniBridgeInit(JNIEnv* env);
void jniBridgeCleanup(JNIEnv* env);

void sendPeersToUI(const std::vector<Peer>& peers);

// New function to send logs to the UI
void sendToLogUI(const std::string& message);

#endif // JNI_BRIDGE_H
