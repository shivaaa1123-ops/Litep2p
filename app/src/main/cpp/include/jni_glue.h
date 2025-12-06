#ifndef JNI_GLUE_H
#define JNI_GLUE_H

#include <jni.h>
#include <vector>
#include "peer.h"

#ifdef __cplusplus
extern "C" {
#endif

// Initialize global JNI references for P2P Java-side class
// Returns true on success.
bool jniGlueInit(JNIEnv* env, jclass p2pClass);

// Cleanup global JNI refs (call from P2P.stop or library unload)
void jniGlueCleanup(JNIEnv* env);

// Convert native peers -> Java PeerInfo[] and call P2P.onPeersUpdated(...)
void sendPeersToUI(const std::vector<Peer>& peers);

#ifdef __cplusplus
}
#endif

#endif // JNI_GLUE_H