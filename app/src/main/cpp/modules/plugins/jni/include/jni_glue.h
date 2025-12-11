
#ifndef JNI_GLUE_H
#define JNI_GLUE_H

#include "peer.h"
#include <vector>

#ifdef HAVE_JNI
#include <jni.h>
#else
typedef void JNIEnv;
#endif

/**
 * @file jni_glue.h
 * @brief This file contains the JNI glue code for the P2P library.
 */

/**
 * @brief Initializes the JNI glue.
 * @param env The JNI environment.
 * @return True if initialization was successful, false otherwise.
 */
bool jniGlueInit(JNIEnv* env);

/**
 * @brief Cleans up the JNI glue.
 * @param env The JNI environment.
 */
void jniGlueCleanup(JNIEnv* env);

/**
 * @brief Sends a list of peers to the UI.
 * @param peers The list of peers to send.
 */
void sendPeersToUI(const std::vector<Peer>& peers);

#endif // JNI_GLUE_H
