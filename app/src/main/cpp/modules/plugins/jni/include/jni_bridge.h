
#ifndef JNI_BRIDGE_H
#define JNI_BRIDGE_H

#include "peer.h"
#include <vector>
#include <jni.h>
#include <string>

/**
 * @file jni_bridge.h
 * @brief This file contains the declarations for the JNI bridge functions.
 */

/**
 * @brief Initializes the JNI bridge.
 * @param env The JNI environment.
 * @return True if initialization was successful, false otherwise.
 */
bool jniBridgeInit(JNIEnv* env);

/**
 * @brief Cleans up the JNI bridge.
 * @param env The JNI environment.
 */
void jniBridgeCleanup(JNIEnv* env);

/**
 * @brief Sends a list of peers to the UI.
 * @param peers The list of peers to send.
 */
void sendPeersToUI(const std::vector<Peer>& peers);

/**
 * @brief Sends a log message to the UI.
 * @param message The message to send.
 */
void sendToLogUI(const std::string& message);

#endif // JNI_BRIDGE_H
