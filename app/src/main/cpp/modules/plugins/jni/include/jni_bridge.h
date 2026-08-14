
#ifndef JNI_BRIDGE_H
#define JNI_BRIDGE_H

#include "peer.h"
#include <vector>
#include <jni.h>
#include <string>
#include <cstdint>

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

/**
 * @brief Sends a telemetry JSON snapshot to the UI (Telemetry tab).
 * @param telemetry_json The JSON payload (no "TELEMETRY" prefix).
 */
void sendTelemetryToUI(const std::string& telemetry_json);

/**
 * @brief Notifies the Android UI that an application-level ACK was received.
 * @param msg_id The message id being acknowledged.
 * @param sent_ts_ms Sender-provided send timestamp (epoch ms), if present (else 0).
 * @param recv_ts_ms Receiver-provided receive timestamp (epoch ms), if present (else 0).
 */
void sendMessageAckToUI(const std::string& msg_id, int64_t sent_ts_ms, int64_t recv_ts_ms);

/**
 * @brief Sets the log level.
 * @param level The log level to set.
 */
void setLogLevel(int level);

#endif // JNI_BRIDGE_H
