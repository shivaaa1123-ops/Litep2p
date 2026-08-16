
#ifndef JNI_BRIDGE_H
#define JNI_BRIDGE_H

#include <jni.h>
#include <string>
#include <cstdint>

/**
 * @file jni_bridge.h
 * @brief Android binding-layer hooks for the LiteP2P engine.
 *
 * Phase 3: the JNI entry points (Java_com_zeengal_litep2p_core_LiteP2PNative_*)
 * are thin wrappers over the public C ABI (litep2p.h). The engine no longer has
 * any direct knowledge of the binding; it only emits events through the small
 * set of hooks declared here, which the binding implements by forwarding into
 * com.zeengal.litep2p.core.NativeEvents.
 *
 * These hooks are compiled into the Android build only (HAVE_JNI / __ANDROID__).
 * Desktop builds provide no-op definitions so the engine links unchanged.
 */

/**
 * @brief Initializes the JNI bridge (caches class/method references).
 * @param env The JNI environment.
 * @return True if initialization was successful, false otherwise.
 */
bool jniBridgeInit(JNIEnv* env);

/**
 * @brief Cleans up the JNI bridge (releases cached global references).
 * @param env The JNI environment.
 */
void jniBridgeCleanup(JNIEnv* env);

/**
 * @brief Forwards an engine log line to the UI (Logs tab).
 * @param message The sanitized log message.
 */
void sendToLogUI(const std::string& message);

/**
 * @brief Forwards an engine log line with its level to the UI (Logs tab).
 * @param level Log level: 0=DEBUG 1=INFO 2=WARN 3=ERROR (matches LogLevel / on_log).
 * @param message The sanitized log message.
 */
void sendToLogUI(int level, const std::string& message);

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

#endif // JNI_BRIDGE_H
