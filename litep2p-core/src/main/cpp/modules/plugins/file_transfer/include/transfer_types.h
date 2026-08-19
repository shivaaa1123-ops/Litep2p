#ifndef TRANSFER_TYPES_H
#define TRANSFER_TYPES_H

#include <cstdint>
#include <chrono>

/**
 * TRANSFER TYPES AND COMMON DEFINITIONS
 * 
 * Shared enums and structures used by both FileTransferManager and SessionManager
 * to avoid circular dependencies.
 */

// ============================================================================
// ENUMS - Transfer Control
// ============================================================================

enum class TransferState {
    PENDING,        // Waiting to start
    IN_PROGRESS,    // Currently transferring
    PAUSED,         // Paused by user or error
    COMPLETED,      // Successfully completed
    FAILED,         // Transfer failed
    CANCELLED       // Cancelled by user
};

enum class TransferDirection {
    SEND,           // Outgoing transfer
    RECEIVE         // Incoming transfer
};

enum class TransferPriority {
    LOW,            // Background transfers
    NORMAL,         // Standard priority
    HIGH            // Priority transfers
};

enum class PathSelectionStrategy {
    LATENCY,        // Prefer lowest latency path
    THROUGHPUT,     // Prefer highest throughput path
    BALANCED,       // Balance latency and throughput
    COST            // Prefer lowest cost path
};

enum class CongestionLevel {
    LOW,            // Network is clear
    MODERATE,       // Some congestion detected
    HIGH,           // Significant congestion
    SEVERE          // Network is overloaded
};

// ============================================================================
// FILE-TRANSFER WIRE CONTROL TYPES
// ============================================================================
// Subtypes carried inside MessageType::FILE_TRANSFER payloads. The data plane
// uses CHUNK (1) and ACK (2); the control plane (offer/accept protocol) uses
// the remaining values. All integers on the wire are little-endian; strings
// are length-prefixed with a single byte.
enum class FtControlType : uint8_t {
    CHUNK   = 1,
    ACK     = 2,
    OFFER   = 3,
    ACCEPT  = 4,
    DECLINE = 5,
    CANCEL  = 6,
    PAUSE   = 7,
    RESUME  = 8,
};

// ============================================================================
// CONSTANTS
// ============================================================================

constexpr uint32_t CHUNK_SIZE = 32 * 1024;              // 32KB chunks
constexpr uint32_t MAX_CONCURRENT_TRANSFERS = 100;      // Max transfers at once
constexpr uint32_t MAX_CHUNKS_IN_FLIGHT = 16;           // Sliding window for chunks
constexpr uint32_t INITIAL_RATE_LIMIT_KBPS = 8192;      // 8 Mbps initial (tunable via TransferConfig)
constexpr uint32_t MIN_RATE_LIMIT_KBPS = 64;            // 64 Kbps minimum
constexpr uint32_t MAX_RATE_LIMIT_KBPS = 100000;        // 100 Mbps maximum
constexpr uint32_t CHECKPOINT_INTERVAL = 10;            // Save checkpoint every 10 chunks
constexpr uint32_t PATH_EVAL_INTERVAL_SEC = 5;          // Evaluate paths every 5 seconds
constexpr uint32_t CONGESTION_CHECK_INTERVAL_MS = 100;  // Check congestion every 100ms

// ---------------------------------------------------------------------------
// RELIABILITY / RUGGEDNESS CONSTANTS
// ---------------------------------------------------------------------------
// A lost chunk is retransmitted after a short base delay, growing slightly with
// each attempt, so transient loss recovers in ~1s rather than stalling the whole
// sliding window for 5s. A transfer with no chunk/ack progress for longer than
// the stall timeout is declared FAILED (and surfaced to callers) instead of
// retransmitting a permanently-doomed chunk forever.
constexpr uint32_t CHUNK_RETRANSMIT_BASE_MS = 1000;     // first retransmit delay for a lost chunk
constexpr uint32_t CHUNK_RETRANSMIT_BACKOFF_MS = 300;   // extra delay per prior retry (adaptive)
constexpr uint32_t TRANSFER_STALL_TIMEOUT_MS = 15000;   // no-progress threshold that fails a transfer

// ============================================================================
// STRUCTURES - Congestion Metrics
// ============================================================================

/**
 * Congestion metrics for network monitoring
 */
struct CongestionMetrics {
    CongestionLevel level;
    float packet_loss_percent = 0.0f;
    float rtt_ms = 0.0f;
    float bandwidth_utilization_percent = 0.0f;
    uint32_t queue_depth = 0;
    std::chrono::steady_clock::time_point timestamp;
};

#endif // TRANSFER_TYPES_H
