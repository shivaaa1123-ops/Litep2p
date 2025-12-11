#ifndef FILE_TRANSFER_MANAGER_H
#define FILE_TRANSFER_MANAGER_H

#include "transfer_types.h"
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <memory>
#include <functional>
#include <cstdint>
#include <chrono>
#include <deque>
#include <mutex>
#include <thread>
#include <atomic>

/**
 * FILE TRANSFER MODULE
 * 
 * Features:
 * - 32KB chunking for efficient transfer
 * - Resume capability with checkpoint tracking
 * - Multi-path routing for optimal network path selection
 * - Multiplexing for concurrent transfers
 * - Robust congestion handling with adaptive rate limiting
 * - CRC32 validation per chunk
 * - Priority queuing for transfers
 */

// ============================================================================
// ENUMS AND CONSTANTS (Shared via transfer_types.h)
// ============================================================================

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * Chunk metadata for transfer
 */
struct TransferChunk {
    uint32_t chunk_id;              // Sequence number of chunk
    uint32_t offset;                // Byte offset in file
    uint32_t size;                  // Actual chunk size (may be < CHUNK_SIZE for last chunk)
    uint32_t crc32;                 // CRC32 checksum
    std::vector<uint8_t> data;      // Chunk data
    std::chrono::steady_clock::time_point sent_time;     // When chunk was sent
    bool is_acked = false;          // Whether chunk was acknowledged
    int retry_count = 0;            // Number of retries
};

/**
 * Transfer session metadata
 */
struct TransferSession {
    std::string transfer_id;        // Unique transfer ID (UUID)
    std::string file_path;          // Full path to file
    std::string file_name;          // Just the filename
    uint64_t file_size;             // Total file size in bytes
    uint64_t bytes_transferred;     // Bytes successfully transferred
    uint32_t total_chunks;          // Total number of chunks
    uint32_t chunks_transferred;    // Chunks successfully transferred
    
    TransferDirection direction;    // SEND or RECEIVE
    TransferState state;            // Current transfer state
    TransferPriority priority;      // Transfer priority
    
    std::string peer_id;            // Target/source peer ID
    std::string peer_ip;            // Target/source peer IP
    int peer_port;                  // Target/source peer port
    
    std::chrono::steady_clock::time_point start_time;    // When transfer started
    std::chrono::steady_clock::time_point last_activity; // Last chunk sent/received
    
    float progress_percent = 0.0f;  // 0-100% progress
    float avg_speed_kbps = 0.0f;    // Average transfer speed in Kbps
    
    // Resume capability
    std::vector<uint32_t> completed_chunks;              // Bitmask of completed chunks
    std::string checkpoint_file;    // Path to checkpoint metadata
    
    // Multiplexing
    std::vector<std::string> active_paths;               // Currently active paths/peer connections
    std::map<std::string, uint64_t> path_bytes_transferred;  // Bytes per path
    
    // Error tracking
    int error_count = 0;
    std::string last_error;
};

/**
 * Checkpoint data for resume capability
 */
struct TransferCheckpoint {
    std::string transfer_id;
    uint64_t bytes_transferred;
    uint32_t chunks_transferred;
    std::vector<uint32_t> completed_chunks;
    std::chrono::steady_clock::time_point checkpoint_time;
};

/**
 * Network path metadata for routing
 */
struct NetworkPath {
    std::string path_id;            // Unique path identifier
    std::string next_hop_peer_id;   // Next peer on path
    std::string next_hop_ip;        // Next peer IP
    int next_hop_port;              // Next peer port
    
    int hop_count;                  // Number of hops to destination
    int latency_ms;                 // Estimated latency
    int bandwidth_kbps;             // Estimated available bandwidth
    float path_quality_score;       // 0-100 score (higher is better)
    
    int consecutive_failures = 0;   // Failure tracking
    std::chrono::steady_clock::time_point last_used;
    bool is_available = true;
};

// ============================================================================
// CALLBACKS AND TYPEDEFS
// ============================================================================

using TransferProgressCallback = std::function<void(const std::string& transfer_id, float progress_percent, float speed_kbps)>;
using TransferCompleteCallback = std::function<void(const std::string& transfer_id, bool success, const std::string& error)>;
using PathSelectedCallback = std::function<void(const std::string& transfer_id, const std::string& path_id, int latency_ms)>;
using CongestionChangedCallback = std::function<void(CongestionLevel level, const CongestionMetrics& metrics)>;

// ============================================================================
// FILE TRANSFER MANAGER
// ============================================================================

class FileTransferManager {
public:
    /**
     * Constructor
     * @param max_concurrent_transfers Maximum concurrent transfers
     * @param chunk_size_kb Size of each chunk in KB (default 32)
     */
    explicit FileTransferManager(uint32_t max_concurrent_transfers = MAX_CONCURRENT_TRANSFERS,
                                 uint32_t chunk_size_kb = CHUNK_SIZE / 1024);
    
    ~FileTransferManager();
    
    // ==================== TRANSFER INITIATION ====================
    
    /**
     * Start sending a file to a peer
     * @param file_path Full path to file to send
     * @param peer_id Target peer ID
     * @param peer_ip Target peer IP
     * @param peer_port Target peer port
     * @param priority Transfer priority
     * @param strategy Path selection strategy
     * @return Transfer ID on success, empty string on failure
     */
    std::string send_file(const std::string& file_path,
                          const std::string& peer_id,
                          const std::string& peer_ip,
                          int peer_port,
                          TransferPriority priority = TransferPriority::NORMAL,
                          PathSelectionStrategy strategy = PathSelectionStrategy::BALANCED);
    
    /**
     * Receive a file from a peer
     * @param transfer_id Transfer ID from sender
     * @param file_path Where to save received file
     * @param peer_id Source peer ID
     * @param peer_ip Source peer IP
     * @param peer_port Source peer port
     * @param expected_file_size Expected file size (for pre-allocation)
     * @return true on success
     */
    bool receive_file(const std::string& transfer_id,
                      const std::string& file_path,
                      const std::string& peer_id,
                      const std::string& peer_ip,
                      int peer_port,
                      uint64_t expected_file_size);
    
    // ==================== TRANSFER CONTROL ====================
    
    /**
     * Pause an active transfer
     * @param transfer_id Transfer to pause
     * @return true on success
     */
    bool pause_transfer(const std::string& transfer_id);
    
    /**
     * Resume a paused transfer
     * @param transfer_id Transfer to resume
     * @return true on success
     */
    bool resume_transfer(const std::string& transfer_id);
    
    /**
     * Cancel a transfer
     * @param transfer_id Transfer to cancel
     * @return true on success
     */
    bool cancel_transfer(const std::string& transfer_id);
    
    /**
     * Check if a transfer can be resumed (checkpoint exists)
     * @param file_path File to check
     * @return true if resume possible
     */
    bool can_resume_transfer(const std::string& file_path);
    
    // ==================== TRANSFER STATUS ====================
    
    /**
     * Get status of a transfer
     * @param transfer_id Transfer ID
     * @return Transfer session if found, nullptr otherwise
     */
    std::shared_ptr<TransferSession> get_transfer_status(const std::string& transfer_id);
    
    /**
     * Get all active transfers
     * @return Vector of transfer IDs
     */
    std::vector<std::string> get_active_transfers();
    
    /**
     * Get transfer progress
     * @param transfer_id Transfer ID
     * @return Progress as percentage (0-100), -1 if not found
     */
    float get_transfer_progress(const std::string& transfer_id);
    
    /**
     * Get transfer speed
     * @param transfer_id Transfer ID
     * @return Speed in Kbps, 0 if not found or not active
     */
    float get_transfer_speed(const std::string& transfer_id);
    
    // ==================== PATH MANAGEMENT ====================
    
    /**
     * Register an available network path to a peer
     * @param peer_id Target peer
     * @param next_hop_peer_id Next hop peer
     * @param next_hop_ip Next hop IP
     * @param next_hop_port Next hop port
     * @param latency_ms Estimated latency
     * @param bandwidth_kbps Estimated available bandwidth
     * @return Path ID
     */
    std::string register_network_path(const std::string& peer_id,
                                      const std::string& next_hop_peer_id,
                                      const std::string& next_hop_ip,
                                      int next_hop_port,
                                      int latency_ms,
                                      int bandwidth_kbps);
    
    /**
     * Find optimal path to peer using selected strategy
     * @param peer_id Target peer
     * @param strategy Path selection strategy
     * @return Best path, nullptr if no available paths
     */
    std::shared_ptr<NetworkPath> find_optimal_path(const std::string& peer_id,
                                                    PathSelectionStrategy strategy = PathSelectionStrategy::BALANCED);
    
    /**
     * Update path metrics (called periodically or on network events)
     * @param path_id Path to update
     * @param latency_ms New latency
     * @param bandwidth_kbps New bandwidth
     */
    void update_path_metrics(const std::string& path_id,
                             int latency_ms,
                             int bandwidth_kbps);
    
    /**
     * Mark path as failed
     * @param path_id Path that failed
     */
    void mark_path_failed(const std::string& path_id);
    
    // ==================== MULTIPLEXING ====================
    
    /**
     * Get active paths for a transfer (for multiplexing)
     * @param transfer_id Transfer ID
     * @return Vector of active path IDs
     */
    std::vector<std::string> get_transfer_paths(const std::string& transfer_id);
    
    /**
     * Add path to active transfer (for load balancing)
     * @param transfer_id Transfer ID
     * @param path_id Path to add
     * @return true on success
     */
    bool add_path_to_transfer(const std::string& transfer_id,
                              const std::string& path_id);
    
    /**
     * Remove path from active transfer
     * @param transfer_id Transfer ID
     * @param path_id Path to remove
     * @return true on success
     */
    bool remove_path_from_transfer(const std::string& transfer_id,
                                   const std::string& path_id);
    
    // ==================== CONGESTION HANDLING ====================
    
    /**
     * Report congestion on a path
     * @param path_id Path experiencing congestion
     * @param metrics Congestion metrics
     */
    void report_congestion(const std::string& path_id,
                           const CongestionMetrics& metrics);
    
    /**
     * Get current congestion level
     * @return Current congestion metrics
     */
    CongestionMetrics get_congestion_metrics();
    
    /**
     * Get adaptive rate limit (based on congestion)
     * @return Rate limit in Kbps
     */
    uint32_t get_adaptive_rate_limit();
    
    /**
     * Manually set rate limit (for testing)
     * @param rate_kbps Rate in Kbps
     */
    void set_rate_limit(uint32_t rate_kbps);
    
    // ==================== CHUNK HANDLING ====================
    
    /**
     * Handle incoming chunk from peer
     * @param transfer_id Transfer ID
     * @param chunk Chunk data
     * @return true if valid and accepted
     */
    bool handle_incoming_chunk(const std::string& transfer_id,
                               const TransferChunk& chunk);
    
    /**
     * Get next chunk to send for a transfer
     * @param transfer_id Transfer ID
     * @return Chunk to send, nullptr if none available
     */
    std::shared_ptr<TransferChunk> get_next_chunk_to_send(const std::string& transfer_id);
    
    /**
     * Mark chunk as acknowledged
     * @param transfer_id Transfer ID
     * @param chunk_id Chunk ID that was acked
     */
    void acknowledge_chunk(const std::string& transfer_id,
                          uint32_t chunk_id);
    
    /**
     * Get chunks needing retransmission
     * @param transfer_id Transfer ID
     * @return Vector of chunk IDs to retransmit
     */
    std::vector<uint32_t> get_chunks_to_retransmit(const std::string& transfer_id);
    
    // ==================== CHECKPOINT/RESUME ====================
    
    /**
     * Save checkpoint for a transfer
     * @param transfer_id Transfer ID
     * @return true on success
     */
    bool save_checkpoint(const std::string& transfer_id);
    
    /**
     * Load checkpoint to resume transfer
     * @param file_path File being transferred
     * @return Checkpoint data if found, nullptr otherwise
     */
    std::shared_ptr<TransferCheckpoint> load_checkpoint(const std::string& file_path);
    
    /**
     * Clear checkpoint (after successful transfer or cancel)
     * @param file_path File to clear checkpoint for
     */
    void clear_checkpoint(const std::string& file_path);
    
    // ==================== CALLBACKS ====================
    
    /**
     * Register progress callback
     */
    void on_transfer_progress(TransferProgressCallback callback) {
        m_progress_callback = callback;
    }
    
    /**
     * Register completion callback
     */
    void on_transfer_complete(TransferCompleteCallback callback) {
        m_complete_callback = callback;
    }
    
    /**
     * Register path selection callback
     */
    void on_path_selected(PathSelectedCallback callback) {
        m_path_selected_callback = callback;
    }
    
    /**
     * Register congestion change callback
     */
    void on_congestion_changed(CongestionChangedCallback callback) {
        m_congestion_callback = callback;
    }
    
    // ==================== STATISTICS ====================
    
    /**
     * Get transfer statistics
     * @return Map of stat names to values
     */
    std::map<std::string, double> get_statistics();
    
    /**
     * Reset statistics
     */
    void reset_statistics();

private:
    // ==================== INTERNAL STATE ====================
    
    uint32_t m_max_concurrent_transfers;
    uint32_t m_chunk_size;
    std::atomic<uint32_t> m_current_rate_limit_kbps{INITIAL_RATE_LIMIT_KBPS};
    CongestionLevel m_current_congestion_level{CongestionLevel::LOW};
    
    // Transfer sessions
    std::unordered_map<std::string, std::shared_ptr<TransferSession>> m_transfers;
    std::mutex m_transfers_mutex;
    
    // Network paths
    std::unordered_map<std::string, std::vector<std::shared_ptr<NetworkPath>>> m_peer_paths;
    std::unordered_map<std::string, std::shared_ptr<NetworkPath>> m_path_map;
    std::mutex m_paths_mutex;
    
    // Pending chunks (per transfer)
    std::unordered_map<std::string, std::deque<std::shared_ptr<TransferChunk>>> m_pending_chunks;
    std::mutex m_chunks_mutex;
    
    // Congestion history
    std::deque<CongestionMetrics> m_congestion_history;
    std::mutex m_congestion_mutex;
    
    // Statistics
    struct Stats {
        uint64_t total_bytes_transferred = 0;
        uint64_t total_files_transferred = 0;
        uint32_t total_transfers = 0;
        uint32_t successful_transfers = 0;
        uint32_t failed_transfers = 0;
        std::chrono::steady_clock::time_point start_time = std::chrono::steady_clock::now();
    };
    Stats m_stats;
    std::mutex m_stats_mutex;
    
    // Callbacks
    TransferProgressCallback m_progress_callback;
    TransferCompleteCallback m_complete_callback;
    PathSelectedCallback m_path_selected_callback;
    CongestionChangedCallback m_congestion_callback;
    
    // Background threads
    std::thread m_path_monitor_thread;
    std::thread m_congestion_monitor_thread;
    std::atomic<bool> m_running{true};
    
    // ==================== INTERNAL METHODS ====================
    
    /**
     * Path monitoring thread
     */
    void path_monitor_loop();
    
    /**
     * Congestion monitoring thread
     */
    void congestion_monitor_loop();
    
    /**
     * Load file into chunks
     */
    std::vector<std::shared_ptr<TransferChunk>> load_file_chunks(const std::string& file_path);
    
    /**
     * Calculate CRC32 checksum
     */
    uint32_t calculate_crc32(const std::vector<uint8_t>& data);
    
    /**
     * Score a network path for selection
     */
    float score_path(const std::shared_ptr<NetworkPath>& path,
                     PathSelectionStrategy strategy);
    
    /**
     * Adjust rate limit based on congestion
     */
    void adjust_rate_limit(CongestionLevel level);
    
    /**
     * Estimate congestion from metrics
     */
    CongestionLevel estimate_congestion();
};

#endif // FILE_TRANSFER_MANAGER_H
