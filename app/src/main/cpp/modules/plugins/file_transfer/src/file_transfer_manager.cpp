// =============================================================================
//  FileTransferManager implementation
// =============================================================================
// This file implements the high‑level file transfer manager used by Litep2p.
// It provides functionality for sending/receiving files over multiple network
// paths, checkpoint‑based resume, congestion‑aware rate limiting, and progress
// callbacks.  The implementation is deliberately lightweight to run on low‑
// power, battery‑operated devices.

#include "file_transfer_manager.h"
#include "logger.h"
// Standard library includes – kept minimal to reduce binary size and I/O.
#include <fstream>
#include <cstring>
#include <algorithm>
#include <random>
#include <iomanip>
#include <sstream>
#include <cstdio>

namespace {
static void append_u32_le(std::string& out, uint32_t v) {
    out.push_back(static_cast<char>(v & 0xFF));
    out.push_back(static_cast<char>((v >> 8) & 0xFF));
    out.push_back(static_cast<char>((v >> 16) & 0xFF));
    out.push_back(static_cast<char>((v >> 24) & 0xFF));
}

static std::string encode_chunk_payload(const std::string& transfer_id, const TransferChunk& chunk) {
    // Payload format (little-endian integers):
    // [type=1][id_len][id bytes][chunk_id][offset][size][crc32][data]
    std::string out;
    out.reserve(1 + 1 + transfer_id.size() + 16 + chunk.data.size());
    out.push_back(static_cast<char>(1));
    out.push_back(static_cast<char>(static_cast<uint8_t>(transfer_id.size())));
    out.append(transfer_id);
    append_u32_le(out, chunk.chunk_id);
    append_u32_le(out, chunk.offset);
    append_u32_le(out, chunk.size);
    append_u32_le(out, chunk.crc32);
    if (!chunk.data.empty()) {
        out.append(reinterpret_cast<const char*>(chunk.data.data()), chunk.data.size());
    }
    return out;
}
}

// ============================================================================
// CRC32 CALCULATION
// ============================================================================
// Pre‑computed lookup table for fast CRC32 checksum of each chunk.  The table is
// initialised once in the constructor via `init_crc32_table()`.

// Precomputed CRC32 lookup table
static uint32_t crc32_table[256];

void init_crc32_table() {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320UL;
            } else {
                crc >>= 1;
            }
        }
        crc32_table[i] = crc;
    }
}

uint32_t FileTransferManager::calculate_crc32(const std::vector<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFFUL;
    for (uint8_t byte : data) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ byte) & 0xFF];
    }
    return crc ^ 0xFFFFFFFFUL;
}

// ============================================================================
// UUID GENERATION
// ============================================================================
// Generates a random 36‑character UUID (hex digits with hyphens) used as a
// unique transfer identifier.  The function is deterministic per process and
// does not require external libraries, keeping the footprint small.

std::string generate_transfer_id() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    
    static const char* hex_chars = "0123456789abcdef";
    std::string uuid;
    uuid.reserve(36);
    
    for (int i = 0; i < 8; i++) uuid += hex_chars[dis(gen)];
    uuid += '-';
    for (int i = 0; i < 4; i++) uuid += hex_chars[dis(gen)];
    uuid += '-';
    for (int i = 0; i < 4; i++) uuid += hex_chars[dis(gen)];
    uuid += '-';
    for (int i = 0; i < 4; i++) uuid += hex_chars[dis(gen)];
    uuid += '-';
    for (int i = 0; i < 12; i++) uuid += hex_chars[dis(gen)];
    
    return uuid;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================
// The manager is constructed with a `TransferConfig` that allows tuning of
// concurrency, chunk size, monitoring intervals and initial rate limit.  The
// constructor starts two background threads for path monitoring and congestion
// monitoring.  The destructor calls `stop()` to ensure a clean shutdown.

FileTransferManager::FileTransferManager(const TransferConfig& cfg)
        : m_max_concurrent_transfers(cfg.max_concurrent_transfers),
            m_chunk_size(cfg.chunk_size_kb * 1024),
            m_current_rate_limit_kbps(cfg.initial_rate_limit_kbps),
            m_path_eval_interval_sec(cfg.path_eval_interval_sec),
            m_congestion_check_interval_ms(cfg.congestion_check_interval_ms) {

        init_crc32_table();

        LOG_INFO("FT: FileTransferManager initialized with max " +
                 std::to_string(cfg.max_concurrent_transfers) + " concurrent transfers");
        LOG_INFO("FT: Chunk size: " + std::to_string(cfg.chunk_size_kb) + "KB");

        // Start background threads
        m_path_monitor_thread = std::thread(&FileTransferManager::path_monitor_loop, this);
        m_congestion_monitor_thread = std::thread(&FileTransferManager::congestion_monitor_loop, this);
        m_send_worker_thread = std::thread(&FileTransferManager::send_worker_loop, this);
}

FileTransferManager::~FileTransferManager() {
    // Ensure background threads are stopped before destruction.
    stop();
    LOG_INFO("FT: FileTransferManager shutdown complete");
}

void FileTransferManager::stop() {
    // Signal threads to exit and wait for them.  The condition variable wakes
    // any thread that is sleeping on the configurable interval.
    m_running = false;
    m_shutdown_cv.notify_all();
    m_send_cv.notify_all();
    if (m_path_monitor_thread.joinable()) {
        m_path_monitor_thread.join();
    }
    if (m_congestion_monitor_thread.joinable()) {
        m_congestion_monitor_thread.join();
    }
    if (m_send_worker_thread.joinable()) {
        m_send_worker_thread.join();
    }
}

void FileTransferManager::set_outbound_message_callback(TransferOutboundMessageCallback cb) {
    {
        std::lock_guard<std::mutex> lock(m_send_mutex);
        m_outbound_callback = std::move(cb);
    }
    m_send_cv.notify_all();
}

// ============================================================================
// TRANSFER INITIATION
// ============================================================================
// Public API to start sending or receiving a file.  These functions perform
// validation, create a `TransferSession`, register a checkpoint file and select
// an initial network path based on the configured strategy.

std::string FileTransferManager::send_file(const std::string& file_path,
                                           const std::string& peer_id,
                                           const std::string& peer_ip,
                                           int peer_port,
                                           TransferPriority priority,
                                           PathSelectionStrategy strategy) {
    
    // Protect the transfer map while we check limits and insert a new session.
    std::lock_guard<std::mutex> lock(m_transfers_mutex);
    
    // Enforce the maximum number of concurrent transfers configured.
    if (m_transfers.size() >= m_max_concurrent_transfers) {
        LOG_WARN("FT: Maximum concurrent transfers reached (" +
                 std::to_string(m_max_concurrent_transfers) + ")");
        return "";
    }
    
    // Verify the source file exists and obtain its size.
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        LOG_WARN("FT: Cannot open file for sending: " + file_path);
        return "";
    }
    
    uint64_t file_size = file.tellg();
    file.close();
    
    if (file_size == 0) {
        LOG_WARN("FT: File is empty: " + file_path);
        return "";
    }
    
    // Resume from an existing checkpoint if present.
    std::shared_ptr<TransferCheckpoint> checkpoint = load_checkpoint(file_path);

    // Initialise a new TransferSession structure.
    std::string transfer_id = (checkpoint && !checkpoint->transfer_id.empty())
                                  ? checkpoint->transfer_id
                                  : generate_transfer_id();
    auto session = std::make_shared<TransferSession>();
    
    session->transfer_id = transfer_id;
    session->file_path = file_path;
    session->file_name = file_path.substr(file_path.find_last_of("/\\") + 1);
    session->file_size = file_size;
    session->total_chunks = (file_size + m_chunk_size - 1) / m_chunk_size;
    session->direction = TransferDirection::SEND;
    session->state = TransferState::IN_PROGRESS;
    session->priority = priority;
    session->peer_id = peer_id;
    session->peer_ip = peer_ip;
    session->peer_port = peer_port;
    session->start_time = std::chrono::steady_clock::now();
    session->last_activity = session->start_time;
    session->bytes_transferred = 0;
    session->chunks_transferred = 0;
    session->completed_chunks.assign(session->total_chunks, 0);
    
    // Create checkpoint file path
    session->checkpoint_file = file_path + ".checkpoint";

    // Apply checkpoint progress if available.
    if (checkpoint) {
        session->completed_chunks = checkpoint->completed_chunks;
        if (session->completed_chunks.size() < session->total_chunks) {
            session->completed_chunks.resize(session->total_chunks, 0);
        }

        // Recompute counters defensively based on completed chunks.
        uint64_t bytes = 0;
        uint32_t chunks = 0;
        for (uint32_t i = 0; i < session->total_chunks && i < session->completed_chunks.size(); i++) {
            if (!session->completed_chunks[i]) continue;
            chunks++;
            uint32_t chunk_bytes = m_chunk_size;
            if (i == session->total_chunks - 1) {
                chunk_bytes = static_cast<uint32_t>(session->file_size % m_chunk_size);
                if (chunk_bytes == 0) chunk_bytes = m_chunk_size;
            }
            bytes += chunk_bytes;
        }
        session->bytes_transferred = bytes;
        session->chunks_transferred = chunks;
        session->next_chunk_id = 0;

        LOG_INFO("FT: Resuming send transfer from checkpoint - " + std::to_string(session->bytes_transferred) + " bytes completed");
    }
    
    // Select the best available network path for the initial transfer.
    auto optimal_path = find_optimal_path(peer_id, strategy);
    if (optimal_path) {
        session->active_paths.push_back(optimal_path->path_id);
        LOG_INFO("FT: Send transfer " + transfer_id + " to " + peer_id +
                 " using path " + optimal_path->path_id +
                 " (latency: " + std::to_string(optimal_path->latency_ms) + "ms)");
    } else {
        LOG_WARN("FT: No available paths to peer " + peer_id);
    }
    
    m_transfers[transfer_id] = session;

    // Clear any stale chunk queues (in case of transfer_id reuse on resume).
    {
        std::lock_guard<std::mutex> chunks_lock(m_chunks_mutex);
        m_pending_chunks.erase(transfer_id);
        m_inflight_chunks.erase(transfer_id);
    }
    
    // Update statistics
    {
        std::lock_guard<std::mutex> stats_lock(m_stats_mutex);
        m_stats.total_transfers++;
    }
    
    LOG_INFO("FT: Send transfer initiated: " + transfer_id +
             " File: " + session->file_name +
             " Size: " + std::to_string(file_size) + " bytes" +
             " Chunks: " + std::to_string(session->total_chunks));

    // Wake sender worker
    m_send_cv.notify_all();
    return transfer_id;
}

bool FileTransferManager::receive_file(const std::string& transfer_id,
                                       const std::string& file_path,
                                       const std::string& peer_id,
                                       const std::string& peer_ip,
                                       int peer_port,
                                       uint64_t expected_file_size) {
    
    // Protect the transfer map while creating a new receive session.
    std::lock_guard<std::mutex> lock(m_transfers_mutex);
    
    // Check if we're at max concurrent transfers
    if (m_transfers.size() >= m_max_concurrent_transfers) {
        LOG_WARN("FT: Maximum concurrent transfers reached");
        return false;
    }
    
    // Create transfer session
    auto session = std::make_shared<TransferSession>();
    
    session->transfer_id = transfer_id;
    session->file_path = file_path;
    session->file_name = file_path.substr(file_path.find_last_of("/\\") + 1);
    session->file_size = expected_file_size;
    session->total_chunks = (expected_file_size + m_chunk_size - 1) / m_chunk_size;
    session->direction = TransferDirection::RECEIVE;
    session->state = TransferState::IN_PROGRESS;
    session->priority = TransferPriority::NORMAL;
    session->peer_id = peer_id;
    session->peer_ip = peer_ip;
    session->peer_port = peer_port;
    session->start_time = std::chrono::steady_clock::now();
    session->last_activity = session->start_time;
    session->bytes_transferred = 0;
    session->chunks_transferred = 0;

    // Receiver writes into a temp file and renames atomically on completion.
    session->temp_file_path = file_path + ".part";
    session->completed_chunks.assign(session->total_chunks, 0);
    
    session->checkpoint_file = file_path + ".checkpoint";
    
    // Attempt to resume from an existing checkpoint if present.
    auto checkpoint = load_checkpoint(file_path);
    if (checkpoint) {
        session->bytes_transferred = checkpoint->bytes_transferred;
        session->chunks_transferred = checkpoint->chunks_transferred;
        session->completed_chunks = checkpoint->completed_chunks;
        if (session->completed_chunks.size() < session->total_chunks) {
            session->completed_chunks.resize(session->total_chunks, 0);
        }
        LOG_INFO("FT: Resuming receive transfer from checkpoint - " +
                 std::to_string(session->bytes_transferred) + " bytes completed");
    }

    // Ensure parent directories exist and create/preallocate the .part file.
    try {
        std::filesystem::path out_path(file_path);
        if (out_path.has_parent_path()) {
            std::filesystem::create_directories(out_path.parent_path());
        }

        // Create the part file if it doesn't exist.
        if (!std::filesystem::exists(session->temp_file_path)) {
            std::ofstream create(session->temp_file_path, std::ios::binary);
            create.close();
        }

        // Preallocate/resize to expected size for sparse-friendly random writes.
        std::error_code ec;
        std::filesystem::resize_file(session->temp_file_path, expected_file_size, ec);
        if (ec) {
            LOG_WARN("FT: Failed to preallocate part file: " + session->temp_file_path + " error=" + ec.message());
        }
    } catch (const std::exception& e) {
        LOG_WARN("FT: Failed to prepare receive file: " + std::string(e.what()));
    }
    
    m_transfers[transfer_id] = session;
    
    LOG_INFO("FT: Receive transfer initiated: " + transfer_id +
             " File: " + session->file_name +
             " Expected size: " + std::to_string(expected_file_size) + " bytes");
    
    return true;
}

// ============================================================================
// TRANSFER CONTROL
// ============================================================================
// Functions to pause, resume, or cancel an ongoing transfer.  They update the
// session state and optionally persist a checkpoint.

bool FileTransferManager::pause_transfer(const std::string& transfer_id) {
    std::lock_guard<std::mutex> lock(m_transfers_mutex);
    
    auto it = m_transfers.find(transfer_id);
    if (it == m_transfers.end()) {
        LOG_WARN("FT: Transfer not found: " + transfer_id);
        return false;
    }
    
    if (it->second->state != TransferState::IN_PROGRESS) {
        LOG_WARN("FT: Cannot pause transfer in state " +
                 std::to_string(static_cast<int>(it->second->state)));
        return false;
    }
    
    it->second->state = TransferState::PAUSED;
    save_checkpoint(transfer_id);
    
    LOG_INFO("FT: Transfer paused: " + transfer_id);
    return true;
}

bool FileTransferManager::resume_transfer(const std::string& transfer_id) {
    std::lock_guard<std::mutex> lock(m_transfers_mutex);
    
    auto it = m_transfers.find(transfer_id);
    if (it == m_transfers.end()) {
        LOG_WARN("FT: Transfer not found: " + transfer_id);
        return false;
    }
    
    if (it->second->state != TransferState::PAUSED) {
        LOG_WARN("FT: Cannot resume transfer not in PAUSED state");
        return false;
    }
    
    it->second->state = TransferState::IN_PROGRESS;
    it->second->last_activity = std::chrono::steady_clock::now();
    
    LOG_INFO("FT: Transfer resumed: " + transfer_id);
    m_send_cv.notify_all();
    return true;
}

void FileTransferManager::send_worker_loop() {
    using clock = std::chrono::steady_clock;
    auto last = clock::now();
    double tokens_bytes = 0.0;

    while (m_running.load(std::memory_order_acquire)) {
        // Wait a short interval or until woken by new work/ACKs.
        {
            std::unique_lock<std::mutex> lk(m_send_mutex);
            m_send_cv.wait_for(lk, std::chrono::milliseconds(20), [this] {
                return !m_running.load(std::memory_order_acquire);
            });
        }

        if (!m_running.load(std::memory_order_acquire)) {
            break;
        }

        TransferOutboundMessageCallback outbound;
        {
            std::lock_guard<std::mutex> lk(m_send_mutex);
            outbound = m_outbound_callback;
        }
        if (!outbound) {
            continue;
        }

        // Update token bucket based on current adaptive rate.
        const auto now = clock::now();
        const double dt = std::chrono::duration<double>(now - last).count();
        last = now;

        const uint32_t rate_kbps = get_adaptive_rate_limit();
        const double bytes_per_sec = (static_cast<double>(rate_kbps) * 1000.0) / 8.0;
        const double max_tokens = std::max(1.0, bytes_per_sec);  // allow up to ~1s burst
        tokens_bytes = std::min(max_tokens, tokens_bytes + dt * bytes_per_sec);

        // Snapshot active transfers and attempt to send chunks.
        const auto active = get_active_transfers();
        int total_sent = 0;

        // LOG_DEBUG("FT: Active transfers: " + std::to_string(active.size()));

        for (const auto& transfer_id : active) {
            if (total_sent >= 128) {
                break; // keep fairness and avoid long loops
            }

            auto session = get_transfer_status(transfer_id);
            if (!session) {
                continue;
            }
            if (session->direction != TransferDirection::SEND) {
                continue;
            }
            if (session->state != TransferState::IN_PROGRESS) {
                continue;
            }

            // Retransmit timeouts (moves timed-out inflight chunks back to pending queue).
            (void)get_chunks_to_retransmit(transfer_id);

            // Attempt to send as many chunks as tokens/window allow.
            for (int i = 0; i < 32 && total_sent < 128; i++) {
                auto chunk = get_next_chunk_to_send(transfer_id);
                if (!chunk) {
                    // LOG_DEBUG("FT: No chunk to send for " + transfer_id);
                    break;
                }

                if (tokens_bytes < static_cast<double>(chunk->size)) {
                    // LOG_DEBUG("FT: Not enough tokens for " + transfer_id + " needed=" + std::to_string(chunk->size) + " have=" + std::to_string(tokens_bytes));
                    // Not enough budget yet: put it back to pending and try later.
                    {
                        std::lock_guard<std::mutex> chunks_lock(m_chunks_mutex);
                        auto& pending = m_pending_chunks[transfer_id];
                        pending.push_front(chunk);

                        auto it = m_inflight_chunks.find(transfer_id);
                        if (it != m_inflight_chunks.end()) {
                            auto& inflight = it->second;
                            inflight.erase(
                                std::remove_if(inflight.begin(), inflight.end(),
                                               [&](const std::shared_ptr<TransferChunk>& c) {
                                                   return c && c->chunk_id == chunk->chunk_id;
                                               }),
                                inflight.end());
                        }
                    }
                    break;
                }

                tokens_bytes -= static_cast<double>(chunk->size);

                const std::string payload = encode_chunk_payload(transfer_id, *chunk);
                outbound(session->peer_id, payload);
                total_sent++;
                // LOG_DEBUG("FT: Sent chunk " + std::to_string(chunk->chunk_id) + " for " + transfer_id);
            }
        }
    }
}

bool FileTransferManager::cancel_transfer(const std::string& transfer_id) {
    std::lock_guard<std::mutex> lock(m_transfers_mutex);
    
    auto it = m_transfers.find(transfer_id);
    if (it == m_transfers.end()) {
        LOG_WARN("FT: Transfer not found: " + transfer_id);
        return false;
    }
    
    auto& session = it->second;
    session->state = TransferState::CANCELLED;
    
    // Clear checkpoint
    clear_checkpoint(session->file_path);
    
    // Update statistics
    {
        std::lock_guard<std::mutex> stats_lock(m_stats_mutex);
        m_stats.failed_transfers++;
    }
    
    LOG_INFO("FT: Transfer cancelled: " + transfer_id);
    return true;
}

bool FileTransferManager::can_resume_transfer(const std::string& file_path) {
    return load_checkpoint(file_path) != nullptr;
}

// ============================================================================
// TRANSFER STATUS
// ============================================================================
// Query functions that return the current state of a transfer or aggregate
// information such as progress and speed.

std::shared_ptr<TransferSession> FileTransferManager::get_transfer_status(
    const std::string& transfer_id) {
    
    std::lock_guard<std::mutex> lock(m_transfers_mutex);
    
    auto it = m_transfers.find(transfer_id);
    if (it != m_transfers.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<std::string> FileTransferManager::get_active_transfers() {
    std::lock_guard<std::mutex> lock(m_transfers_mutex);
    
    std::vector<std::string> active;
    for (const auto& [id, session] : m_transfers) {
        if (session->state == TransferState::IN_PROGRESS) {
            active.push_back(id);
        }
    }
    return active;
}

float FileTransferManager::get_transfer_progress(const std::string& transfer_id) {
    std::lock_guard<std::mutex> lock(m_transfers_mutex);
    
    auto it = m_transfers.find(transfer_id);
    if (it == m_transfers.end()) {
        return -1.0f;
    }
    
    uint64_t total = it->second->file_size;
    if (total == 0) return 0.0f;
    
    return (it->second->bytes_transferred * 100.0f) / total;
}

float FileTransferManager::get_transfer_speed(const std::string& transfer_id) {
    std::lock_guard<std::mutex> lock(m_transfers_mutex);
    
    auto it = m_transfers.find(transfer_id);
    if (it == m_transfers.end()) {
        return 0.0f;
    }
    
    if (it->second->state != TransferState::IN_PROGRESS) {
        return 0.0f;
    }
    
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - it->second->start_time
    ).count();
    
    if (elapsed == 0) return 0.0f;
    
    // Speed in Kbps
    return (it->second->bytes_transferred * 8.0f) / elapsed;
}

// ============================================================================
// STATISTICS
// ============================================================================

std::map<std::string, double> FileTransferManager::get_statistics() {
    std::lock_guard<std::mutex> lock(m_stats_mutex);
    
    auto now = std::chrono::steady_clock::now();
    auto elapsed_sec = std::chrono::duration_cast<std::chrono::seconds>(
        now - m_stats.start_time
    ).count();
    
    std::map<std::string, double> stats;
    stats["total_bytes_transferred"] = m_stats.total_bytes_transferred;
    stats["total_files_transferred"] = m_stats.total_files_transferred;
    stats["total_transfers"] = m_stats.total_transfers;
    stats["successful_transfers"] = m_stats.successful_transfers;
    stats["failed_transfers"] = m_stats.failed_transfers;
    stats["success_rate"] = m_stats.total_transfers > 0 ?
        (m_stats.successful_transfers * 100.0f) / m_stats.total_transfers : 0.0;
    stats["avg_speed_kbps"] = elapsed_sec > 0 ?
        (m_stats.total_bytes_transferred * 8.0f) / (elapsed_sec * 1000.0f) : 0.0;
    stats["uptime_seconds"] = elapsed_sec;
    
    return stats;
}

void FileTransferManager::reset_statistics() {
    std::lock_guard<std::mutex> lock(m_stats_mutex);
    
    m_stats.total_bytes_transferred = 0;
    m_stats.total_files_transferred = 0;
    m_stats.total_transfers = 0;
    m_stats.successful_transfers = 0;
    m_stats.failed_transfers = 0;
    m_stats.start_time = std::chrono::steady_clock::now();
    
    LOG_INFO("FT: Statistics reset");
}
