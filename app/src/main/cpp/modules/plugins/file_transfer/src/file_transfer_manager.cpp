#include "file_transfer_manager.h"
#include "logger.h"
#include <fstream>
#include <cstring>
#include <algorithm>
#include <random>
#include <iomanip>
#include <sstream>

// ============================================================================
// CRC32 CALCULATION
// ============================================================================

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

FileTransferManager::FileTransferManager(uint32_t max_concurrent_transfers,
                                         uint32_t chunk_size_kb)
    : m_max_concurrent_transfers(max_concurrent_transfers),
      m_chunk_size(chunk_size_kb * 1024) {
    
    init_crc32_table();
    
    LOG_INFO("FT: FileTransferManager initialized with max " +
             std::to_string(max_concurrent_transfers) + " concurrent transfers");
    LOG_INFO("FT: Chunk size: " + std::to_string(chunk_size_kb) + "KB");
    
    // Start background threads
    m_path_monitor_thread = std::thread(&FileTransferManager::path_monitor_loop, this);
    m_congestion_monitor_thread = std::thread(&FileTransferManager::congestion_monitor_loop, this);
}

FileTransferManager::~FileTransferManager() {
    m_running = false;
    
    if (m_path_monitor_thread.joinable()) {
        m_path_monitor_thread.join();
    }
    if (m_congestion_monitor_thread.joinable()) {
        m_congestion_monitor_thread.join();
    }
    
    LOG_INFO("FT: FileTransferManager shutdown complete");
}

// ============================================================================
// TRANSFER INITIATION
// ============================================================================

std::string FileTransferManager::send_file(const std::string& file_path,
                                           const std::string& peer_id,
                                           const std::string& peer_ip,
                                           int peer_port,
                                           TransferPriority priority,
                                           PathSelectionStrategy strategy) {
    
    std::lock_guard<std::mutex> lock(m_transfers_mutex);
    
    // Check if we're at max concurrent transfers
    if (m_transfers.size() >= m_max_concurrent_transfers) {
        LOG_WARN("FT: Maximum concurrent transfers reached (" +
                 std::to_string(m_max_concurrent_transfers) + ")");
        return "";
    }
    
    // Check if file exists and get size
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
    
    // Create transfer session
    std::string transfer_id = generate_transfer_id();
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
    
    // Create checkpoint file path
    session->checkpoint_file = file_path + ".checkpoint";
    
    // Find optimal initial path
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
    
    // Update statistics
    {
        std::lock_guard<std::mutex> stats_lock(m_stats_mutex);
        m_stats.total_transfers++;
    }
    
    LOG_INFO("FT: Send transfer initiated: " + transfer_id +
             " File: " + session->file_name +
             " Size: " + std::to_string(file_size) + " bytes" +
             " Chunks: " + std::to_string(session->total_chunks));
    
    return transfer_id;
}

bool FileTransferManager::receive_file(const std::string& transfer_id,
                                       const std::string& file_path,
                                       const std::string& peer_id,
                                       const std::string& peer_ip,
                                       int peer_port,
                                       uint64_t expected_file_size) {
    
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
    
    session->checkpoint_file = file_path + ".checkpoint";
    
    // Try to resume from checkpoint
    auto checkpoint = load_checkpoint(file_path);
    if (checkpoint) {
        session->bytes_transferred = checkpoint->bytes_transferred;
        session->chunks_transferred = checkpoint->chunks_transferred;
        session->completed_chunks = checkpoint->completed_chunks;
        LOG_INFO("FT: Resuming receive transfer from checkpoint - " +
                 std::to_string(session->bytes_transferred) + " bytes completed");
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
    return true;
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
// PATH MANAGEMENT
// ============================================================================

std::string FileTransferManager::register_network_path(
    const std::string& peer_id,
    const std::string& next_hop_peer_id,
    const std::string& next_hop_ip,
    int next_hop_port,
    int latency_ms,
    int bandwidth_kbps) {
    
    std::lock_guard<std::mutex> lock(m_paths_mutex);
    
    auto path = std::make_shared<NetworkPath>();
    path->path_id = "path_" + peer_id + "_" + generate_transfer_id();
    path->next_hop_peer_id = next_hop_peer_id;
    path->next_hop_ip = next_hop_ip;
    path->next_hop_port = next_hop_port;
    path->hop_count = 1;
    path->latency_ms = latency_ms;
    path->bandwidth_kbps = bandwidth_kbps;
    path->path_quality_score = 100.0f;
    path->last_used = std::chrono::steady_clock::now();
    path->is_available = true;
    
    m_peer_paths[peer_id].push_back(path);
    m_path_map[path->path_id] = path;
    
    LOG_DEBUG("FT: Registered path " + path->path_id +
              " to peer " + peer_id +
              " (latency: " + std::to_string(latency_ms) + "ms" +
              ", bandwidth: " + std::to_string(bandwidth_kbps) + " Kbps)");
    
    return path->path_id;
}

std::shared_ptr<NetworkPath> FileTransferManager::find_optimal_path(
    const std::string& peer_id,
    PathSelectionStrategy strategy) {
    
    std::lock_guard<std::mutex> lock(m_paths_mutex);
    
    auto it = m_peer_paths.find(peer_id);
    if (it == m_peer_paths.end() || it->second.empty()) {
        return nullptr;
    }
    
    auto& paths = it->second;
    
    // Filter available paths
    std::vector<std::shared_ptr<NetworkPath>> available;
    for (auto& path : paths) {
        if (path->is_available && path->consecutive_failures < 3) {
            available.push_back(path);
        }
    }
    
    if (available.empty()) {
        return nullptr;
    }
    
    // Find best path based on strategy
    std::shared_ptr<NetworkPath> best = available[0];
    float best_score = score_path(best, strategy);
    
    for (size_t i = 1; i < available.size(); i++) {
        float score = score_path(available[i], strategy);
        if (score > best_score) {
            best = available[i];
            best_score = score;
        }
    }
    
    return best;
}

void FileTransferManager::update_path_metrics(const std::string& path_id,
                                              int latency_ms,
                                              int bandwidth_kbps) {
    std::lock_guard<std::mutex> lock(m_paths_mutex);
    
    auto it = m_path_map.find(path_id);
    if (it == m_path_map.end()) {
        return;
    }
    
    auto& path = it->second;
    
    // Exponential moving average for latency and bandwidth
    path->latency_ms = (path->latency_ms * 3 + latency_ms) / 4;
    path->bandwidth_kbps = (path->bandwidth_kbps * 3 + bandwidth_kbps) / 4;
    path->consecutive_failures = 0;
    path->is_available = true;
    path->last_used = std::chrono::steady_clock::now();
    
    LOG_DEBUG("FT: Updated path " + path_id +
              " - latency: " + std::to_string(path->latency_ms) + "ms" +
              " bandwidth: " + std::to_string(path->bandwidth_kbps) + " Kbps");
}

void FileTransferManager::mark_path_failed(const std::string& path_id) {
    std::lock_guard<std::mutex> lock(m_paths_mutex);
    
    auto it = m_path_map.find(path_id);
    if (it == m_path_map.end()) {
        return;
    }
    
    auto& path = it->second;
    path->consecutive_failures++;
    
    if (path->consecutive_failures >= 3) {
        path->is_available = false;
        LOG_WARN("FT: Path " + path_id + " marked unavailable after 3 failures");
    }
}

// ============================================================================
// MULTIPLEXING
// ============================================================================

std::vector<std::string> FileTransferManager::get_transfer_paths(
    const std::string& transfer_id) {
    
    std::lock_guard<std::mutex> lock(m_transfers_mutex);
    
    auto it = m_transfers.find(transfer_id);
    if (it == m_transfers.end()) {
        return {};
    }
    
    return it->second->active_paths;
}

bool FileTransferManager::add_path_to_transfer(const std::string& transfer_id,
                                                const std::string& path_id) {
    std::lock_guard<std::mutex> lock(m_transfers_mutex);
    
    auto it = m_transfers.find(transfer_id);
    if (it == m_transfers.end()) {
        return false;
    }
    
    auto& paths = it->second->active_paths;
    if (std::find(paths.begin(), paths.end(), path_id) == paths.end()) {
        paths.push_back(path_id);
        LOG_INFO("FT: Added path " + path_id + " to transfer " + transfer_id);
        return true;
    }
    
    return false;
}

bool FileTransferManager::remove_path_from_transfer(const std::string& transfer_id,
                                                     const std::string& path_id) {
    std::lock_guard<std::mutex> lock(m_transfers_mutex);
    
    auto it = m_transfers.find(transfer_id);
    if (it == m_transfers.end()) {
        return false;
    }
    
    auto& paths = it->second->active_paths;
    auto path_it = std::find(paths.begin(), paths.end(), path_id);
    if (path_it != paths.end()) {
        paths.erase(path_it);
        LOG_INFO("FT: Removed path " + path_id + " from transfer " + transfer_id);
        return true;
    }
    
    return false;
}

// ============================================================================
// CONGESTION HANDLING
// ============================================================================

void FileTransferManager::report_congestion(const std::string& path_id,
                                            const CongestionMetrics& metrics) {
    {
        std::lock_guard<std::mutex> lock(m_congestion_mutex);
        m_congestion_history.push_back(metrics);
        
        // Keep last 100 samples
        if (m_congestion_history.size() > 100) {
            m_congestion_history.pop_front();
        }
    }
    
    // Update path metrics based on congestion
    {
        std::lock_guard<std::mutex> path_lock(m_paths_mutex);
        auto it = m_path_map.find(path_id);
        if (it != m_path_map.end()) {
            // Reduce bandwidth estimate based on loss
            if (metrics.packet_loss_percent > 0) {
                int reduced_bw = static_cast<int>(it->second->bandwidth_kbps *
                                (1.0f - metrics.packet_loss_percent / 100.0f));
                it->second->bandwidth_kbps = std::max(reduced_bw, static_cast<int>(MIN_RATE_LIMIT_KBPS));
            }
        }
    }
    
    // Estimate new congestion level
    CongestionLevel new_level = estimate_congestion();
    if (new_level != m_current_congestion_level) {
        m_current_congestion_level = new_level;
        adjust_rate_limit(new_level);
        
        if (m_congestion_callback) {
            m_congestion_callback(new_level, metrics);
        }
    }
}

CongestionMetrics FileTransferManager::get_congestion_metrics() {
    std::lock_guard<std::mutex> lock(m_congestion_mutex);
    
    if (m_congestion_history.empty()) {
        return CongestionMetrics{CongestionLevel::LOW, 0.0f, 0.0f, 0.0f, 0};
    }
    
    return m_congestion_history.back();
}

uint32_t FileTransferManager::get_adaptive_rate_limit() {
    return m_current_rate_limit_kbps.load();
}

void FileTransferManager::set_rate_limit(uint32_t rate_kbps) {
    uint32_t limited = std::max(MIN_RATE_LIMIT_KBPS,
                               std::min(rate_kbps, MAX_RATE_LIMIT_KBPS));
    m_current_rate_limit_kbps.store(limited);
    LOG_INFO("FT: Rate limit set to " + std::to_string(limited) + " Kbps");
}

// ============================================================================
// CHUNK HANDLING
// ============================================================================

bool FileTransferManager::handle_incoming_chunk(const std::string& transfer_id,
                                                 const TransferChunk& chunk) {
    std::lock_guard<std::mutex> lock(m_transfers_mutex);
    
    auto it = m_transfers.find(transfer_id);
    if (it == m_transfers.end()) {
        LOG_WARN("FT: Received chunk for unknown transfer: " + transfer_id);
        return false;
    }
    
    auto& session = it->second;
    
    // Validate chunk CRC
    uint32_t calculated_crc = calculate_crc32(chunk.data);
    if (calculated_crc != chunk.crc32) {
        LOG_WARN("FT: CRC mismatch for chunk " + std::to_string(chunk.chunk_id) +
                 " in transfer " + transfer_id);
        return false;
    }
    
    // Mark chunk as completed
    if (chunk.chunk_id >= session->completed_chunks.size()) {
        session->completed_chunks.resize(chunk.chunk_id + 1, 0);
    }
    
    if (!session->completed_chunks[chunk.chunk_id]) {
        session->completed_chunks[chunk.chunk_id] = 1;
        session->bytes_transferred += chunk.size;
        session->chunks_transferred++;
        session->last_activity = std::chrono::steady_clock::now();
        
        // Save checkpoint periodically
        if (session->chunks_transferred % CHECKPOINT_INTERVAL == 0) {
            save_checkpoint(transfer_id);
        }
        
        // Call progress callback
        if (m_progress_callback) {
            float progress = (session->bytes_transferred * 100.0f) / session->file_size;
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - session->start_time
            ).count();
            float speed_kbps = elapsed_ms > 0 ? (session->bytes_transferred * 8.0f) / elapsed_ms : 0.0f;
            
            m_progress_callback(transfer_id, progress, speed_kbps);
        }
        
        // Check if transfer complete
        if (session->chunks_transferred == session->total_chunks) {
            session->state = TransferState::COMPLETED;
            clear_checkpoint(session->file_path);
            
            {
                std::lock_guard<std::mutex> stats_lock(m_stats_mutex);
                m_stats.total_bytes_transferred += session->bytes_transferred;
                m_stats.total_files_transferred++;
                m_stats.successful_transfers++;
            }
            
            if (m_complete_callback) {
                m_complete_callback(transfer_id, true, "");
            }
            
            LOG_INFO("FT: Transfer completed: " + transfer_id);
        }
        
        return true;
    }
    
    return false;
}

std::shared_ptr<TransferChunk> FileTransferManager::get_next_chunk_to_send(
    const std::string& transfer_id) {
    
    std::lock_guard<std::mutex> chunks_lock(m_chunks_mutex);
    
    auto it = m_pending_chunks.find(transfer_id);
    if (it != m_pending_chunks.end() && !it->second.empty()) {
        auto chunk = it->second.front();
        it->second.pop_front();
        chunk->sent_time = std::chrono::steady_clock::now();
        return chunk;
    }
    
    return nullptr;
}

void FileTransferManager::acknowledge_chunk(const std::string& transfer_id,
                                            uint32_t chunk_id) {
    std::lock_guard<std::mutex> lock(m_transfers_mutex);
    
    auto it = m_transfers.find(transfer_id);
    if (it == m_transfers.end()) {
        return;
    }
    
    auto& session = it->second;
    session->bytes_transferred += std::min(m_chunk_size, 
                                           static_cast<uint32_t>(session->file_size - 
                                                               chunk_id * m_chunk_size));
    session->chunks_transferred++;
}

std::vector<uint32_t> FileTransferManager::get_chunks_to_retransmit(
    const std::string& transfer_id) {
    
    std::vector<uint32_t> to_retransmit;
    
    std::lock_guard<std::mutex> chunks_lock(m_chunks_mutex);
    
    auto it = m_pending_chunks.find(transfer_id);
    if (it != m_pending_chunks.end()) {
        auto now = std::chrono::steady_clock::now();
        
        for (auto& chunk : it->second) {
            if (chunk->is_acked) continue;
            
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - chunk->sent_time
            ).count();
            
            // Timeout = 5 seconds + 100ms per retry
            int timeout_ms = 5000 + (chunk->retry_count * 100);
            
            if (elapsed > timeout_ms) {
                to_retransmit.push_back(chunk->chunk_id);
                chunk->retry_count++;
            }
        }
    }
    
    return to_retransmit;
}

// ============================================================================
// CHECKPOINT / RESUME
// ============================================================================

bool FileTransferManager::save_checkpoint(const std::string& transfer_id) {
    std::lock_guard<std::mutex> lock(m_transfers_mutex);
    
    auto it = m_transfers.find(transfer_id);
    if (it == m_transfers.end()) {
        return false;
    }
    
    auto& session = it->second;
    
    try {
        std::ofstream checkpoint(session->checkpoint_file, std::ios::binary);
        if (!checkpoint.is_open()) {
            LOG_WARN("FT: Cannot create checkpoint file: " + session->checkpoint_file);
            return false;
        }
        
        // Write checkpoint data
        checkpoint.write(session->transfer_id.c_str(), session->transfer_id.length());
        checkpoint.put('\0');
        
        uint64_t bytes = session->bytes_transferred;
        checkpoint.write(reinterpret_cast<const char*>(&bytes), sizeof(bytes));
        
        uint32_t chunks = session->chunks_transferred;
        checkpoint.write(reinterpret_cast<const char*>(&chunks), sizeof(chunks));
        
        checkpoint.close();
        
        LOG_DEBUG("FT: Checkpoint saved for transfer " + transfer_id +
                  " - " + std::to_string(session->bytes_transferred) + " bytes");
        
        return true;
    } catch (const std::exception& e) {
        LOG_WARN("FT: Error saving checkpoint: " + std::string(e.what()));
        return false;
    }
}

std::shared_ptr<TransferCheckpoint> FileTransferManager::load_checkpoint(
    const std::string& file_path) {
    
    std::string checkpoint_file = file_path + ".checkpoint";
    
    std::ifstream checkpoint(checkpoint_file, std::ios::binary);
    if (!checkpoint.is_open()) {
        return nullptr;
    }
    
    try {
        auto result = std::make_shared<TransferCheckpoint>();
        
        // Read transfer ID
        std::string transfer_id;
        char c;
        while (checkpoint.get(c) && c != '\0') {
            transfer_id += c;
        }
        result->transfer_id = transfer_id;
        
        // Read bytes transferred
        checkpoint.read(reinterpret_cast<char*>(&result->bytes_transferred),
                       sizeof(result->bytes_transferred));
        
        // Read chunks transferred
        checkpoint.read(reinterpret_cast<char*>(&result->chunks_transferred),
                       sizeof(result->chunks_transferred));
        
        result->checkpoint_time = std::chrono::steady_clock::now();
        
        checkpoint.close();
        
        LOG_DEBUG("FT: Checkpoint loaded for file " + file_path +
                  " - " + std::to_string(result->bytes_transferred) + " bytes");
        
        return result;
    } catch (const std::exception& e) {
        LOG_WARN("FT: Error loading checkpoint: " + std::string(e.what()));
        return nullptr;
    }
}

void FileTransferManager::clear_checkpoint(const std::string& file_path) {
    std::string checkpoint_file = file_path + ".checkpoint";
    
    if (std::remove(checkpoint_file.c_str()) == 0) {
        LOG_DEBUG("FT: Checkpoint cleared for file " + file_path);
    }
}

// ============================================================================
// INTERNAL METHODS
// ============================================================================

float FileTransferManager::score_path(const std::shared_ptr<NetworkPath>& path,
                                       PathSelectionStrategy strategy) {
    if (!path || !path->is_available) {
        return 0.0f;
    }
    
    switch (strategy) {
        case PathSelectionStrategy::LATENCY:
            // Lower latency is better (normalize to 0-100 range)
            return std::max(0.0f, 100.0f - (path->latency_ms / 10.0f));
        
        case PathSelectionStrategy::THROUGHPUT:
            // Higher bandwidth is better
            return path->bandwidth_kbps / 1000.0f;  // Normalize to 0-100 scale
        
        case PathSelectionStrategy::BALANCED: {
            // Combination of both
            float latency_score = std::max(0.0f, 100.0f - (path->latency_ms / 10.0f));
            float bandwidth_score = path->bandwidth_kbps / 1000.0f;
            return (latency_score * 0.5f) + (bandwidth_score * 0.5f);
        }
        
        case PathSelectionStrategy::COST:
            // Simple cost = hops (lower is better)
            return std::max(0.0f, 100.0f - (path->hop_count * 10.0f));
        
        default:
            return path->path_quality_score;
    }
}

void FileTransferManager::adjust_rate_limit(CongestionLevel level) {
    uint32_t new_limit = m_current_rate_limit_kbps.load();
    
    switch (level) {
        case CongestionLevel::LOW:
            new_limit = std::min(new_limit + 100, MAX_RATE_LIMIT_KBPS);
            LOG_DEBUG("FT: Congestion LOW - increasing rate limit to " +
                     std::to_string(new_limit) + " Kbps");
            break;
        
        case CongestionLevel::MODERATE:
            new_limit = std::max(new_limit - 50, MIN_RATE_LIMIT_KBPS);
            LOG_DEBUG("FT: Congestion MODERATE - reducing rate limit to " +
                     std::to_string(new_limit) + " Kbps");
            break;
        
        case CongestionLevel::HIGH:
            new_limit = std::max(new_limit - 200, MIN_RATE_LIMIT_KBPS);
            LOG_DEBUG("FT: Congestion HIGH - significantly reducing rate limit to " +
                     std::to_string(new_limit) + " Kbps");
            break;
        
        case CongestionLevel::SEVERE:
            new_limit = MIN_RATE_LIMIT_KBPS;
            LOG_WARN("FT: Congestion SEVERE - limiting rate to minimum " +
                    std::to_string(new_limit) + " Kbps");
            break;
    }
    
    m_current_rate_limit_kbps.store(new_limit);
}

CongestionLevel FileTransferManager::estimate_congestion() {
    std::lock_guard<std::mutex> lock(m_congestion_mutex);
    
    if (m_congestion_history.empty()) {
        return CongestionLevel::LOW;
    }
    
    // Average recent samples (last 10)
    float avg_loss = 0.0f;
    float avg_rtt = 0.0f;
    float avg_util = 0.0f;
    
    size_t samples = std::min(size_t(10), m_congestion_history.size());
    for (size_t i = m_congestion_history.size() - samples; i < m_congestion_history.size(); i++) {
        avg_loss += m_congestion_history[i].packet_loss_percent;
        avg_rtt += m_congestion_history[i].rtt_ms;
        avg_util += m_congestion_history[i].bandwidth_utilization_percent;
    }
    
    avg_loss /= samples;
    avg_rtt /= samples;
    avg_util /= samples;
    
    // Estimate congestion level
    if (avg_loss > 10.0f || avg_util > 80.0f) {
        return CongestionLevel::SEVERE;
    } else if (avg_loss > 5.0f || avg_util > 60.0f) {
        return CongestionLevel::HIGH;
    } else if (avg_loss > 1.0f || avg_util > 40.0f) {
        return CongestionLevel::MODERATE;
    } else {
        return CongestionLevel::LOW;
    }
}

void FileTransferManager::path_monitor_loop() {
    while (m_running) {
        std::this_thread::sleep_for(std::chrono::seconds(PATH_EVAL_INTERVAL_SEC));
        
        // Evaluate and update paths periodically
        {
            std::lock_guard<std::mutex> lock(m_paths_mutex);
            
            for (auto& [path_id, path] : m_path_map) {
                if (!path->is_available) {
                    // Try to recover unavailable paths
                    auto now = std::chrono::steady_clock::now();
                    auto inactive_sec = std::chrono::duration_cast<std::chrono::seconds>(
                        now - path->last_used
                    ).count();
                    
                    if (inactive_sec > 60) {  // Reset after 60 seconds
                        path->consecutive_failures = 0;
                        path->is_available = true;
                        LOG_DEBUG("FT: Path " + path_id + " recovered from failure");
                    }
                }
            }
        }
    }
}

void FileTransferManager::congestion_monitor_loop() {
    while (m_running) {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(CONGESTION_CHECK_INTERVAL_MS)
        );
        
        // Monitor active transfers for congestion
        // This would be called periodically to update congestion metrics
        // In a real implementation, this would gather RTT, packet loss, etc.
    }
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
