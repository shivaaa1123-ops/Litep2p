#include "file_transfer_manager.h"
#include "logger.h"
#include <fstream>
#include <vector>
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <system_error>

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

    if (session->direction != TransferDirection::RECEIVE) {
        LOG_WARN("FT: Received chunk for non-receive session: " + transfer_id);
        return false;
    }

    // LOG_DEBUG("FT: Processing chunk " + std::to_string(chunk.chunk_id) + " offset=" + std::to_string(chunk.offset) + " size=" + std::to_string(chunk.size));

    // Basic bounds validation (prevents disk/memory abuse)
    if (chunk.chunk_id >= session->total_chunks) {
        LOG_WARN("FT: Chunk id out of range: " + std::to_string(chunk.chunk_id) +
                 " total=" + std::to_string(session->total_chunks) +
                 " transfer=" + transfer_id);
        return false;
    }
    if (chunk.size == 0 || chunk.size > m_chunk_size) {
        LOG_WARN("FT: Invalid chunk size: " + std::to_string(chunk.size) + " transfer=" + transfer_id);
        return false;
    }
    if (static_cast<uint64_t>(chunk.offset) + static_cast<uint64_t>(chunk.size) > session->file_size) {
        LOG_WARN("FT: Chunk bounds exceed expected file size (offset=" + std::to_string(chunk.offset) +
                 ", size=" + std::to_string(chunk.size) + ") transfer=" + transfer_id);
        return false;
    }

    // Validate chunk CRC
    uint32_t calculated_crc = calculate_crc32(chunk.data);
    if (calculated_crc != chunk.crc32) {
        LOG_WARN("FT: CRC mismatch for chunk " + std::to_string(chunk.chunk_id) +
                 " in transfer " + transfer_id);
        return false;
    }

    // Ensure completed_chunks has at least total_chunks entries for O(1) lookup.
    if (session->completed_chunks.size() < session->total_chunks) {
        session->completed_chunks.resize(session->total_chunks, 0);
    }

    // Duplicate chunk: treat as success (we should ACK again), but do not double-count.
    if (session->completed_chunks[chunk.chunk_id]) {
        session->last_activity = std::chrono::steady_clock::now();
        return true;
    }

    // Persist chunk data to disk before marking it complete.
    {
        std::lock_guard<std::mutex> io_lock(session->file_io_mutex);
        const std::string part_path = !session->temp_file_path.empty()
                                          ? session->temp_file_path
                                          : (session->file_path + ".part");

        std::fstream out(part_path, std::ios::in | std::ios::out | std::ios::binary);
        if (!out.is_open()) {
            // Create then reopen in read/write mode.
            std::ofstream create(part_path, std::ios::binary);
            create.close();
            out.open(part_path, std::ios::in | std::ios::out | std::ios::binary);
        }

        if (!out.is_open()) {
            session->state = TransferState::FAILED;
            session->error_count++;
            session->last_error = "Failed to open receive part file: " + part_path;
            LOG_WARN("FT: " + session->last_error);
            {
                std::lock_guard<std::mutex> stats_lock(m_stats_mutex);
                m_stats.failed_transfers++;
            }
            if (m_complete_callback) {
                m_complete_callback(transfer_id, false, session->last_error);
            }
            return false;
        }

        out.seekp(static_cast<std::streamoff>(chunk.offset), std::ios::beg);
        out.write(reinterpret_cast<const char*>(chunk.data.data()), static_cast<std::streamsize>(chunk.data.size()));
        out.flush();

        if (!out) {
            session->state = TransferState::FAILED;
            session->error_count++;
            session->last_error = "Failed to write chunk to disk (chunk=" + std::to_string(chunk.chunk_id) + ")";
            LOG_WARN("FT: " + session->last_error);
            {
                std::lock_guard<std::mutex> stats_lock(m_stats_mutex);
                m_stats.failed_transfers++;
            }
            if (m_complete_callback) {
                m_complete_callback(transfer_id, false, session->last_error);
            }
            return false;
        }
    }

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
                             std::chrono::steady_clock::now() - session->start_time)
                             .count();
        float speed_kbps = elapsed_ms > 0 ? (session->bytes_transferred * 8.0f) / elapsed_ms : 0.0f;

        m_progress_callback(transfer_id, progress, speed_kbps);
    }

    // Completion: atomically finalize .part -> destination and then clear checkpoint.
    if (session->chunks_transferred >= session->total_chunks) {
        {
            std::lock_guard<std::mutex> io_lock(session->file_io_mutex);
            const std::string part_path = !session->temp_file_path.empty()
                                              ? session->temp_file_path
                                              : (session->file_path + ".part");

            std::error_code ec;
            std::filesystem::rename(part_path, session->file_path, ec);
            if (ec) {
                // If destination exists, try remove+rename.
                std::error_code ec2;
                std::filesystem::remove(session->file_path, ec2);
                ec.clear();
                std::filesystem::rename(part_path, session->file_path, ec);
            }

            if (ec) {
                session->state = TransferState::FAILED;
                session->error_count++;
                session->last_error = "Finalize failed: " + ec.message();
                LOG_WARN("FT: " + session->last_error);
                {
                    std::lock_guard<std::mutex> stats_lock(m_stats_mutex);
                    m_stats.failed_transfers++;
                }
                if (m_complete_callback) {
                    m_complete_callback(transfer_id, false, session->last_error);
                }
                // Return true so sender still gets ACKs; receiver keeps .part for manual recovery.
                return true;
            }
        }

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

// Helper to read LE uint32
static uint32_t read_uint32_le(const uint8_t* data) {
    return static_cast<uint32_t>(data[0]) | 
           (static_cast<uint32_t>(data[1]) << 8) | 
           (static_cast<uint32_t>(data[2]) << 16) | 
           (static_cast<uint32_t>(data[3]) << 24);
}

static void append_uint32_le(std::string& out, uint32_t v) {
    out.push_back(static_cast<char>(v & 0xFF));
    out.push_back(static_cast<char>((v >> 8) & 0xFF));
    out.push_back(static_cast<char>((v >> 16) & 0xFF));
    out.push_back(static_cast<char>((v >> 24) & 0xFF));
}

static std::string encode_ack_payload(const std::string& transfer_id, uint32_t chunk_id) {
    // Payload format: [type=2][id_len][id bytes][chunk_id]
    std::string out;
    out.reserve(1 + 1 + transfer_id.size() + 4);
    out.push_back(static_cast<char>(2));
    out.push_back(static_cast<char>(static_cast<uint8_t>(transfer_id.size())));
    out.append(transfer_id);
    append_uint32_le(out, chunk_id);
    return out;
}

void FileTransferManager::handle_incoming_message(const std::string& peer_id, std::string_view payload) {
    if (payload.empty()) {
        return;
    }

    const uint8_t* data = reinterpret_cast<const uint8_t*>(payload.data());
    size_t len = payload.size();
    uint8_t msg_type = data[0];
    size_t offset = 1;

    // Message Types: 1=CHUNK, 2=ACK
    if (msg_type == 1) { // CHUNK
        if (offset + 1 > len) return;
        uint8_t id_len = data[offset++];
        if (id_len == 0 || id_len > 128) return;
        if (offset + id_len > len) return;
        
        std::string transfer_id(reinterpret_cast<const char*>(data + offset), id_len);
        offset += id_len;

        // Chunk header requires 16 bytes
        if (offset + 16 > len) return;
        
        TransferChunk chunk;
        chunk.chunk_id = read_uint32_le(data + offset); offset += 4;
        chunk.offset = read_uint32_le(data + offset); offset += 4;
        chunk.size = read_uint32_le(data + offset); offset += 4;
        chunk.crc32 = read_uint32_le(data + offset); offset += 4;

        if (chunk.size == 0) return;
        if (chunk.size > m_chunk_size) return;
        if (offset + chunk.size > len) return;
        
        chunk.data.assign(data + offset, data + offset + chunk.size);
        
        // Process the chunk
        const bool accepted = handle_incoming_chunk(transfer_id, chunk);
        // LOG_DEBUG("FT: Received chunk " + std::to_string(chunk.chunk_id) + " for " + transfer_id + " accepted=" + std::to_string(accepted));

        // ACK if accepted (including duplicates), to keep sender's window moving.
        if (accepted) {
            TransferOutboundMessageCallback outbound;
            {
                std::lock_guard<std::mutex> lk(m_send_mutex);
                outbound = m_outbound_callback;
            }
            if (outbound) {
                outbound(peer_id, encode_ack_payload(transfer_id, chunk.chunk_id));
            }
        }
        
    } else if (msg_type == 2) { // ACK
        if (offset + 1 > len) return;
        uint8_t id_len = data[offset++];
        if (id_len == 0 || id_len > 128) return;
        if (offset + id_len > len) return;
        
        std::string transfer_id(reinterpret_cast<const char*>(data + offset), id_len);
        offset += id_len;

        if (offset + 4 > len) return;
        
        uint32_t chunk_id = read_uint32_le(data + offset);
        
        acknowledge_chunk(transfer_id, chunk_id);

        // Wake sender worker (window may have freed up).
        m_send_cv.notify_all();
    }
}

std::shared_ptr<TransferChunk> FileTransferManager::get_next_chunk_to_send(
    const std::string& transfer_id) {

    {
        std::lock_guard<std::mutex> chunks_lock(m_chunks_mutex);

        // Enforce a sliding window.
        if (m_inflight_chunks[transfer_id].size() >= MAX_CHUNKS_IN_FLIGHT) {
            return nullptr;
        }

        auto it = m_pending_chunks.find(transfer_id);
        if (it != m_pending_chunks.end() && !it->second.empty()) {
            auto chunk = it->second.front();
            it->second.pop_front();
            chunk->sent_time = std::chrono::steady_clock::now();
            
            // Track inflight chunks
            m_inflight_chunks[transfer_id].push_back(chunk);
            
            return chunk;
        }
    }

    // No pending chunks, try to load more from file
    std::shared_ptr<TransferSession> session;
    {
        std::lock_guard<std::mutex> lock(m_transfers_mutex);
        auto it = m_transfers.find(transfer_id);
        if (it == m_transfers.end()) return nullptr;
        session = it->second;
    }

    if (session->state != TransferState::IN_PROGRESS) return nullptr;

    // Skip chunks already ACKed (resume support).
    while (session->next_chunk_id < session->total_chunks &&
           session->next_chunk_id < session->completed_chunks.size() &&
           session->completed_chunks[session->next_chunk_id]) {
        session->next_chunk_id++;
    }

    if (session->next_chunk_id >= session->total_chunks) return nullptr;

    // Read next batch (up to 4 chunks)
    std::vector<std::shared_ptr<TransferChunk>> new_chunks;
    std::ifstream file(session->file_path, std::ios::binary);
    if (!file.is_open()) return nullptr;

    for (int i = 0; i < 4 && session->next_chunk_id < session->total_chunks; i++) {
        auto chunk = std::make_shared<TransferChunk>();
        chunk->chunk_id = session->next_chunk_id;
        chunk->offset = chunk->chunk_id * m_chunk_size;
        
        file.seekg(chunk->offset);
        
        // Calculate size
        uint32_t size = m_chunk_size;
        if (chunk->offset + size > session->file_size) {
            size = static_cast<uint32_t>(session->file_size - chunk->offset);
        }
        chunk->size = size;
        chunk->data.resize(size);
        file.read(reinterpret_cast<char*>(chunk->data.data()), size);
        
        chunk->crc32 = calculate_crc32(chunk->data);
        new_chunks.push_back(chunk);
        
        session->next_chunk_id++;
    }
    
    if (new_chunks.empty()) return nullptr;

    // Add to pending and return first
    std::shared_ptr<TransferChunk> ret = nullptr;
    {
        std::lock_guard<std::mutex> chunks_lock(m_chunks_mutex);
        auto& queue = m_pending_chunks[transfer_id];
        for (auto& chunk : new_chunks) {
            queue.push_back(chunk);
        }

        // Enforce window again before popping
        if (m_inflight_chunks[transfer_id].size() >= MAX_CHUNKS_IN_FLIGHT) {
            return nullptr;
        }

        if (!queue.empty()) {
            ret = queue.front();
            queue.pop_front();
            ret->sent_time = std::chrono::steady_clock::now();
            m_inflight_chunks[transfer_id].push_back(ret);
        }
    }

    return ret;
}

void FileTransferManager::acknowledge_chunk(const std::string& transfer_id,
                                            uint32_t chunk_id) {
    {
        std::lock_guard<std::mutex> lock(m_transfers_mutex);

        auto it = m_transfers.find(transfer_id);
        if (it == m_transfers.end()) {
            return;
        }

        auto& session = it->second;

        if (session->direction != TransferDirection::SEND) {
            return;
        }

        if (chunk_id >= session->total_chunks) {
            return;
        }

        if (session->completed_chunks.size() < session->total_chunks) {
            session->completed_chunks.resize(session->total_chunks, 0);
        }

        // Duplicate ACK: ignore.
        if (session->completed_chunks[chunk_id]) {
            return;
        }
        session->completed_chunks[chunk_id] = 1;
        // Calculate actual bytes for this chunk (handle last chunk)
        uint32_t chunk_bytes = m_chunk_size;
        if (chunk_id == session->total_chunks - 1) {
            chunk_bytes = static_cast<uint32_t>(session->file_size % m_chunk_size);
            if (chunk_bytes == 0) chunk_bytes = m_chunk_size;
        }
        
        session->bytes_transferred += chunk_bytes;
        session->chunks_transferred++;
        session->last_activity = std::chrono::steady_clock::now();

        if (session->chunks_transferred % CHECKPOINT_INTERVAL == 0) {
            save_checkpoint(transfer_id);
        }
        
        // Check if transfer complete (Sender side)
        if (session->chunks_transferred >= session->total_chunks) {
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
            
            LOG_INFO("FT: Transfer completed (Sender): " + transfer_id);
        }
    }

    // Remove from inflight
    {
        std::lock_guard<std::mutex> chunks_lock(m_chunks_mutex);
        auto it = m_inflight_chunks.find(transfer_id);
        if (it != m_inflight_chunks.end()) {
            auto& inflight = it->second;
            for (auto v_it = inflight.begin(); v_it != inflight.end(); ++v_it) {
                if ((*v_it)->chunk_id == chunk_id) {
                    inflight.erase(v_it);
                    break;
                }
            }
        }
    }
}

std::vector<uint32_t> FileTransferManager::get_chunks_to_retransmit(
    const std::string& transfer_id) {

    std::vector<uint32_t> to_retransmit;

    std::lock_guard<std::mutex> chunks_lock(m_chunks_mutex);

    auto it = m_inflight_chunks.find(transfer_id);
    if (it != m_inflight_chunks.end()) {
        auto now = std::chrono::steady_clock::now();
        
        auto& inflight = it->second;
        std::vector<std::shared_ptr<TransferChunk>> remaining_inflight;
        auto& pending = m_pending_chunks[transfer_id];
        
        for (auto& chunk : inflight) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                               now - chunk->sent_time)
                               .count();

            // Timeout = 5 seconds + 100ms per retry
            int timeout_ms = 5000 + (chunk->retry_count * 100);

            if (elapsed > timeout_ms) {
                to_retransmit.push_back(chunk->chunk_id);
                chunk->retry_count++;
                // Move back to pending queue for re-sending
                pending.push_front(chunk);
            } else {
                remaining_inflight.push_back(chunk);
            }
        }
        
        inflight = std::move(remaining_inflight);
    }

    return to_retransmit;
}
