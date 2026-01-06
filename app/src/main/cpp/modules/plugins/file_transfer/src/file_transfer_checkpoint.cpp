#include "file_transfer_manager.h"
#include "logger.h"

#include <cstdio>
#include <fstream>

// ============================================================================
// CHECKPOINT / RESUME
// ============================================================================

bool FileTransferManager::save_checkpoint(const std::string& transfer_id) {
    // Note: m_transfers_mutex MUST be held by the caller.
    // std::lock_guard<std::mutex> lock(m_transfers_mutex);

    auto it = m_transfers.find(transfer_id);
    if (it == m_transfers.end()) {
        return false;
    }

    auto& session = it->second;

    try {
        // Write to a temporary file first to guarantee atomicity.
        std::string tmp_file = session->checkpoint_file + ".tmp";
        std::ofstream checkpoint(tmp_file, std::ios::binary);
        if (!checkpoint.is_open()) {
            LOG_WARN("FT: Cannot create checkpoint file: " + tmp_file);
            return false;
        }

        // Serialize checkpoint data.
        checkpoint.write(session->transfer_id.c_str(), session->transfer_id.length());
        checkpoint.put('\0');
        uint64_t bytes = session->bytes_transferred;
        checkpoint.write(reinterpret_cast<const char*>(&bytes), sizeof(bytes));
        uint32_t chunks = session->chunks_transferred;
        checkpoint.write(reinterpret_cast<const char*>(&chunks), sizeof(chunks));

        // Serialize completed_chunks vector
        uint32_t vec_size = static_cast<uint32_t>(session->completed_chunks.size());
        checkpoint.write(reinterpret_cast<const char*>(&vec_size), sizeof(vec_size));
        if (vec_size > 0) {
            checkpoint.write(reinterpret_cast<const char*>(session->completed_chunks.data()), 
                             vec_size * sizeof(uint32_t));
        }

        checkpoint.close();

        // Atomically replace the old checkpoint.
        // Use C std::rename for portability; it atomically replaces the target.
        std::rename(tmp_file.c_str(), session->checkpoint_file.c_str());

        // LOG_DEBUG("FT: Checkpoint saved for transfer " + transfer_id +
        //           " - " + std::to_string(session->bytes_transferred) + " bytes");
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
        checkpoint.read(reinterpret_cast<char*>(&result->bytes_transferred), sizeof(result->bytes_transferred));

        // Read chunks transferred
        checkpoint.read(reinterpret_cast<char*>(&result->chunks_transferred), sizeof(result->chunks_transferred));

        // Read completed_chunks vector
        uint32_t vec_size = 0;
        if (checkpoint.read(reinterpret_cast<char*>(&vec_size), sizeof(vec_size))) {
            result->completed_chunks.resize(vec_size);
            if (vec_size > 0) {
                checkpoint.read(reinterpret_cast<char*>(result->completed_chunks.data()), 
                                vec_size * sizeof(uint32_t));
            }
        }

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
