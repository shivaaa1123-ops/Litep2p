#include "file_transfer_manager.h"
#include "logger.h"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <thread>
#include <vector>

static int tests_failed = 0;

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "FAIL: " << msg << " [" << __FILE__ << ":" << __LINE__ << "]" << std::endl; \
            tests_failed++; \
            return false; \
        } \
    } while (0)

static std::vector<uint8_t> read_all_bytes(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in.is_open()) return {};
    in.seekg(0, std::ios::end);
    const auto n = static_cast<size_t>(in.tellg());
    in.seekg(0, std::ios::beg);
    std::vector<uint8_t> data(n);
    if (n > 0) in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(n));
    return data;
}

static bool write_random_file(const std::filesystem::path& p, size_t bytes, uint32_t seed) {
    std::ofstream out(p, std::ios::binary);
    if (!out.is_open()) return false;

    std::mt19937 rng(seed);
    std::uniform_int_distribution<int> dist(0, 255);

    std::vector<uint8_t> buf;
    buf.resize(64 * 1024);

    size_t remaining = bytes;
    while (remaining > 0) {
        const size_t chunk = std::min(remaining, buf.size());
        for (size_t i = 0; i < chunk; i++) {
            buf[i] = static_cast<uint8_t>(dist(rng));
        }
        out.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(chunk));
        remaining -= chunk;
    }

    out.flush();
    return static_cast<bool>(out);
}

static bool wait_for_state(FileTransferManager& mgr,
                           const std::string& transfer_id,
                           TransferState desired,
                           std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        auto s = mgr.get_transfer_status(transfer_id);
        if (s && s->state == desired) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
}

static bool test_roundtrip_basic(const std::filesystem::path& workdir) {
    const auto src = workdir / "src_basic.bin";
    const auto dst = workdir / "dst_basic.bin";

    std::error_code ec;
    std::filesystem::remove(src, ec);
    std::filesystem::remove(dst, ec);
    std::filesystem::remove(src.string() + ".checkpoint", ec);
    std::filesystem::remove(dst.string() + ".checkpoint", ec);
    std::filesystem::remove(dst.string() + ".part", ec);

    TEST_ASSERT(write_random_file(src, 512 * 1024, 123), "Failed to create source file");
    const uint64_t src_size = static_cast<uint64_t>(std::filesystem::file_size(src));

    FileTransferManager::TransferConfig cfg;
    cfg.initial_rate_limit_kbps = 100000; // 100 Mbps
    FileTransferManager sender(cfg);
    FileTransferManager receiver(cfg);

    // Register a dummy path to avoid "No available paths" warning and ensure optimal path selection works
    sender.register_network_path("peer-receiver", "peer-receiver", "127.0.0.1", 12345, 10, 10000);

    // Create transfer before wiring callbacks so no chunks are emitted until receiver is ready.
    const std::string transfer_id = sender.send_file(src.string(), "peer-receiver", "", 0);
    TEST_ASSERT(!transfer_id.empty(), "send_file returned empty transfer id");

    TEST_ASSERT(receiver.receive_file(transfer_id, dst.string(), "peer-sender", "", 0, src_size), "receive_file failed");

    sender.set_outbound_message_callback([&](const std::string&, const std::string& payload) {
        receiver.handle_incoming_message("peer-sender", payload);
    });

    receiver.set_outbound_message_callback([&](const std::string&, const std::string& payload) {
        sender.handle_incoming_message("peer-receiver", payload);
    });

    TEST_ASSERT(wait_for_state(receiver, transfer_id, TransferState::COMPLETED, std::chrono::seconds(10)),
                "Receiver did not complete in time");
    TEST_ASSERT(wait_for_state(sender, transfer_id, TransferState::COMPLETED, std::chrono::seconds(10)),
                "Sender did not complete in time");

    sender.stop();
    receiver.stop();

    TEST_ASSERT(std::filesystem::exists(dst), "Destination file missing after completion");

    const auto a = read_all_bytes(src);
    const auto b = read_all_bytes(dst);
    TEST_ASSERT(a == b, "Roundtrip contents mismatch");

    // Checkpoints should be cleared on success
    TEST_ASSERT(!std::filesystem::exists(src.string() + ".checkpoint"), "Sender checkpoint not cleared");
    TEST_ASSERT(!std::filesystem::exists(dst.string() + ".checkpoint"), "Receiver checkpoint not cleared");

    return true;
}

static bool test_roundtrip_resume(const std::filesystem::path& workdir) {
    const auto src = workdir / "src_resume.bin";
    const auto dst = workdir / "dst_resume.bin";

    std::error_code ec;
    std::filesystem::remove(src, ec);
    std::filesystem::remove(dst, ec);
    std::filesystem::remove(src.string() + ".checkpoint", ec);
    std::filesystem::remove(dst.string() + ".checkpoint", ec);
    std::filesystem::remove(dst.string() + ".part", ec);

    // Larger file to ensure we have time to pause mid-transfer.
    TEST_ASSERT(write_random_file(src, 4 * 1024 * 1024, 456), "Failed to create source file");
    const uint64_t src_size = static_cast<uint64_t>(std::filesystem::file_size(src));

    std::string transfer_id;

    {
        FileTransferManager::TransferConfig cfg;
        cfg.initial_rate_limit_kbps = 100000; // 100 Mbps
        FileTransferManager sender(cfg);
        FileTransferManager receiver(cfg);

        // Register a dummy path
        sender.register_network_path("peer-receiver", "peer-receiver", "127.0.0.1", 12345, 10, 10000);

        transfer_id = sender.send_file(src.string(), "peer-receiver", "", 0);
        TEST_ASSERT(!transfer_id.empty(), "send_file returned empty transfer id");
        TEST_ASSERT(receiver.receive_file(transfer_id, dst.string(), "peer-sender", "", 0, src_size), "receive_file failed");

        sender.set_outbound_message_callback([&](const std::string&, const std::string& payload) {
            receiver.handle_incoming_message("peer-sender", payload);
        });

        receiver.set_outbound_message_callback([&](const std::string&, const std::string& payload) {
            sender.handle_incoming_message("peer-receiver", payload);
        });

        // Wait for some progress.
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (std::chrono::steady_clock::now() < deadline) {
            auto s = receiver.get_transfer_status(transfer_id);
            if (s && s->bytes_transferred >= (128 * 1024)) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        TEST_ASSERT(sender.pause_transfer(transfer_id), "pause_transfer failed on sender");
        TEST_ASSERT(receiver.pause_transfer(transfer_id), "pause_transfer failed on receiver");

        sender.stop();
        receiver.stop();
    }

    // Verify checkpoint + part exist after pause.
    TEST_ASSERT(std::filesystem::exists(src.string() + ".checkpoint"), "Expected sender checkpoint after pause");
    TEST_ASSERT(std::filesystem::exists(dst.string() + ".checkpoint"), "Expected receiver checkpoint after pause");
    TEST_ASSERT(std::filesystem::exists(dst.string() + ".part"), "Expected receiver .part file after pause");

    {
        FileTransferManager::TransferConfig cfg;
        cfg.initial_rate_limit_kbps = 100000; // 100 Mbps
        FileTransferManager sender(cfg);
        FileTransferManager receiver(cfg);

        // Register a dummy path
        sender.register_network_path("peer-receiver", "peer-receiver", "127.0.0.1", 12345, 10, 10000);

        const std::string resumed_id = sender.send_file(src.string(), "peer-receiver", "", 0);
        TEST_ASSERT(resumed_id == transfer_id, "send_file did not reuse checkpoint transfer_id for resume");
        TEST_ASSERT(receiver.receive_file(resumed_id, dst.string(), "peer-sender", "", 0, src_size), "receive_file failed on resume");

        sender.set_outbound_message_callback([&](const std::string&, const std::string& payload) {
            receiver.handle_incoming_message("peer-sender", payload);
        });

        receiver.set_outbound_message_callback([&](const std::string&, const std::string& payload) {
            sender.handle_incoming_message("peer-receiver", payload);
        });

        TEST_ASSERT(wait_for_state(receiver, resumed_id, TransferState::COMPLETED, std::chrono::seconds(20)),
                    "Receiver did not complete in time (resume)");
        TEST_ASSERT(wait_for_state(sender, resumed_id, TransferState::COMPLETED, std::chrono::seconds(20)),
                    "Sender did not complete in time (resume)");

        sender.stop();
        receiver.stop();
    }

    TEST_ASSERT(std::filesystem::exists(dst), "Destination file missing after resume completion");

    const auto a = read_all_bytes(src);
    const auto b = read_all_bytes(dst);
    TEST_ASSERT(a == b, "Resume contents mismatch");

    TEST_ASSERT(!std::filesystem::exists(src.string() + ".checkpoint"), "Sender checkpoint not cleared after resume completion");
    TEST_ASSERT(!std::filesystem::exists(dst.string() + ".checkpoint"), "Receiver checkpoint not cleared after resume completion");
    TEST_ASSERT(!std::filesystem::exists(dst.string() + ".part"), "Receiver .part not removed/renamed after completion");

    return true;
}

int main() {
    set_log_level(LogLevel::DEBUG);
    const auto workdir = std::filesystem::temp_directory_path() / "litep2p_ft_tests";
    std::error_code ec;
    std::filesystem::create_directories(workdir, ec);

    std::cout << "--- FileTransferManager tests (" << workdir << ") ---" << std::endl;

    if (test_roundtrip_basic(workdir)) {
        std::cout << "PASS: basic roundtrip" << std::endl;
    }

    if (test_roundtrip_resume(workdir)) {
        std::cout << "PASS: resumable roundtrip" << std::endl;
    }

    if (tests_failed != 0) {
        std::cerr << "FAILED: " << tests_failed << " test(s)" << std::endl;
        return 1;
    }

    std::cout << "ALL PASS" << std::endl;
    return 0;
}
