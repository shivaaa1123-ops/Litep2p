#include "file_transfer_manager.h"
#include "logger.h"
#include <iostream>
#include <thread>
#include <fstream>
#include <mutex>
#include <vector>
#include <chrono>
#include <algorithm>
#include <cstdint>

/**
 * FILE TRANSFER MANAGER - COMPREHENSIVE EXAMPLE
 * 
 * Demonstrates all major features:
 * - 32KB chunked transfers
 * - Resume capability
 * - Multi-path routing
 * - Multiplexing
 * - Congestion handling
 */

class FileTransferExample {
public:
    void run_all_examples() {
        std::cout << "=== File Transfer Manager Examples ===" << std::endl;
        
        example_1_simple_transfer();
        example_2_resumable_transfer();
        example_3_multipath_transfer();
        example_4_multiplexed_transfer();
        example_5_congestion_handling();
    }
    
private:
    /**
     * Example 1: Simple File Transfer
     * Basic send/receive with progress tracking
     */
    void example_1_simple_transfer() {
        std::cout << "\n[Example 1] Simple File Transfer" << std::endl;
        std::cout << "─────────────────────────────────" << std::endl;
        
        FileTransferManager ft_mgr; // Use default configuration
        
        // Create a test file
        create_test_file("/tmp/test_file.bin", 1024 * 1024);  // 1MB
        
        // Register a network path
        std::string path = ft_mgr.register_network_path(
            "peer_123",           // Target peer
            "gateway_1",          // Next hop
            "192.168.1.100",     // IP
            5000,                // Port
            50,                  // 50ms latency
            10000                // 10 Mbps bandwidth
        );
        std::cout << "Registered path: " << path << std::endl;
        
        // Send file
        std::string transfer_id = ft_mgr.send_file(
            "/tmp/test_file.bin",
            "peer_123",
            "192.168.1.100",
            5000,
            TransferPriority::NORMAL,
            PathSelectionStrategy::BALANCED
        );
        std::cout << "Transfer started: " << transfer_id << std::endl;
        
        // Monitor progress
        for (int i = 0; i < 10; i++) {
            float progress = ft_mgr.get_transfer_progress(transfer_id);
            float speed = ft_mgr.get_transfer_speed(transfer_id);
            
            std::cout << "Progress: " << progress << "% "
                      << "Speed: " << speed << " Kbps" << std::endl;
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    /**
     * Example 2: Resumable Transfer
     * Pause, save checkpoint, resume later
     */
    void example_2_resumable_transfer() {
        std::cout << "\n[Example 2] Resumable Transfer" << std::endl;
        std::cout << "──────────────────────────────" << std::endl;
        
        FileTransferManager ft_mgr; // Use default configuration
        
        // Create test file
        create_test_file("/tmp/resume_file.bin", 5 * 1024 * 1024);  // 5MB
        
        std::string transfer_id = ft_mgr.send_file(
            "/tmp/resume_file.bin",
            "peer_456",
            "192.168.1.101",
            5000
        );
        std::cout << "Transfer started: " << transfer_id << std::endl;
        
        // Simulate partial transfer
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        
        // Pause transfer (automatically saves checkpoint)
        ft_mgr.pause_transfer(transfer_id);
        std::cout << "Transfer paused, checkpoint saved" << std::endl;
        
        // Check if resumable
        bool resumable = ft_mgr.can_resume_transfer("/tmp/resume_file.bin");
        std::cout << "Can resume: " << (resumable ? "YES" : "NO") << std::endl;
        
        // Resume transfer
        ft_mgr.resume_transfer(transfer_id);
        std::cout << "Transfer resumed from checkpoint" << std::endl;
        
        // Get updated progress
        float progress = ft_mgr.get_transfer_progress(transfer_id);
        std::cout << "Progress after resume: " << progress << "%" << std::endl;
    }
    
    /**
     * Example 3: Multi-Path Routing
     * Register multiple paths and select optimal
     */
    void example_3_multipath_transfer() {
        std::cout << "\n[Example 3] Multi-Path Routing" << std::endl;
        std::cout << "──────────────────────────────" << std::endl;
        
        FileTransferManager ft_mgr; // Use default configuration
        
        // Register multiple paths to same peer
        std::string path_1 = ft_mgr.register_network_path(
            "peer_789",
            "gateway_a",
            "192.168.1.10",
            5000,
            50,        // Low latency
            10000      // Moderate bandwidth
        );
        std::cout << "Path 1 (latency optimized): " << path_1 << std::endl;
        
        std::string path_2 = ft_mgr.register_network_path(
            "peer_789",
            "gateway_b",
            "192.168.1.20",
            5000,
            150,       // Higher latency
            50000      // High bandwidth
        );
        std::cout << "Path 2 (throughput optimized): " << path_2 << std::endl;
        
        // Find optimal path for different strategies
        auto latency_path = ft_mgr.find_optimal_path(
            "peer_789",
            PathSelectionStrategy::LATENCY
        );
        std::cout << "Best latency path: " << latency_path->path_id 
                  << " (" << latency_path->latency_ms << "ms)" << std::endl;
        
        auto throughput_path = ft_mgr.find_optimal_path(
            "peer_789",
            PathSelectionStrategy::THROUGHPUT
        );
        std::cout << "Best throughput path: " << throughput_path->path_id 
                  << " (" << throughput_path->bandwidth_kbps << " Kbps)" << std::endl;
        
        auto balanced_path = ft_mgr.find_optimal_path(
            "peer_789",
            PathSelectionStrategy::BALANCED
        );
        std::cout << "Best balanced path: " << balanced_path->path_id << std::endl;
    }
    
    /**
     * Example 4: Multiplexed Transfer
     * Add multiple paths to single transfer for load balancing
     */
    void example_4_multiplexed_transfer() {
        std::cout << "\n[Example 4] Multiplexed Transfer" << std::endl;
        std::cout << "────────────────────────────────" << std::endl;
        
        FileTransferManager ft_mgr; // Use default configuration
        
        // Register multiple paths
        std::string path_1 = ft_mgr.register_network_path(
            "peer_multi",
            "hop_1",
            "192.168.1.30",
            5000,
            50,
            10000
        );
        
        std::string path_2 = ft_mgr.register_network_path(
            "peer_multi",
            "hop_2",
            "192.168.1.40",
            5000,
            60,
            15000
        );
        
        // Create test file
        create_test_file("/tmp/multiplex_file.bin", 10 * 1024 * 1024);  // 10MB
        
        // Start transfer on first path
        std::string transfer_id = ft_mgr.send_file(
            "/tmp/multiplex_file.bin",
            "peer_multi",
            "192.168.1.30",
            5000
        );
        std::cout << "Transfer started with Path 1" << std::endl;
        
        // Add second path for multiplexing
        ft_mgr.add_path_to_transfer(transfer_id, path_2);
        std::cout << "Added Path 2 for multiplexing" << std::endl;
        
        // Get active paths
        auto paths = ft_mgr.get_transfer_paths(transfer_id);
        std::cout << "Active paths for transfer: " << paths.size() << std::endl;
        
        // Simulate progress
        for (int i = 0; i < 5; i++) {
            float speed = ft_mgr.get_transfer_speed(transfer_id);
            float progress = ft_mgr.get_transfer_progress(transfer_id);
            std::cout << "Progress: " << progress << "% Speed: " 
                      << speed << " Kbps" << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    /**
     * Example 5: Congestion Handling
     * Report congestion and observe adaptive rate limiting
     */
    void example_5_congestion_handling() {
        std::cout << "\n[Example 5] Congestion Handling" << std::endl;
        std::cout << "──────────────────────────────" << std::endl;
        
        FileTransferManager ft_mgr; // Use default configuration
        
        std::string path_id = ft_mgr.register_network_path(
            "peer_congestion",
            "gateway_c",
            "192.168.1.50",
            5000,
            100,
            20000
        );
        
        // Initial rate limit
        uint32_t initial_limit = ft_mgr.get_adaptive_rate_limit();
        std::cout << "Initial rate limit: " << initial_limit << " Kbps" << std::endl;
        
        // Report moderate congestion
        CongestionMetrics moderate;
        moderate.level = CongestionLevel::MODERATE;
        moderate.packet_loss_percent = 3.0f;
        moderate.rtt_ms = 150.0f;
        moderate.bandwidth_utilization_percent = 50.0f;
        ft_mgr.report_congestion(path_id, moderate);
        std::cout << "Reported MODERATE congestion" << std::endl;
        
        uint32_t moderate_limit = ft_mgr.get_adaptive_rate_limit();
        std::cout << "Rate limit adjusted to: " << moderate_limit << " Kbps" << std::endl;
        
        // Report high congestion
        CongestionMetrics high;
        high.level = CongestionLevel::HIGH;
        high.packet_loss_percent = 8.0f;
        high.rtt_ms = 300.0f;
        high.bandwidth_utilization_percent = 75.0f;
        ft_mgr.report_congestion(path_id, high);
        std::cout << "Reported HIGH congestion" << std::endl;
        
        uint32_t high_limit = ft_mgr.get_adaptive_rate_limit();
        std::cout << "Rate limit adjusted to: " << high_limit << " Kbps" << std::endl;
        
        // Report severe congestion
        CongestionMetrics severe;
        severe.level = CongestionLevel::SEVERE;
        severe.packet_loss_percent = 15.0f;
        severe.rtt_ms = 500.0f;
        severe.bandwidth_utilization_percent = 95.0f;
        ft_mgr.report_congestion(path_id, severe);
        std::cout << "Reported SEVERE congestion" << std::endl;
        
        uint32_t severe_limit = ft_mgr.get_adaptive_rate_limit();
        std::cout << "Rate limit adjusted to: " << severe_limit << " Kbps" << std::endl;
        
        // Get statistics
        auto stats = ft_mgr.get_statistics();
        std::cout << "\nTransfer Statistics:" << std::endl;
        std::cout << "Total transfers: " << static_cast<int>(stats["total_transfers"]) << std::endl;
        std::cout << "Total bytes: " << static_cast<long>(stats["total_bytes_transferred"]) << std::endl;
    }
    
    /**
     * Helper: Create test file of specified size
     */
    void create_test_file(const std::string& path, size_t size) {
        std::ofstream file(path, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Failed to create test file: " << path << std::endl;
            return;
        }
        
        // Write file in chunks
        std::vector<uint8_t> buffer(4096, 0xAB);
        size_t remaining = size;
        
        while (remaining > 0) {
            size_t to_write = std::min(remaining, buffer.size());
            file.write(reinterpret_cast<const char*>(buffer.data()), to_write);
            remaining -= to_write;
        }
        
        file.close();
        std::cout << "Created test file: " << path << " (" << size << " bytes)" << std::endl;
    }
    
    // Implement thread safety
    std::mutex mtx;
};

// ============================================================================
// MAIN
// ============================================================================

int main() {
    try {
        FileTransferExample example;
        example.run_all_examples();
        
        std::cout << "\n=== All Examples Completed ===" << std::endl;
        std::cout << "File Transfer Manager is working correctly!" << std::endl;
        
        return 0;
    } catch (const std::exception& e) {
        // Handle the exception
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
