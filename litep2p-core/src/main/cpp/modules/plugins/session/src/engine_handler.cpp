#include "engine_handler.h"
#include "../../../corep2p/core/include/logger.h"
#include "../../../corep2p/core/include/constants.h"
#include "discovery.h"
#include "peer_reconnect_policy.h"
#include <chrono>
#include <thread>
#include <algorithm>

EngineHandler::EngineHandler()
    : m_running(false), m_stopping(false), m_force_stop(false),
      m_peer_index(std::make_unique<PeerIndex>()),
      m_battery_optimizer(std::make_unique<BatteryOptimizer>()),
      m_session_cache(std::make_unique<SessionCache>()),
      m_message_batcher(std::make_unique<MessageBatcher>(BATCH_DELAY_MS, BATCH_MAX_MESSAGES)),
      m_failsafe(std::make_unique<TierSystemFailsafe>()),
      m_peer_tier_manager(nullptr),
      m_broadcast_discovery(nullptr),
      m_file_transfer_manager(std::make_unique<FileTransferManager>(FileTransferManager::TransferConfig())) {
    
    m_battery_optimizer->set_optimization_level(BatteryOptimizer::OptimizationLevel::BALANCED);
    LOG_INFO("EH: Battery optimization enabled (BALANCED mode)");
    
    PeerReconnectPolicy& policy = PeerReconnectPolicy::getInstance();
    policy.initialize(100, true);
    LOG_INFO("EH: Reconnect policy initialized");
    
#if HAVE_NOISE_PROTOCOL
    m_secure_session_manager = std::make_unique<SecureSessionManager>();
    m_noise_nk_manager = std::make_unique<NoiseNKManager>();
    m_noise_key_store = std::make_unique<NoiseKeyStore>();
    m_noise_key_store->initialize();
    LOG_INFO("EH: Noise Protocol support enabled");
#else
    LOG_INFO("EH: Noise Protocol not available");
#endif
}

EngineHandler::~EngineHandler() {
    stop();
}

EngineHandler::CommsMode EngineHandler::commsModeFromString(const std::string& mode) {
    if (mode == "TCP" || mode == "tcp") return CommsMode::TCP;
    return CommsMode::UDP; // default/fallback
}

std::string EngineHandler::commsModeToString(CommsMode mode) {
    return (mode == CommsMode::TCP) ? "TCP" : "UDP";
}

bool EngineHandler::start(int port, std::function<void(const std::vector<Peer>&)> cb, 
                          const std::string& comms_mode, const std::string& peer_id) {
    auto start_time = std::chrono::steady_clock::now();
    LOG_INFO("EH: Starting engine handler - checking current state...");
    LOG_INFO("EH: [DIAG] m_running=" + std::to_string(m_running.load()) + ", m_stopping=" + std::to_string(m_stopping.load()));

    // Safety check: Ensure we're in a clean state
    if (m_running) {
        LOG_WARN("EH: Engine handler already running, ignoring start request.");
        return false;
    }

    // Reset stopping flag in case previous shutdown was incomplete
    m_stopping = false;
    LOG_INFO("EH: [DIAG] m_stopping reset to false at start()");

    // Ensure complete cleanup of previous state before starting
    resetComponents();
    
    auto cleanup_time = std::chrono::steady_clock::now();
    auto cleanup_duration = std::chrono::duration_cast<std::chrono::milliseconds>(cleanup_time - start_time);
    LOG_INFO("EH: Cleanup completed in " + std::to_string(cleanup_duration.count()) + "ms");
    
    // Reset the running flag for the new session
    m_running = true;
    m_stopping = false;
    m_force_stop = false;
    
    LOG_INFO("EH: Initializing engine handler components...");
    m_peer_update_cb = cb;
    m_comms_mode = commsModeFromString(comms_mode);
    m_localPeerId = peer_id;
    
    auto init_start_time = std::chrono::steady_clock::now();
    
    // Initialize components with proper error handling
    if (!initializeComponents()) {
        LOG_WARN("EH: Failed to initialize components");
        m_running = false;
        return false;
    }
    
    auto init_end_time = std::chrono::steady_clock::now();
    auto init_duration = std::chrono::duration_cast<std::chrono::milliseconds>(init_end_time - init_start_time);
    LOG_INFO("EH: Component initialization completed in " + std::to_string(init_duration.count()) + "ms");
    
    // Start the low-level UDP discovery service with timeout handling
    LOG_INFO("EH: Starting discovery service...");
    try {
        Discovery* discovery = getGlobalDiscoveryInstance();
        if (discovery) {
            discovery->start(port, peer_id);
            LOG_INFO("EH: Discovery service started");
        } else {
            LOG_WARN("EH: Failed to get global discovery instance");
        }
    } catch (const std::exception& e) {
        LOG_WARN("EH: Exception during discovery service start: " + std::string(e.what()));
    } catch (...) {
        LOG_WARN("EH: Unknown exception during discovery service start");
    }
    
    LOG_INFO("EH: Starting engine handler on port " + std::to_string(port));
    LOG_INFO("EH: Comms mode: " + comms_mode);
    
    // Start connection manager
    bool connection_manager_started = false;
    try {
        if (m_comms_mode == CommsMode::TCP) {
            LOG_INFO("EH: Starting TCP connection manager...");
            connection_manager_started = m_tcpConnectionManager.startServer(port, nullptr, nullptr);
            if (connection_manager_started) {
                LOG_INFO("EH: TCP connection manager started successfully");
            } else {
                LOG_WARN("EH: Failed to start TCP connection manager");
            }
        } else {
            LOG_INFO("EH: Starting UDP connection manager...");
            connection_manager_started = m_udpConnectionManager.startServer(port, nullptr, nullptr);
            if (connection_manager_started) {
                LOG_INFO("EH: UDP connection manager started successfully");
            } else {
                LOG_WARN("EH: Failed to start UDP connection manager");
            }
        }
    } catch (const std::exception& e) {
        LOG_WARN("EH: Exception during connection manager start: " + std::string(e.what()));
        connection_manager_started = false;
    } catch (...) {
        LOG_WARN("EH: Unknown exception during connection manager start");
        connection_manager_started = false;
    }
    
    // If connection manager failed to start, don't proceed
    if (!connection_manager_started) {
        LOG_WARN("EH: Connection manager failed to start, stopping engine handler");
        m_running = false;
        m_eventCv.notify_all();
        return false;
    }
    
    // Start processing threads
    if (!startProcessingThreads()) {
        LOG_WARN("EH: Failed to start processing threads");
        m_running = false;
        m_eventCv.notify_all();
        return false;
    }
    
    LOG_INFO("EH: Engine handler started successfully");
    auto total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time);
    LOG_INFO("EH: Total startup time: " + std::to_string(total_duration.count()) + "ms");
    return true;
}

void EngineHandler::stop() {
    LOG_INFO("EH: [STOP_SEQ] Initiating stop sequence...");
    
    if (m_stopping.exchange(true)) {
        LOG_WARN("EH: [STOP_SEQ] Stop sequence already in progress.");
        return;
    }

    if (!m_running.exchange(false)) {
        LOG_WARN("EH: [STOP_SEQ] Engine was not running, but forcing cleanup.");
        m_stopping = false;
        return;
    }

    LOG_INFO("EH: [STOP_SEQ] Waking up all threads...");
    m_eventCv.notify_all();

    try {
        LOG_INFO("EH: [STOP_SEQ] Stopping Discovery service...");
        Discovery* discovery = getGlobalDiscoveryInstance();
        if (discovery) {
            discovery->stop();
        }
        LOG_INFO("EH: [STOP_SEQ] Discovery service stop command issued.");

        LOG_INFO("EH: [STOP_SEQ] Stopping Connection Managers...");
        if (m_comms_mode == CommsMode::TCP) {
            m_tcpConnectionManager.stop();
        } else {
            m_udpConnectionManager.stop();
        }
        LOG_INFO("EH: [STOP_SEQ] Connection Managers stop command issued.");

        LOG_INFO("EH: [STOP_SEQ] Stopping processing threads...");
        stopProcessingThreads();
        LOG_INFO("EH: [STOP_SEQ] All processing threads stopped.");

        LOG_INFO("EH: [STOP_SEQ] Cleaning up components...");
        cleanupComponents();
        LOG_INFO("EH: [STOP_SEQ] Components cleaned up.");

    } catch (const std::exception& e) {
        LOG_WARN("EH: [STOP_SEQ] EXCEPTION during stop sequence: " + std::string(e.what()));
    } catch (...) {
        LOG_WARN("EH: [STOP_SEQ] UNKNOWN EXCEPTION during stop sequence.");
    }
    
    m_stopping = false;
    LOG_INFO("EH: [STOP_SEQ] Stop sequence complete.");
}

bool EngineHandler::initializeComponents() {
    try {
        LOG_INFO("EH: Initializing PeerTierManager...");
        m_peer_tier_manager = std::make_unique<PeerTierManager>();
        
        LOG_INFO("EH: Initializing BroadcastDiscoveryManager...");
        m_broadcast_discovery = std::make_unique<BroadcastDiscoveryManager>();
        
        LOG_INFO("EH: Initializing other components...");
        m_file_transfer_manager = std::make_unique<FileTransferManager>(FileTransferManager::TransferConfig());
        m_session_cache = std::make_unique<SessionCache>();
        m_message_batcher = std::make_unique<MessageBatcher>(BATCH_DELAY_MS, BATCH_MAX_MESSAGES);
        m_peer_index = std::make_unique<PeerIndex>();
        m_battery_optimizer = std::make_unique<BatteryOptimizer>();
        m_battery_optimizer->set_optimization_level(BatteryOptimizer::OptimizationLevel::BALANCED);
        m_failsafe = std::make_unique<TierSystemFailsafe>();
        
#if HAVE_NOISE_PROTOCOL
        m_secure_session_manager = std::make_unique<SecureSessionManager>();
        m_noise_nk_manager = std::make_unique<NoiseNKManager>();
        m_noise_key_store = std::make_unique<NoiseKeyStore>();
        m_noise_key_store->initialize();
#endif
        
        // Initialize peer reconnect policy
        PeerReconnectPolicy& policy = PeerReconnectPolicy::getInstance();
        policy.initialize(100, true);
        
        return true;
    } catch (const std::exception& e) {
        LOG_WARN("EH: Failed to initialize components: " + std::string(e.what()));
        return false;
    } catch (...) {
        LOG_WARN("EH: Unknown error during component initialization");
        return false;
    }
}

void EngineHandler::cleanupComponents() {
    LOG_INFO("EH: Cleaning up components...");
    
    // Reset unique pointers to ensure clean state
    m_broadcast_discovery.reset();
    m_peer_tier_manager.reset();
    m_file_transfer_manager.reset();
    m_session_cache.reset();
    m_message_batcher.reset();
    m_peer_index.reset();
    m_battery_optimizer.reset();
    m_failsafe.reset();
    
#if HAVE_NOISE_PROTOCOL
    m_secure_session_manager.reset();
    m_noise_nk_manager.reset();
    m_noise_key_store.reset();
#endif
}

void EngineHandler::resetComponents() {
    LOG_INFO("EH: Resetting components...");
    
    // Clear all data structures
    {
        std::lock_guard<std::mutex> lock(m_eventMutex);
        while (!m_eventQueue.empty()) {
            m_eventQueue.pop();
        }
    }
    
    // Clear background futures
    {
        std::lock_guard<std::mutex> lock(m_backgroundFuturesMutex);
        m_backgroundFutures.clear();
    }
    
    // Reset components
    cleanupComponents();
    
    // Reinitialize basic components
    m_peer_index = std::make_unique<PeerIndex>();
    m_battery_optimizer = std::make_unique<BatteryOptimizer>();
    m_session_cache = std::make_unique<SessionCache>();
    m_message_batcher = std::make_unique<MessageBatcher>(BATCH_DELAY_MS, BATCH_MAX_MESSAGES);
    m_failsafe = std::make_unique<TierSystemFailsafe>();
    m_file_transfer_manager = std::make_unique<FileTransferManager>(FileTransferManager::TransferConfig());
}

bool EngineHandler::startProcessingThreads() {
    LOG_INFO("EH: Starting processing threads...");
    
    try {
        m_processingThread = std::thread([this] { processEventQueue(); });
        m_timerThread = std::thread([this] { timerLoop(); });
        LOG_INFO("EH: New processing threads started successfully");
        return true;
    } catch (const std::exception& e) {
        LOG_WARN("EH: Failed to start processing threads: " + std::string(e.what()));
        return false;
    } catch (...) {
        LOG_WARN("EH: Unknown error starting processing threads");
        return false;
    }
}

void EngineHandler::stopProcessingThreads() {
    LOG_INFO("EH: [STOP_SEQ] Joining timer thread...");
    try {
        if (m_timerThread.joinable()) {
            m_timerThread.join();
            LOG_INFO("EH: [STOP_SEQ] Timer thread joined successfully.");
        } else {
            LOG_INFO("EH: [STOP_SEQ] Timer thread was not joinable.");
        }
    } catch (const std::exception& e) {
        LOG_WARN("EH: [STOP_SEQ] EXCEPTION while joining timer thread: " + std::string(e.what()));
    } catch (...) {
        LOG_WARN("EH: [STOP_SEQ] UNKNOWN EXCEPTION while joining timer thread.");
    }

    LOG_INFO("EH: [STOP_SEQ] Joining processing thread...");
    try {
        if (m_processingThread.joinable()) {
            m_processingThread.join();
            LOG_INFO("EH: [STOP_SEQ] Processing thread joined successfully.");
        } else {
            LOG_INFO("EH: [STOP_SEQ] Processing thread was not joinable.");
        }
    } catch (const std::exception& e) {
        LOG_WARN("EH: [STOP_SEQ] EXCEPTION while joining processing thread: " + std::string(e.what()));
    } catch (...) {
        LOG_WARN("EH: [STOP_SEQ] UNKNOWN EXCEPTION while joining processing thread.");
    }
}

void EngineHandler::pushEvent(SessionEvent event) {
    std::lock_guard<std::mutex> lock(m_eventMutex);
    m_eventQueue.push(std::move(event));
    m_eventCv.notify_one();
}

void EngineHandler::timerLoop() {
    while (m_running) {
        // Use an interruptible wait so stop() doesn't have to wait up to 1s.
        std::unique_lock<std::mutex> lock(m_eventMutex);
        m_eventCv.wait_for(lock, std::chrono::seconds(1), [this] {
            return !m_running.load();
        });

        if (!m_running) {
            break;
        }

        // pushEvent locks m_eventMutex internally; release before calling.
        lock.unlock();
        pushEvent(TimerTickEvent{});
    }
}

void EngineHandler::processEventQueue() {
    while (m_running) {
        std::unique_lock<std::mutex> lock(m_eventMutex);
        m_eventCv.wait(lock, [this] { return !m_eventQueue.empty() || !m_running; });
        
        if (!m_running) break;
        
        if (!m_eventQueue.empty()) {
            SessionEvent event = std::move(m_eventQueue.front());
            m_eventQueue.pop();
            lock.unlock();
            
            // Process the event (placeholder - actual event processing would be implemented here)
            // std::visit([this](auto& e) { /* process event */ }, event);
        }
    }
}

// Component accessors
ConnectionManager& EngineHandler::getConnectionManager() { return m_tcpConnectionManager; }
UdpConnectionManager& EngineHandler::getUdpConnectionManager() { return m_udpConnectionManager; }
PeerIndex* EngineHandler::getPeerIndex() { return m_peer_index.get(); }
PeerTierManager* EngineHandler::getPeerTierManager() { return m_peer_tier_manager.get(); }
BroadcastDiscoveryManager* EngineHandler::getBroadcastDiscoveryManager() { return m_broadcast_discovery.get(); }
FileTransferManager* EngineHandler::getFileTransferManager() { return m_file_transfer_manager.get(); }
BatteryOptimizer* EngineHandler::getBatteryOptimizer() { return m_battery_optimizer.get(); }
SessionCache* EngineHandler::getSessionCache() { return m_session_cache.get(); }
MessageBatcher* EngineHandler::getMessageBatcher() { return m_message_batcher.get(); }

#if HAVE_NOISE_PROTOCOL
SecureSessionManager* EngineHandler::getSecureSessionManager() { return m_secure_session_manager.get(); }
NoiseNKManager* EngineHandler::getNoiseNKManager() { return m_noise_nk_manager.get(); }
NoiseKeyStore* EngineHandler::getNoiseKeyStore() { return m_noise_key_store.get(); }
#endif
