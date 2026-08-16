#ifndef ENGINE_HANDLER_H
#define ENGINE_HANDLER_H

#include "session_events.h"
#include "../../../corep2p/transport/include/connection_manager.h"
#include "../../../corep2p/transport/include/udp_connection_manager.h"
#include "battery_optimizer.h"
#include "session_cache.h"
#include "message_batcher.h"
#include "peer_index.h"
#include "peer_tier_manager.h"
#include "tier_system_failsafe.h"
#include "broadcast_discovery_manager.h"
#include "file_transfer_manager.h"
#if HAVE_NOISE_PROTOCOL
#include "secure_session.h"
#include "noise_nk.h"
#include "noise_key_store.h"
#endif
#include <vector>
#include <string>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <atomic>
#include <future>
#include <queue>

class EngineHandler {
public:
    EngineHandler();
    ~EngineHandler();

    bool start(int port, std::function<void(const std::vector<Peer>&)> cb, 
               const std::string& comms_mode, const std::string& peer_id);
    void stop();
    
    // Thread management
    bool startProcessingThreads();
    void stopProcessingThreads();
    
    // Component management
    bool initializeComponents();
    void cleanupComponents();
    void resetComponents();
    
    // State management
    bool isRunning() const { return m_running.load(); }
    bool isStopping() const { return m_stopping.load(); }
    void setForceStop(bool force) { m_force_stop = force; }
    
    // Component accessors
    ConnectionManager& getConnectionManager();
    UdpConnectionManager& getUdpConnectionManager();
    PeerIndex* getPeerIndex();
    PeerTierManager* getPeerTierManager();
    BroadcastDiscoveryManager* getBroadcastDiscoveryManager();
    FileTransferManager* getFileTransferManager();
    BatteryOptimizer* getBatteryOptimizer();
    SessionCache* getSessionCache();
    MessageBatcher* getMessageBatcher();
    
#if HAVE_NOISE_PROTOCOL
    SecureSessionManager* getSecureSessionManager();
    NoiseNKManager* getNoiseNKManager();
    NoiseKeyStore* getNoiseKeyStore();
#endif

private:
    // Communication mode
    enum class CommsMode { TCP, UDP };
    static CommsMode commsModeFromString(const std::string& mode);
    static std::string commsModeToString(CommsMode mode);
    
    // Thread functions
    void timerLoop();
    void processEventQueue();
    
    // Event handling
    void pushEvent(SessionEvent event);
    
    // Member variables
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_stopping{false};
    std::atomic<bool> m_force_stop{false};
    
    ConnectionManager m_tcpConnectionManager;
    UdpConnectionManager m_udpConnectionManager;
    CommsMode m_comms_mode{CommsMode::TCP};
    
    std::string m_localPeerId;
    std::function<void(const std::vector<Peer>&)> m_peer_update_cb;
    
    // Component management
    std::unique_ptr<PeerIndex> m_peer_index;
    std::unique_ptr<PeerTierManager> m_peer_tier_manager;
    std::unique_ptr<BroadcastDiscoveryManager> m_broadcast_discovery;
    std::unique_ptr<FileTransferManager> m_file_transfer_manager;
    std::unique_ptr<BatteryOptimizer> m_battery_optimizer;
    std::unique_ptr<SessionCache> m_session_cache;
    std::unique_ptr<MessageBatcher> m_message_batcher;
    std::unique_ptr<TierSystemFailsafe> m_failsafe;
    
#if HAVE_NOISE_PROTOCOL
    std::unique_ptr<SecureSessionManager> m_secure_session_manager;
    std::unique_ptr<NoiseNKManager> m_noise_nk_manager;
    std::unique_ptr<NoiseKeyStore> m_noise_key_store;
#endif

    // Thread management
    std::thread m_processingThread;
    std::thread m_timerThread;
    std::queue<SessionEvent> m_eventQueue;
    std::mutex m_eventMutex;
    std::condition_variable m_eventCv;
    
    // Background operations
    std::vector<std::future<void>> m_backgroundFutures;
    std::mutex m_backgroundFuturesMutex;
};

#endif // ENGINE_HANDLER_H