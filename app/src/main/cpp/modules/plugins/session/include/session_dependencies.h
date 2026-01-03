#ifndef SESSION_DEPENDENCIES_H
#define SESSION_DEPENDENCIES_H

#include "peer.h"
#include "peer_index.h"
#include "battery_optimizer.h"
#include "session_cache.h"
#include "message_batcher.h"
#include "file_transfer_manager.h"
#include "event_manager.h"
#include "peer_tier_manager.h"
#include "broadcast_discovery_manager.h"
#include "tier_system_failsafe.h"
#include "itcp_connection_manager.h"
#include "iudp_connection_manager.h"
#include "../../../corep2p/transport/include/connection_manager.h"
#include "../../../corep2p/transport/include/udp_connection_manager.h"
#include <memory>
#include <string>
#include <vector>
#include <functional>

#if HAVE_NOISE_PROTOCOL
#include "secure_session.h"
#include "noise_nk.h"
#include "noise_key_store.h"
#endif

// Forward declarations
class Discovery;
class Constants;

// Factory interface for creating default implementations
class ISessionDependenciesFactory {
public:
    virtual ~ISessionDependenciesFactory() = default;
    
    virtual std::unique_ptr<PeerIndex> createPeerIndex() = 0;
    virtual std::unique_ptr<BatteryOptimizer> createBatteryOptimizer() = 0;
    virtual std::unique_ptr<SessionCache> createSessionCache() = 0;
    virtual std::unique_ptr<MessageBatcher> createMessageBatcher(int batchDelayMs, int maxMessages) = 0;
    virtual std::unique_ptr<FileTransferManager> createFileTransferManager() = 0;
    virtual std::unique_ptr<EventManager> createEventManager() = 0;
    virtual std::unique_ptr<PeerTierManager> createPeerTierManager() = 0;
    virtual std::unique_ptr<BroadcastDiscoveryManager> createBroadcastDiscoveryManager() = 0;
    virtual std::unique_ptr<TierSystemFailsafe> createTierSystemFailsafe() = 0;
    
    // Transport manager factory methods
    virtual std::unique_ptr<ITcpConnectionManager> createTcpConnectionManager() = 0;
    virtual std::unique_ptr<IUdpConnectionManager> createUdpConnectionManager() = 0;
    
#if HAVE_NOISE_PROTOCOL
    virtual std::unique_ptr<SecureSessionManager> createSecureSessionManager() = 0;
    virtual std::unique_ptr<NoiseNKManager> createNoiseNKManager() = 0;
    virtual std::unique_ptr<NoiseKeyStore> createNoiseKeyStore() = 0;
#endif
};

// Default factory implementation
class DefaultSessionDependenciesFactory : public ISessionDependenciesFactory {
private:
    int m_batchDelayMs;
    int m_maxMessages;
    
public:
    DefaultSessionDependenciesFactory(int batchDelayMs = 100, int maxMessages = 10) 
        : m_batchDelayMs(batchDelayMs), m_maxMessages(maxMessages) {}
    
    std::unique_ptr<PeerIndex> createPeerIndex() override {
        return std::make_unique<PeerIndex>();
    }
    
    std::unique_ptr<BatteryOptimizer> createBatteryOptimizer() override {
        return std::make_unique<BatteryOptimizer>();
    }
    
    std::unique_ptr<SessionCache> createSessionCache() override {
        return std::make_unique<SessionCache>();
    }
    
    std::unique_ptr<MessageBatcher> createMessageBatcher(int batchDelayMs, int maxMessages) override {
        return std::make_unique<MessageBatcher>(batchDelayMs, maxMessages);
    }
    
    std::unique_ptr<FileTransferManager> createFileTransferManager() override {
        return std::make_unique<FileTransferManager>(FileTransferManager::TransferConfig(100, 32));
    }
    
    std::unique_ptr<EventManager> createEventManager() override {
        return std::make_unique<EventManager>();
    }
    
    std::unique_ptr<PeerTierManager> createPeerTierManager() override {
        return std::make_unique<PeerTierManager>();
    }
    
    std::unique_ptr<BroadcastDiscoveryManager> createBroadcastDiscoveryManager() override {
        return std::make_unique<BroadcastDiscoveryManager>();
    }
    
    std::unique_ptr<TierSystemFailsafe> createTierSystemFailsafe() override {
        return std::make_unique<TierSystemFailsafe>();
    }
    
#if HAVE_NOISE_PROTOCOL
    std::unique_ptr<SecureSessionManager> createSecureSessionManager() override {
        return std::make_unique<SecureSessionManager>();
    }
    
    std::unique_ptr<NoiseNKManager> createNoiseNKManager() override {
        return std::make_unique<NoiseNKManager>();
    }
    
    std::unique_ptr<NoiseKeyStore> createNoiseKeyStore() override {
        return std::make_unique<NoiseKeyStore>();
    }
#endif
    
    // Transport manager factory methods
    std::unique_ptr<ITcpConnectionManager> createTcpConnectionManager() override {
        return std::make_unique<ConnectionManager>();
    }
    
    std::unique_ptr<IUdpConnectionManager> createUdpConnectionManager() override {
        return std::make_unique<UdpConnectionManager>();
    }
};

#endif // SESSION_DEPENDENCIES_H