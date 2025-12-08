# SessionManager Integration Guide for Noise Protocol

## Quick Start

Follow these steps to integrate Noise Protocol into your existing SessionManager.

## Step 1: Update SessionManager Header

Edit `include/session_manager.h`:

```cpp
#include "secure_session.h"
#include <memory>

class SessionManager {
public:
    // ... existing methods ...
    
private:
    class Impl {
        // ... existing members ...
        std::unique_ptr<SecureSessionManager> m_secure_session_manager;
        bool m_use_noise_protocol = true; // Feature flag
        
        void initializeSecureSessions() {
            m_secure_session_manager = std::make_unique<SecureSessionManager>();
        }
    };
};
```

## Step 2: Update SessionManager Constructor

In `src/session_manager.cpp`:

```cpp
SessionManager::Impl::Impl(/* ... */)
    : m_udpConnectionManager(jniCallback),
      m_timerExpired(false) {
    
    // Initialize secure session manager
    m_secure_session_manager = std::make_unique<SecureSessionManager>();
    LOG_I("SessionManager", "Noise Protocol initialized");
}
```

## Step 3: Update onData Handler

Replace the current message handling with Noise-aware decryption:

```cpp
void SessionManager::Impl::onData(const std::string& peerId, const std::string& data) {
    if (!m_use_noise_protocol) {
        // Fallback to legacy AES
        std::string plaintext = crypto_utils_decrypt_message(data);
        processApplicationData(peerId, plaintext);
        return;
    }
    
    // Use Noise Protocol
    auto session = m_secure_session_manager->get_session(peerId);
    if (!session) {
        LOG_W("SessionManager", "No Noise session for peer: %s", peerId.c_str());
        return;
    }
    
    if (!session->is_ready()) {
        // Still in handshake phase
        std::string response = session->process_handshake(data);
        if (!response.empty()) {
            // Send handshake response
            m_tcpConnectionManager->sendMessageToPeer(peerId, response);
        }
        return;
    }
    
    // Session ready - decrypt message
    try {
        std::string plaintext = session->receive_message(data);
        processApplicationData(peerId, plaintext);
    } catch (const std::exception& e) {
        LOG_E("SessionManager", "Decryption failed: %s", e.what());
    }
}
```

## Step 4: Update sendMessageToPeer

Modify the send path to encrypt with Noise:

```cpp
void SessionManager::Impl::sendMessageToPeer(
    const std::string& peerId,
    const std::string& message) {
    
    if (!m_use_noise_protocol) {
        // Fallback to legacy AES
        std::string encrypted = crypto_utils_encrypt_message(message);
        m_tcpConnectionManager->sendMessageToPeer(peerId, encrypted);
        return;
    }
    
    // Get or create secure session
    auto session = m_secure_session_manager->get_or_create_session(
        peerId,
        NoiseSession::Role::INITIATOR  // Assume we initiate for outgoing messages
    );
    
    if (!session->is_ready()) {
        // Handshake not complete - queue message and start handshake
        queueMessageForPeer(peerId, message);
        
        std::string handshake = session->start_handshake();
        m_tcpConnectionManager->sendMessageToPeer(peerId, handshake);
        return;
    }
    
    // Encrypt and send
    try {
        std::string ciphertext = session->send_message(message);
        m_tcpConnectionManager->sendMessageToPeer(peerId, ciphertext);
    } catch (const std::exception& e) {
        LOG_E("SessionManager", "Encryption failed: %s", e.what());
    }
}
```

## Step 5: Add Handshake on New Connection

When a peer connects, initiate Noise handshake:

```cpp
void SessionManager::Impl::onPeerDiscovered(const std::string& peerId, const std::string& address) {
    LOG_I("SessionManager", "Peer discovered: %s at %s", peerId.c_str(), address.c_str());
    
    // Existing peer management
    m_peers[peerId] = {peerId, true};
    
    // NEW: Start Noise handshake
    if (m_use_noise_protocol) {
        auto session = m_secure_session_manager->get_or_create_session(
            peerId,
            NoiseSession::Role::INITIATOR
        );
        
        std::string handshake = session->start_handshake();
        m_tcpConnectionManager->sendMessageToPeer(peerId, handshake);
        
        LOG_I("SessionManager", "Noise handshake initiated for peer: %s", peerId.c_str());
    }
}
```

## Step 6: Add Message Queuing (Optional)

While handshake is in progress, queue messages:

```cpp
private:
    class Impl {
        std::map<std::string, std::vector<std::string>> m_pending_messages;
        
        void queueMessageForPeer(const std::string& peerId, const std::string& message) {
            m_pending_messages[peerId].push_back(message);
        }
        
        void flushQueuedMessages(const std::string& peerId) {
            auto it = m_pending_messages.find(peerId);
            if (it == m_pending_messages.end()) return;
            
            auto session = m_secure_session_manager->get_session(peerId);
            if (!session || !session->is_ready()) return;
            
            for (const auto& msg : it->second) {
                std::string ciphertext = session->send_message(msg);
                m_tcpConnectionManager->sendMessageToPeer(peerId, ciphertext);
            }
            m_pending_messages.erase(it);
        }
    };
};
```

## Step 7: Update CMakeLists.txt (if not done)

Ensure `secure_session.cpp` is included:

```cmake
set(SOURCES
    # ... existing sources ...
    src/noise_protocol.cpp
    src/secure_session.cpp
)
```

## Step 8: Update Include Paths

In any file using SecureSession:

```cpp
#include "secure_session.h"
#include "noise_protocol.h"  // For Role enum
#include "logger.h"
```

## Testing the Integration

### Unit Test

```cpp
void test_session_manager_with_noise() {
    // Create two session managers
    SessionManager peer1;
    SessionManager peer2;
    
    // Peer 1 initiates connection to Peer 2
    peer1.connectToPeer("peer2_id");
    
    // Simulate network exchange
    std::string handshake = getLastSentMessage(peer1);
    peer2.onData("peer1_id", handshake);
    
    std::string response = getLastSentMessage(peer2);
    peer1.onData("peer2_id", response);
    
    // Now send encrypted message
    peer1.sendMessageToPeer("peer2_id", "Hello");
    std::string encrypted_msg = getLastSentMessage(peer1);
    
    peer2.onData("peer1_id", encrypted_msg);
    std::string received = getLastReceivedMessage(peer2);
    
    assert(received == "Hello");
}
```

## Configuration Options

Add to `constants.h`:

```cpp
// Noise Protocol Configuration
constexpr bool ENABLE_NOISE_PROTOCOL = true;
constexpr bool ENABLE_AES_FALLBACK = true;  // For transition period
constexpr int HANDSHAKE_TIMEOUT_SEC = 5;
constexpr int SESSION_IDLE_TIMEOUT_SEC = 300;  // 5 minutes
```

## Migration Timeline

### Phase 1: Deploy with Both (Week 1)
- Deploy code with `ENABLE_NOISE_PROTOCOL = true`
- Fallback to AES if Noise fails
- Monitor logs and metrics

### Phase 2: Monitor (Week 2-3)
- Check success rate of Noise handshakes
- Watch for any compatibility issues
- Ensure no performance degradation

### Phase 3: Full Rollout (Week 4+)
- Confident all peers support Noise
- Set `ENABLE_AES_FALLBACK = false` to disable legacy path
- Remove AES encryption code

### Phase 4: Cleanup (Month 2+)
- Completely remove AES encryption
- Simplify codebase

## Debugging

### Enable Verbose Logging

In `logger.h`:

```cpp
constexpr bool LOG_NOISE_HANDSHAKE = true;
constexpr bool LOG_ENCRYPTION_DETAILS = true;
```

### Check Session State

```cpp
auto session = m_secure_session_manager->get_session(peerId);
if (session) {
    LOG_I("Debug", "Session ready: %s", session->is_ready() ? "yes" : "no");
}
```

### Monitor Performance

```cpp
auto start = std::chrono::high_resolution_clock::now();
std::string ciphertext = session->send_message(plaintext);
auto end = std::chrono::high_resolution_clock::now();
auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
LOG_I("Perf", "Encryption took %lld us", duration.count());
```

## Rollback Plan

If issues arise, quickly revert:

```cpp
// In constants.h
constexpr bool ENABLE_NOISE_PROTOCOL = false;  // Disable Noise
constexpr bool ENABLE_AES_FALLBACK = true;      // Use legacy AES
```

Then rebuild and deploy. Existing connections will use AES.

## Troubleshooting

### Handshake Never Completes

```
Causes:
1. Network issues (check TCP connectivity)
2. One peer not supporting Noise
3. Async timing issue (handshake packets out of order)

Fix:
- Check network with simple ping
- Verify both peers have updated code
- Add message numbering if async
```

### Decryption Failures

```
Causes:
1. Corrupted message in transit
2. Nonce desync (shouldn't happen)
3. Handshake incomplete

Fix:
- Add CRC/checksum before encryption
- Log nonce counter values
- Verify handshake completion before sending
```

### Memory Leaks

```
Causes:
1. SecureSession not destroyed
2. Uncaught exceptions in decrypt

Fix:
- Check m_pending_messages queue cleanup
- Use try-catch in all crypto operations
- Profile with valgrind on Linux target
```

## Next Steps

1. ✅ Review this guide
2. ✅ Implement changes to session_manager.cpp
3. ✅ Test locally with multiple peers
4. ✅ Monitor logs during integration testing
5. ✅ Deploy to production with gradual rollout

Once integrated, you'll have production-grade encryption with perfect forward secrecy! 🔐
