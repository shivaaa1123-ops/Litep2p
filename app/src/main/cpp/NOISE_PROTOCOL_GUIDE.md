# Noise Protocol Implementation Guide

## Overview

This implementation provides **Noise Protocol NN** for your P2P application, providing:

✅ **ECDH Key Exchange** - Curve25519 elliptic curve cryptography  
✅ **Forward Secrecy** - Ephemeral keys that cannot be recovered  
✅ **Authenticated Encryption** - ChaCha20-Poly1305 AEAD cipher  
✅ **Replay Protection** - Per-message nonce counter  
✅ **Modern Cryptography** - Uses libsodium library  

## Architecture

### Noise Protocol NN Pattern

```
Initiator                          Responder
   |                                   |
   |-- send ephemeral public key e -->|
   |                                   |
   |<-- send e, ee (encrypted) -------|
   |                                   |
  [Handshake complete]            [Handshake complete]
   |                                   |
   |<---- encrypted messages ----->|
```

### Key Components

1. **NoiseSession** - Low-level Noise Protocol state machine
2. **SecureSession** - High-level wrapper for easy integration
3. **SecureSessionManager** - Manages multiple peer sessions

## Usage Examples

### Basic Usage

```cpp
#include "secure_session.h"
#include "noise_protocol.h"

// As INITIATOR (client connecting to peer)
auto session = std::make_unique<SecureSession>("peer_ip:port", NoiseSession::Role::INITIATOR);

// Start handshake
std::string handshake_msg = session->start_handshake();
// Send handshake_msg to peer

// Receive response from peer
std::string peer_response = /* receive from network */;
std::string final_msg = session->process_handshake(peer_response);

// Now session is ready!
if (session->is_ready()) {
    std::string ciphertext = session->send_message("Hello, peer!");
    // Send ciphertext to peer
}

// Receive encrypted message from peer
std::string received_ciphertext = /* receive from network */;
std::string plaintext = session->receive_message(received_ciphertext);
```

### As RESPONDER (server)

```cpp
auto session = std::make_unique<SecureSession>("peer_ip:port", NoiseSession::Role::RESPONDER);

// Receive handshake from peer
std::string peer_handshake = /* receive from network */;
std::string response = session->process_handshake(peer_handshake);

// Send response back
// Send response to peer

// Session is now complete!
if (session->is_ready()) {
    // Can send/receive encrypted messages
}
```

### Using SecureSessionManager

```cpp
SecureSessionManager session_manager;

// Get or create session (automatically manages multiple peers)
auto session = session_manager.get_or_create_session(
    "192.168.1.100:30001",
    NoiseSession::Role::INITIATOR
);

// Perform handshake
std::string msg = session->start_handshake();

// Check if ready
if (session_manager.is_session_ready("192.168.1.100:30001")) {
    auto encrypted = session->send_message("Secure message");
}
```

## Integration with Existing Code

### Option 1: Replace AES with Noise (Recommended)

Update `session_manager.cpp` to use Noise Protocol for all P2P communication:

```cpp
#include "secure_session.h"

class SessionManager::Impl {
    SecureSessionManager m_secure_sessions;
    
    // In onData handler
    void onData(const std::string& network_id, const std::string& data) {
        auto session = m_secure_sessions.get_session(network_id);
        if (session) {
            std::string plaintext = session->receive_message(data);
            // Process plaintext
        }
    }
};
```

### Option 2: Hybrid Mode (AES + Noise)

Keep existing AES for backward compatibility, use Noise for new connections:

```cpp
std::string send_message(const std::string& peer_id) {
    if (m_use_noise_protocol) {
        // Use Noise Protocol
        auto session = m_secure_sessions.get_session(peer_id);
        return session->send_message(message);
    } else {
        // Fall back to old AES
        return encrypt_message_legacy(message);
    }
}
```

## Handshake Flow for SessionManager

Add to `session_manager.cpp`:

```cpp
void handleEvent(const ConnectToPeerEvent& event) {
    // Create secure session during connection
    auto secure_session = m_session_manager.get_or_create_session(
        event.peerId,
        NoiseSession::Role::INITIATOR
    );
    
    // Send handshake message
    std::string handshake = secure_session->start_handshake();
    m_tcpConnectionManager.sendMessageToPeer(event.peerId, handshake);
}
```

## Security Properties

### What Noise Protocol Provides

| Property | AES-CBC | Noise NN |
|----------|---------|----------|
| **Confidentiality** | ✅ Yes | ✅ Yes |
| **Authentication** | ❌ No | ✅ Yes (forward-secure) |
| **Key Exchange** | ❌ No | ✅ ECDH |
| **Forward Secrecy** | ❌ No | ✅ Yes |
| **Integrity** | ❌ No | ✅ AEAD |
| **Replay Protection** | ❌ No | ✅ Nonce counter |
| **Known Key Attack** | ❌ Vulnerable | ✅ Safe |

### Noise NN Limitations

- **No mutual authentication**: Both parties trust the ephemeral keys but don't verify identities
- **Vulnerable to MITM**: Consider using Noise NK or KK if identity pre-sharing is available
- **Perfect Forward Secrecy**: Only applies to transport keys (not handshake authentication)

## Performance Considerations

- **Handshake overhead**: ~130 bytes (32-byte e + 32-byte e + 16-byte tag + 32-byte ee + 16-byte tag)
- **Message overhead**: 16 bytes per message (Poly1305 tag only)
- **CPU**: ~100-200 microseconds per message on modern ARM CPUs
- **Memory**: ~1-2 KB per session

## Switching from AES to Noise

### Migration Steps

1. **Deploy new code** with both AES and Noise (hybrid mode)
2. **Gradually enable Noise** for new connections
3. **Monitor logs** for any issues
4. **Deprecate AES** once all peers support Noise
5. **Remove AES code** in future release

### Configuration

Add to your constants/config:

```cpp
// In constants.h
constexpr bool USE_NOISE_PROTOCOL = true;
constexpr bool ENABLE_AES_FALLBACK = true; // For transition period
```

## Troubleshooting

### Handshake Fails

- Check peer is using same Noise version (NN pattern)
- Verify network connectivity during handshake
- Check logs for ECDH or HKDF errors

### Decryption Failures

- Ensure handshake completed on both sides
- Check for packet loss/corruption
- Verify nonce counter sync (shouldn't happen)

### Performance Issues

- Reduce handshake frequency (reuse sessions)
- Use session pooling with SecureSessionManager
- Monitor ECDH computation time on device

## Dependencies

**libsodium** is required. Install with:

```bash
# Prebuilt for Android NDK (recommended)
# Or compile from source

# Verify in your Android build
find $ANDROID_SDK_ROOT/ndk -name "libsodium*"
```

## Testing

```cpp
// Unit test example
void test_noise_handshake() {
    NoiseSession initiator(NoiseSession::Role::INITIATOR, "initiator_id");
    NoiseSession responder(NoiseSession::Role::RESPONDER, "responder_id");
    
    // Initiate
    auto msg1 = initiator.initiate_handshake();
    auto msg2 = responder.process_handshake_message(msg1);
    auto _ = initiator.process_handshake_message(msg2);
    
    // Test encryption
    auto plaintext = std::string("Hello");
    auto ciphertext = initiator.encrypt_message(plaintext);
    auto decrypted = responder.decrypt_message(ciphertext);
    
    assert(plaintext == decrypted);
}
```

## Future Improvements

1. **Noise KK**: Pre-share static keys for mutual authentication
2. **Key Rotation**: Periodic key refresh for long-lived sessions
3. **Multiple Message Patterns**: NN → NK → KK progression
4. **Session Resumption**: Resume interrupted connections
5. **Rate Limiting**: Protect against handshake floods

## References

- [Noise Protocol Framework](https://noiseprotocol.org/)
- [Curve25519](https://cr.yp.to/ecdh.html)
- [ChaCha20-Poly1305](https://tools.ietf.org/html/rfc7539)
- [libsodium Documentation](https://doc.libsodium.org/)
