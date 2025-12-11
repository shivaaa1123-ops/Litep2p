/**
 * CoreP2P - Aggregated P2P Core Module
 * 
 * Unified interface for the 5 core layers of LiteP2P:
 *   1. Foundation (core)
 *   2. Infrastructure (crypto, reactor)
 *   3. Core Services (transport, security)
 * 
 * This module provides a single point of entry for all core P2P functionality.
 */

#ifndef COREP2P_H
#define COREP2P_H

// ============================================================================
// Layer 1: Foundation (No Dependencies)
// ============================================================================

#include "config_manager.h"
#include "logger.h"
#include "constants.h"

// ============================================================================
// Layer 2: Infrastructure (Depends on Foundation)
// ============================================================================

// Cryptography Module
#include "aes.h"
#include "noise_key_store.h"
#include "crypto_utils.h"

// Reactor Module (Event-Driven I/O)
#include "epoll_reactor.h"
#include "event_thread_pool.h"

// ============================================================================
// Layer 3: Core Services (Depends on Infrastructure)
// ============================================================================

// Transport Module (Network Communication)
#include "network.h"
#include "connection_manager.h"
#include "udp_connection_manager.h"
#include "batch_connection_manager.h"
#include "multi_socket_manager.h"

// Security Module (Encrypted Sessions)
#include "secure_session.h"

// ============================================================================
// Unified CoreP2P Namespace
// ============================================================================

namespace corep2p {

/**
 * CoreP2P Library - Aggregated interface for core P2P networking
 * 
 * Combines all 5 core layers:
 * - Configuration and logging
 * - Cryptographic operations
 * - Event-driven I/O and threading
 * - Network transport (TCP/UDP)
 * - Secure encrypted sessions
 */
class CoreP2P {
public:
    // Version information
    static constexpr const char* VERSION = "1.0.0";
    static constexpr const char* NAME = "CoreP2P - LiteP2P Foundation";
    static constexpr int MAJOR = 1;
    static constexpr int MINOR = 0;
    static constexpr int PATCH = 0;

    /**
     * Initialize CoreP2P subsystems
     * Must be called before using any core functionality
     */
    static void initialize();

    /**
     * Cleanup CoreP2P subsystems
     * Should be called before application exit
     */
    static void shutdown();
};

// ============================================================================
// Module Information
// ============================================================================

/**
 * Get CoreP2P module information
 */
struct ModuleInfo {
    const char* name;
    const char* version;
    const char* description;
};

/**
 * Layer 1: Foundation Module
 */
inline ModuleInfo get_core_module_info() {
    return {
        "litep2p_core",
        "1.0.0",
        "Foundation layer: Configuration, logging, common types"
    };
}

/**
 * Layer 2a: Cryptography Module
 */
inline ModuleInfo get_crypto_module_info() {
    return {
        "litep2p_crypto",
        "1.0.0",
        "Cryptography: AES encryption, key management, utilities"
    };
}

/**
 * Layer 2b: Reactor Module (Event I/O)
 */
inline ModuleInfo get_reactor_module_info() {
    return {
        "litep2p_reactor",
        "1.0.0",
        "Event-driven I/O: Epoll reactor, thread pool, timers"
    };
}

/**
 * Layer 3a: Transport Module
 */
inline ModuleInfo get_transport_module_info() {
    return {
        "litep2p_transport",
        "1.0.0",
        "Network transport: TCP/UDP sockets, connections, message framing"
    };
}

/**
 * Layer 3b: Security Module
 */
inline ModuleInfo get_security_module_info() {
    return {
        "litep2p_security",
        "1.0.0",
        "Encrypted sessions: Secure session establishment and management"
    };
}

} // namespace corep2p

#endif // COREP2P_H
