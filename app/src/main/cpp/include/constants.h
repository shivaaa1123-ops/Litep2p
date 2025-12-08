#ifndef CONSTANTS_H
#define CONSTANTS_H

// Network Configuration
constexpr int DEFAULT_SERVER_PORT = 30001;
constexpr int DISCOVERY_PORT = 30000;
constexpr int DEFAULT_LISTEN_BACKLOG = 5;

// Timeouts (in seconds/milliseconds)
constexpr int TCP_CONNECT_TIMEOUT_SEC = 10;
constexpr int TCP_SELECT_TIMEOUT_SEC = 1;
constexpr int UDP_SELECT_TIMEOUT_SEC = 1;
constexpr int PEER_TIMEOUT_SEC = 30;  // Increased from 20 for battery savings
constexpr int TIMER_TICK_INTERVAL_SEC = 10; // Increased from 5 for battery savings (ping less frequently)

// Battery Optimization (Android-specific)
constexpr int PING_INTERVAL_SEC = 10;       // How often to ping peers (battery saving)
constexpr int BATCH_DELAY_MS = 50;          // Delay message send for batching
constexpr int BATCH_MAX_MESSAGES = 10;      // Max messages per batch
constexpr bool ENABLE_MESSAGE_BATCHING = true;
constexpr bool ENABLE_SESSION_CACHING = true;
constexpr bool ENABLE_SELECTIVE_ENCRYPTION = true;  // Only encrypt on cellular

// Buffer Sizes
constexpr size_t TCP_BUFFER_SIZE = 4096;
constexpr size_t UDP_BUFFER_SIZE = 4096;
constexpr size_t DISCOVERY_MSG_MAX = 1024;

// Socket Behavior
constexpr int SELECT_MAX_RETRIES = 3;

// Discovery
constexpr const char* DISCOVERY_MESSAGE_PREFIX = "LITEP2P_DISCOVERY";
constexpr int DISCOVERY_BROADCAST_INTERVAL_SEC = 5;

#endif // CONSTANTS_H
