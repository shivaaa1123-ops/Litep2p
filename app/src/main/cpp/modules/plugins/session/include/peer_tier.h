#pragma once

enum class PeerTier {
    TIER_1,     // Hot - direct connection, <100ms latency
    TIER_2,     // Warm - occasional connection, 100-300ms
    TIER_3,     // Cold - unknown or broadcast only
    TIER_UNKNOWN // Not yet classified
};
