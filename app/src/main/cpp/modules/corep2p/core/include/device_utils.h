#ifndef DEVICE_UTILS_H
#define DEVICE_UTILS_H

#include <string>

/**
 * @brief Generates a persistent device ID based on hardware characteristics (MAC address).
 * Falls back to a random UUID if hardware info is unavailable.
 * 
 * Format: "litep2p-device-<mac_hex>" or "litep2p-random-<uuid>"
 */
std::string get_persistent_device_id();

#endif // DEVICE_UTILS_H
