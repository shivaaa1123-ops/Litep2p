#ifndef DEVICE_UTILS_H
#define DEVICE_UTILS_H

#include <string>
#include <vector>

struct sockaddr; // forward declaration (defined in <sys/socket.h>)

/**
 * @brief Generates a persistent device ID based on hardware characteristics (MAC address).
 * Falls back to a random UUID if hardware info is unavailable.
 * 
 * Format: "litep2p-device-<mac_hex>" or "litep2p-random-<uuid>"
 */
std::string get_persistent_device_id();

/**
 * @brief Gets all active IPv4 addresses on non-loopback interfaces
 * @return Vector of IP address strings
 */
std::vector<std::string> get_active_ipv4_addresses();

/**
 * @brief Gets the primary IPv4 address (prefers WiFi/ethernet over cellular)
 * @return Primary IP address string, or empty if none found
 */
std::string get_primary_ipv4_address();

/**
 * @brief Gets all active IPv6 addresses on non-loopback interfaces
 * (link-local and multicast addresses are excluded)
 * @return Vector of IPv6 address strings (no brackets)
 */
std::vector<std::string> get_active_ipv6_addresses();

/**
 * @brief Gets the primary address for the device.
 * IPv6-preferred: returns a global/unique-local IPv6 address when available,
 * falling back to the primary IPv4 address otherwise.
 * @return Address string (IPv4 "a.b.c.d" or IPv6 "x:y:z" without brackets),
 *         or empty if none found
 */
std::string get_primary_ip_address();

/**
 * @brief True when the host has at least one usable IPv6 address.
 */
bool has_ipv6_connectivity();

// ---------------------------------------------------------------------------
// Endpoint helpers (IPv6-aware network_id format: "a.b.c.d:port" / "[v6]:port")
// ---------------------------------------------------------------------------

/**
 * @brief Format host:port as a network_id. IPv6 hosts are wrapped in brackets
 * ("[2001:db8::1]:30001") so the colon separator stays unambiguous.
 */
std::string format_network_id(const std::string& host, uint16_t port);

/**
 * @brief Parse a network_id into host + port.
 * Accepts "a.b.c.d:port", "[v6]:port" and a bare IPv6 literal without port
 * (port stays 0). Returns false when the string is not a valid endpoint.
 */
bool parse_network_id(const std::string& network_id, std::string& host, uint16_t& port);

/**
 * @brief Format a sockaddr (IPv4/IPv6) as a network_id.
 * IPv4-mapped IPv6 addresses are normalized to plain IPv4.
 */
std::string sockaddr_to_network_id(const struct sockaddr* sa);

/**
 * @brief True when the string is an IPv6 literal (contains ':').
 */
bool is_ipv6_literal(const std::string& host);

#endif // DEVICE_UTILS_H
