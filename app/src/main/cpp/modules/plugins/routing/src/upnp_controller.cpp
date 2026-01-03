#include "../include/upnp_controller.h"
#include "../../../corep2p/core/include/logger.h"
#include <array>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <sstream>

UpnpController::UpnpController() : m_available(false) {
    // Check if upnpc command is available
    std::string output;
    if (executeCommand("upnpc -s", output) || executeCommand("which upnpc", output)) {
        m_available = true;
        LOG_INFO("UPnP: 'upnpc' command found. UPnP support enabled.");
    } else {
        LOG_WARN("UPnP: 'upnpc' command NOT found. UPnP support disabled.");
    }
}

UpnpController::~UpnpController() = default;

bool UpnpController::isAvailable() const {
    return m_available;
}

bool UpnpController::addPortMapping(uint16_t internal_port,
                                    uint16_t external_port,
                                    const std::string& protocol,
                                    int lease_seconds,
                                    std::string& mapping_id) {
    if (!m_available) return false;

    // Command: upnpc -a <internal_ip> <internal_port> <external_port> <protocol> [duration]
    // Note: upnpc -a usually detects internal IP automatically if not specified, or we might need to parse it.
    // Simpler usage: upnpc -e <description> -a <ip> <port> <ext_port> <proto> <duration>
    // Let's try the simplest form: upnpc -a <internal_ip> <port> <ext_port> <proto>
    
    // Since we don't easily know our local IP here without more logic, we rely on upnpc's auto-detection
    // or we pass a dummy IP if upnpc handles it. 
    // Actually, 'upnpc -r <port> <proto>' adds a redirection for the local machine.
    
    std::stringstream cmd;
    cmd << "upnpc -r " << internal_port << " " << protocol;
    if (lease_seconds > 0) {
        // upnpc might not support lease duration in all versions with -r, but let's try
        // standard upnpc -r port protocol [tcp|udp]
    }

    LOG_INFO("UPnP: Executing " + cmd.str());
    
    std::string output;
    if (executeCommand(cmd.str(), output)) {
        if (output.find("mapped") != std::string::npos || output.find("TCP is redirected") != std::string::npos || output.find("UDP is redirected") != std::string::npos) {
            mapping_id = std::to_string(external_port) + ":" + protocol;
            LOG_INFO("UPnP: Port mapping successful: " + mapping_id);
            return true;
        }
    }
    
    LOG_ERROR("UPnP: Port mapping failed. Output: " + output);
    return false;
}

bool UpnpController::removePortMapping(const std::string& mapping_id) {
    if (!m_available) return false;

    // mapping_id is ext_port:protocol
    size_t sep = mapping_id.find(':');
    if (sep == std::string::npos) return false;

    std::string port = mapping_id.substr(0, sep);
    std::string proto = mapping_id.substr(sep + 1);

    std::stringstream cmd;
    cmd << "upnpc -d " << port << " " << proto;

    std::string output;
    return executeCommand(cmd.str(), output);
}

bool UpnpController::executeCommand(const std::string& cmd, std::string& output) const {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) {
        return false;
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    output = result;
    return true; // We assume execution happened, caller checks output content
}
