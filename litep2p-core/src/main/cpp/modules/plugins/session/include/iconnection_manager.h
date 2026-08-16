#ifndef ICONNECTION_MANAGER_H
#define ICONNECTION_MANAGER_H

#include <string>
#include <functional>

class IConnectionManager {
public:
    virtual ~IConnectionManager() = default;
    
    virtual bool startServer(int port, 
                            std::function<void(const std::string&, const std::string&)> dataCallback,
                            std::function<void(const std::string&)> disconnectCallback) = 0;
    virtual void stop() = 0;
    virtual bool connectToPeer(const std::string& ip, int port) = 0;
    virtual void sendMessageToPeer(const std::string& networkId, const std::string& message) = 0;

    // Gracefully close the transport connection to a specific peer endpoint.
    // Connection-oriented transports (TCP) close the socket, which triggers the
    // normal disconnect path (on_disconnect callback). Connectionless transports
    // (UDP) have no per-peer socket to close and return false by default; the
    // session layer handles those via the peer FSM.
    virtual bool disconnectPeer(const std::string& networkId) { (void)networkId; return false; }
};

#endif // ICONNECTION_MANAGER_H