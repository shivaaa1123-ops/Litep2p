#ifndef HANDSHAKE_SERVER_H
#define HANDSHAKE_SERVER_H

#include <functional>
#include <string>
#include <atomic>
#include <thread>

class HandshakeAcceptor {
public:
    using OnConnect = std::function<void(int, const std::string&)>;

    HandshakeAcceptor(int port = 9000);
    ~HandshakeAcceptor();

    bool start(OnConnect cb);
    void stop();

private:
    void handleClient(int fd, const std::string& raddr, OnConnect cb);

    int port_;                 // <-- REQUIRED
    std::atomic_bool running_; // <-- REQUIRED
    int sock_;                 // <-- REQUIRED
    std::thread worker_;       // <-- REQUIRED
};

#endif