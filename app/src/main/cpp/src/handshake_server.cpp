#include "handshake_server.h"
#include <thread>
#include <string>
#include <functional>
#include <atomic>
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <arpa/inet.h>
#include <chrono>

// ------------------------------
// Constructor / Destructor
// ------------------------------

HandshakeAcceptor::HandshakeAcceptor(int port)
        : port_(port), running_(false), sock_(-1) {}

HandshakeAcceptor::~HandshakeAcceptor() {
    stop();
}

// ------------------------------
// Start Listening
// ------------------------------

bool HandshakeAcceptor::start(OnConnect cb) {
    if (running_) return false;

    sock_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_ < 0) return false;

    int yes = 1;
    setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port_);

    if (bind(sock_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock_);
        sock_ = -1;
        return false;
    }

    if (listen(sock_, 16) < 0) {
        close(sock_);
        sock_ = -1;
        return false;
    }

    running_ = true;

    worker_ = std::thread([this, cb]() {
        while (running_) {
            struct sockaddr_in cli{};
            socklen_t clilen = sizeof(cli);

            int fd = accept(sock_, (struct sockaddr*)&cli, &clilen);
            if (fd < 0) {
                if (!running_) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            char cip[64] = {0};
            inet_ntop(AF_INET, &cli.sin_addr, cip, sizeof(cip));

            std::string raddr = std::string(cip) + ":" +
                                std::to_string(ntohs(cli.sin_port));

            std::thread([this, fd, raddr, cb]() {
                this->handleClient(fd, raddr, cb);
            }).detach();
        }
    });

    return true;
}

// ------------------------------
// Client Handler
// ------------------------------

void HandshakeAcceptor::handleClient(int fd, const std::string& raddr, OnConnect cb) {
    struct timeval tv{};
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char buf[512];
    std::string data;

    while (true) {
        ssize_t r = recv(fd, buf, sizeof(buf) - 1, 0);
        if (r <= 0) break;

        buf[r] = 0;
        data.append(buf);

        auto pos = data.find('\n');
        if (pos != std::string::npos) {
            data = data.substr(0, pos);
            break;
        }

        if (data.size() > 1024) break;
    }

    if (data.rfind("HELLO:", 0) == 0) {
        std::string id = data.substr(6);
        if (!id.empty() && (id.back() == '\r' || id.back() == '\n'))
            id.pop_back();

        std::string resp = "WELCOME:servernode\n";
        send(fd, resp.data(), resp.size(), 0);
    }

    if (cb) cb(fd, raddr);

    close(fd);
}

// ------------------------------
// Stop Listener
// ------------------------------

void HandshakeAcceptor::stop() {
    running_ = false;
    if (sock_ >= 0) {
        close(sock_);
        sock_ = -1;
    }
    if (worker_.joinable()) {
        worker_.join();
    }
}