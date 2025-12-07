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

// Very small TCP acceptor which replies to HELLO with WELCOME:<id>

class HandshakeAcceptor {
public:
    using OnConnect = std::function<void(int client_fd, const std::string& remote_addr)>;

    HandshakeAcceptor(int port = 9000): port_(port), running_(false), sock_(-1) {}
    ~HandshakeAcceptor(){ stop(); }

    bool start(OnConnect cb) {
        if (running_) return false;
        sock_ = socket(AF_INET, SOCK_STREAM, 0);
        if (sock_ < 0) return false;
        int yes = 1;
        setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        struct sockaddr_in addr;
        memset(&addr,0,sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port_);
        if (bind(sock_, (struct sockaddr*)&addr, sizeof(addr))<0) {
            close(sock_); sock_=-1; return false;
        }
        if (listen(sock_, 16) < 0) { close(sock_); sock_=-1; return false; }
        running_ = true;
        worker_ = std::thread([this,cb](){
            while (running_) {
                struct sockaddr_in cli;
                socklen_t clilen = sizeof(cli);
                int fd = accept(sock_, (struct sockaddr*)&cli, &clilen);
                if (fd < 0) { std::this_thread::sleep_for(std::chrono::milliseconds(100)); continue; }
                char cip[64]; inet_ntop(AF_INET, &cli.sin_addr, cip, sizeof(cip));
                std::string raddr = std::string(cip) + ":" + std::to_string(ntohs(cli.sin_port));
                // handle in a detached thread: read HELLO, reply WELCOME:<id>
                std::thread([fd, raddr, cb](){
                    char buf[512];
                    ssize_t r = recv(fd, buf, sizeof(buf)-1, 0);
                    if (r > 0) {
                        buf[r]=0;
                        std::string req(buf);
                        if (req.rfind("HELLO:",0) == 0) {
                            // extract id
                            std::string id = req.substr(6);
                            // strip newline
                            if (!id.empty() && id.back()=='\n') id.pop_back();
                            std::string resp = "WELCOME:servernode\n";
                            send(fd, resp.data(), resp.size(), 0);
                        }
                    }
                    if (cb) cb(fd, raddr);
                    // leave socket open for further protocol; caller can close fd
                }).detach();
            }
        });
        return true;
    }

    void stop() {
        running_ = false;
        if (sock_>=0) { close(sock_); sock_=-1; }
        if (worker_.joinable()) worker_.join();
    }

private:
    int port_;
    std::atomic<bool> running_;
    int sock_;
    std::thread worker_;
});
