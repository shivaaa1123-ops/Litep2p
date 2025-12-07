#ifndef CONNECTION_MANAGER_H
#define CONNECTION_MANAGER_H

#include <string>
#include <vector>
#include <functional>
#include <thread>
#include <mutex>
#include <map>
#include <atomic>

class ConnectionManager {
public:
    void startServer(int port, 
                     std::function<void(const std::string&, const std::string&)> on_data, 
                     std::function<void(const std::string&)> on_disconnect);
    void stop();
    bool connectToPeer(const std::string& ip, int port);
    void sendMessageToPeer(const std::string& network_id, const std::string& message);

private:
    void serverLoop(int port);
    void readLoop(int client_sock, std::string network_id);

    std::atomic<bool> m_running{false};
    int m_server_sock = -1;
    std::thread m_serverThread;
    std::map<std::string, int> m_clients;
    std::mutex m_clients_mutex;
    
    std::function<void(const std::string&, const std::string&)> m_on_data_cb;
    std::function<void(const std::string&)> m_on_disconnect_cb;
};

#endif // CONNECTION_MANAGER_H
