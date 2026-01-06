// ... existing code ...
    void start(int port, std::function<void(const std::vector<Peer>&)> cb, const std::string& comms_mode, const std::string& peer_id);
    void stop();
    std::future<void> stopAsync();
    void connectToPeer(const std::string& peer_id);
    void sendMessageToPeer(const std::string& peer_id, const std::string& message);
// ... existing code ...
