#ifndef MESSAGE_ROUTER_H
#define MESSAGE_ROUTER_H

#include <functional>
#include <string>

using MessageCallback = std::function<void(const std::string&, const std::string&)>;

class MessageRouter {
public:
    void setCallback(MessageCallback cb);
    void send(const std::string &peerId, const std::string &data);

private:
    MessageCallback m_cb;
};

#endif
