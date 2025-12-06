#ifndef HEARTBEAT_H
#define HEARTBEAT_H

#include <functional>
#include <string>

class Heartbeat {
public:
    Heartbeat();
    ~Heartbeat();

    void start(int intervalMs);
    void stop();
    void setSendCallback(std::function<void(const std::string&)>&& cb);
};

#endif
