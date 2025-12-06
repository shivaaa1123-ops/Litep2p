#ifndef EPOLL_REACTOR_H
#define EPOLL_REACTOR_H

#include <functional>
#include <mutex>
#include <vector>

using Task = std::function<void()>;

class EpollReactor {
public:
    EpollReactor();
    ~EpollReactor();
    void post(Task t);

private:
    std::mutex m_lock;
};

#endif
