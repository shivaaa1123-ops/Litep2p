

#ifndef EPOLL_REACTOR_H
#define EPOLL_REACTOR_H

#include <functional>
#include <memory>
#include <cstdint>

class EpollReactorImpl;

using EventCallback = std::function<void(int fd, uint32_t events)>;
using Task = std::function<void()>;
using TimerId = int;

class EpollReactor {
public:
    EpollReactor();
    ~EpollReactor();

    void start();
    void stop();

    bool add(int fd, uint32_t events, EventCallback cb);
    bool remove(int fd);
    void post(Task t);

    TimerId runAfter(int milliseconds, Task t);
    TimerId runEvery(int milliseconds, Task t);
    void cancelTimer(TimerId id);

private:
    std::unique_ptr<EpollReactorImpl> m_impl;
};

#endif // EPOLL_REACTOR_H
