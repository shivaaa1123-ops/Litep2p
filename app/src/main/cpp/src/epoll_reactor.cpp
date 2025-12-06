#include "epoll_reactor.h"
#include "logger.h"

EpollReactor::EpollReactor() { nativeLog("EpollReactor (stub) created"); }
EpollReactor::~EpollReactor() { nativeLog("EpollReactor destroyed"); }
void EpollReactor::post(Task t) {
    if (!t) return;
    std::lock_guard<std::mutex> l(m_lock);
    // run inline for simplicity
    t();
}
