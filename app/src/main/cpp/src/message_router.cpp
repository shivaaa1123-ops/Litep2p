#include "message_router.h"
#include "logger.h"
#include <mutex>

static std::mutex g_mtx;

void MessageRouter::setCallback(MessageCallback cb) {
    m_cb = cb;
}

void MessageRouter::send(const std::string &peerId, const std::string &data) {
    std::lock_guard<std::mutex> lock(g_mtx);

    if (m_cb) {
        m_cb(peerId, data);
    } else {
        nativeLog("MessageRouter: no callback for msg to " + peerId);
    }
}
