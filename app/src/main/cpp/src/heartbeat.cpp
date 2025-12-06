#include "heartbeat.h"
#include "logger.h"
#include <thread>
#include <atomic>

class HBImpl {
public:
    HBImpl() : m_running(false) {}
    ~HBImpl() { stop(); }

    void start(int intervalMs) {
        if (m_running) return;
        m_running = true;

        m_thread = std::thread([this, intervalMs]() {
            nativeLog("Heartbeat: started");

            while (m_running) {
                std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));

                if (!m_running) break;

                if (m_cb) {
                    m_cb("PING");
                }
            }

            nativeLog("Heartbeat: stopped");
        });
    }

    void stop() {
        if (!m_running) return;
        m_running = false;
        if (m_thread.joinable()) m_thread.join();
    }

    void setCb(std::function<void(const std::string&)> cb) {
        m_cb = cb;
    }

private:
    std::atomic<bool> m_running;
    std::thread m_thread;
    std::function<void(const std::string&)> m_cb;
};

static HBImpl* g_hb = nullptr;

// Public wrapper

Heartbeat::Heartbeat() {
    if (!g_hb) g_hb = new HBImpl();
}

Heartbeat::~Heartbeat() {
    if (g_hb) {
        delete g_hb;
        g_hb = nullptr;
    }
}

void Heartbeat::start(int intervalMs) {
    if (g_hb) g_hb->start(intervalMs);
}

void Heartbeat::stop() {
    if (g_hb) g_hb->stop();
}

void Heartbeat::setSendCallback(std::function<void(const std::string&)>&& cb) {
    if (g_hb) g_hb->setCb(cb);
}
