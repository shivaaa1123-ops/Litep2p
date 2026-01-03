
#include "epoll_reactor.h"
#include "logger.h"
#include <vector>
#include <unordered_map>
#include <map>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>

#if !BUILD_TARGET_DESKTOP

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <fcntl.h>

struct Timer {
    int id;
    long long expirationMs;
    int intervalMs; 
    Task task;
};

static long long nowMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

class EpollReactorImpl {
public:
    EpollReactorImpl() : m_running(false), m_timerSeq(0) {
        m_epollFd = epoll_create1(0);
        m_wakeFd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        
        struct epoll_event ev{};
        ev.events = EPOLLIN;
        ev.data.fd = m_wakeFd;
        epoll_ctl(m_epollFd, EPOLL_CTL_ADD, m_wakeFd, &ev);
    }

    ~EpollReactorImpl() {
        stop();
        close(m_epollFd);
        close(m_wakeFd);
    }

    void start() {
        if (m_running) return;
        m_running = true;
        m_thread = std::thread([this]() { loop(); });
        nativeLog("Reactor: Started");
    }

    void stop() {
        if (!m_running) return;
        m_running = false;
        wakeUp();
        if (m_thread.joinable()) m_thread.join();
    }

    void wakeUp() {
        uint64_t u = 1;
        write(m_wakeFd, &u, sizeof(u));
    }

    bool add(int fd, uint32_t events, EventCallback cb) {
        std::lock_guard<std::mutex> lock(m_mutex);
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        struct epoll_event ev{};
        ev.events = events;
        ev.data.fd = fd;
        if (epoll_ctl(m_epollFd, EPOLL_CTL_ADD, fd, &ev) < 0) return false;
        m_callbacks[fd] = cb;
        return true;
    }

    bool remove(int fd) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_callbacks.erase(fd);
        return epoll_ctl(m_epollFd, EPOLL_CTL_DEL, fd, nullptr) == 0;
    }

    void post(Task t) {
        {
            std::lock_guard<std::mutex> lock(m_taskMutex);
            m_pendingTasks.push_back(t);
        }
        wakeUp();
    }

    int runAfter(int ms, Task t) {
        std::lock_guard<std::mutex> lock(m_timerMutex);
        int id = ++m_timerSeq;
        Timer timer{id, nowMs() + ms, 0, t};
        m_timers.insert({timer.expirationMs, timer});
        wakeUp();
        return id;
    }

    int runEvery(int ms, Task t) {
        std::lock_guard<std::mutex> lock(m_timerMutex);
        int id = ++m_timerSeq;
        Timer timer{id, nowMs() + ms, ms, t};
        m_timers.insert({timer.expirationMs, timer});
        wakeUp();
        return id;
    }

    void cancelTimer(int id) {
        std::lock_guard<std::mutex> lock(m_timerMutex);
        for (auto it = m_timers.begin(); it != m_timers.end(); ) {
            if (it->second.id == id) it = m_timers.erase(it);
            else ++it;
        }
    }

private:
    void loop() {
        const int MAX_EVENTS = 64;
        struct epoll_event events[MAX_EVENTS];

        while (m_running) {
            int timeout = -1;
            {
                std::lock_guard<std::mutex> lock(m_timerMutex);
                if (!m_timers.empty()) {
                    long long now = nowMs();
                    long long next = m_timers.begin()->first;
                    timeout = (next > now) ? (int)(next - now) : 0;
                }
            }

            int n = epoll_wait(m_epollFd, events, MAX_EVENTS, timeout);

            if (n > 0) {
                for (int i = 0; i < n; ++i) {
                    int fd = events[i].data.fd;
                    if (fd == m_wakeFd) {
                        uint64_t u; read(m_wakeFd, &u, sizeof(u));
                    } else {
                        EventCallback cb;
                        {
                            std::lock_guard<std::mutex> lock(m_mutex);
                            if (m_callbacks.count(fd)) cb = m_callbacks[fd];
                        }
                        if (cb) cb(fd, events[i].events);
                    }
                }
            }

            std::vector<Task> tasks;
            {
                std::lock_guard<std::mutex> lock(m_taskMutex);
                tasks.swap(m_pendingTasks);
            }
            for (auto& t : tasks) t();

            {
                std::lock_guard<std::mutex> lock(m_timerMutex);
                long long now = nowMs();
                auto it = m_timers.begin();
                while (it != m_timers.end() && it->first <= now) {
                    Timer t = it->second;
                    it = m_timers.erase(it);
                    
                    // Release lock before executing task to prevent deadlock
                    lock.~lock_guard();
                    if(t.task) t.task();
                    
                    // Reacquire lock for multimap operations
                    new (&lock) std::lock_guard<std::mutex>(m_timerMutex);
                    
                    // If this is a repeating timer, reschedule it
                    if (t.intervalMs > 0) {
                        t.expirationMs = now + t.intervalMs;
                        m_timers.insert({t.expirationMs, t});
                        it = m_timers.lower_bound(now);
                    }
                }
            }
        }
    }

    int m_epollFd, m_wakeFd;
    std::atomic<bool> m_running;
    std::thread m_thread;
    std::mutex m_mutex;
    std::unordered_map<int, EventCallback> m_callbacks;
    std::mutex m_taskMutex;
    std::vector<Task> m_pendingTasks;
    std::mutex m_timerMutex;
    std::multimap<long long, Timer> m_timers; 
    int m_timerSeq;
};

EpollReactor::EpollReactor() : m_impl(std::make_unique<EpollReactorImpl>()) {}
EpollReactor::~EpollReactor() = default;
void EpollReactor::start() { m_impl->start(); }
void EpollReactor::stop() { m_impl->stop(); }
bool EpollReactor::add(int fd, uint32_t events, EventCallback cb) { return m_impl->add(fd, events, cb); }
bool EpollReactor::remove(int fd) { return m_impl->remove(fd); }
void EpollReactor::post(Task t) { m_impl->post(t); }
TimerId EpollReactor::runAfter(int ms, Task t) { return m_impl->runAfter(ms, t); }
TimerId EpollReactor::runEvery(int ms, Task t) { return m_impl->runEvery(ms, t); }
void EpollReactor::cancelTimer(TimerId id) { m_impl->cancelTimer(id); }

#else

// Desktop/macOS stub implementation
class EpollReactorImpl {};

EpollReactor::EpollReactor() : m_impl(std::make_unique<EpollReactorImpl>()) {}
EpollReactor::~EpollReactor() = default;
void EpollReactor::start() {}
void EpollReactor::stop() {}
bool EpollReactor::add(int fd, uint32_t events, EventCallback cb) { return false; }
bool EpollReactor::remove(int fd) { return false; }
void EpollReactor::post(Task t) {}
TimerId EpollReactor::runAfter(int ms, Task t) { return 0; }
TimerId EpollReactor::runEvery(int ms, Task t) { return 0; }
void EpollReactor::cancelTimer(TimerId id) {}

#endif
