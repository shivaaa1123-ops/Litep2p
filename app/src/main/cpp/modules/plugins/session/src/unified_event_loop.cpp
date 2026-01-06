#include "unified_event_loop.h"
#include "logger.h"
#include "config_manager.h"
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <cstring>
#include <algorithm>

#ifdef __APPLE__
#include <sys/event.h>
#include <sys/time.h>
#else
#include <poll.h>
#endif

// Helper for platform-specific logging
#if HAVE_JNI
#include <android/log.h>
#define UEL_LOG(msg) __android_log_write(ANDROID_LOG_DEBUG, "UnifiedEventLoop", msg)
#else
#include <iostream>
#define UEL_LOG(msg) std::cerr << "[UEL] " << msg << std::endl
#endif

UnifiedEventLoop::UnifiedEventLoop() {
    // Create wake-up pipe for cross-thread signaling
    if (pipe(m_wakeup_pipe) < 0) {
        UEL_LOG("Failed to create wake-up pipe");
        return;
    }
    
    // Set wake-up pipe to non-blocking
    fcntl(m_wakeup_pipe[0], F_SETFL, O_NONBLOCK);
    fcntl(m_wakeup_pipe[1], F_SETFL, O_NONBLOCK);

#ifdef __APPLE__
    m_kqueue_fd = kqueue();
    if (m_kqueue_fd < 0) {
        UEL_LOG("Failed to create kqueue");
    }
    
    // Register wake-up pipe with kqueue
    struct kevent ev;
    EV_SET(&ev, m_wakeup_pipe[0], EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, nullptr);
    kevent(m_kqueue_fd, &ev, 1, nullptr, 0, nullptr);
#endif
    
    m_last_timer_tick = std::chrono::steady_clock::now();
    
    LOG_DEBUG("UnifiedEventLoop: Initialized");
}

UnifiedEventLoop::~UnifiedEventLoop() {
    stop();
    
    if (m_wakeup_pipe[0] >= 0) close(m_wakeup_pipe[0]);
    if (m_wakeup_pipe[1] >= 0) close(m_wakeup_pipe[1]);
    
#ifdef __APPLE__
    if (m_kqueue_fd >= 0) close(m_kqueue_fd);
#endif
    
    LOG_DEBUG("UnifiedEventLoop: Destroyed");
}

void UnifiedEventLoop::start(EventHandler handler) {
    if (m_running.load(std::memory_order_acquire)) {
        LOG_WARN("UnifiedEventLoop: Already running");
        return;
    }
    
    m_event_handler = handler;
    m_running.store(true, std::memory_order_release);
    m_stopping.store(false, std::memory_order_release);
    
    LOG_INFO("UnifiedEventLoop: Starting single-threaded event loop");
    
    // Run the event loop in the current thread
    runLoop();
}

void UnifiedEventLoop::stop() {
    if (!m_running.load(std::memory_order_acquire)) {
        return;
    }
    
    LOG_INFO("UnifiedEventLoop: Stopping");
    m_stopping.store(true, std::memory_order_release);
    m_running.store(false, std::memory_order_release);
    
    // Wake up the loop to exit
    wakeup();
}

void UnifiedEventLoop::registerFd(int fd, FdType type, const std::string& peer_id) {
    if (fd < 0) return;
    
    // Set to non-blocking
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    
    {
        std::lock_guard<std::mutex> lock(m_fds_mutex);
        m_fds[fd] = {fd, type, peer_id};
        m_fds_dirty.store(true, std::memory_order_release);
    }
    
#ifdef __APPLE__
    struct kevent ev;
    EV_SET(&ev, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, nullptr);
    kevent(m_kqueue_fd, &ev, 1, nullptr, 0, nullptr);
#endif
    
    LOG_DEBUG("UnifiedEventLoop: Registered fd=" + std::to_string(fd) + 
              " type=" + std::to_string(static_cast<int>(type)) + 
              " peer=" + peer_id);
    
    wakeup();
}

void UnifiedEventLoop::unregisterFd(int fd) {
    if (fd < 0) return;
    
    {
        std::lock_guard<std::mutex> lock(m_fds_mutex);
        m_fds.erase(fd);
        m_fds_dirty.store(true, std::memory_order_release);
    }
    
#ifdef __APPLE__
    struct kevent ev;
    EV_SET(&ev, fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
    kevent(m_kqueue_fd, &ev, 1, nullptr, 0, nullptr);
#endif
    
    LOG_DEBUG("UnifiedEventLoop: Unregistered fd=" + std::to_string(fd));
}

void UnifiedEventLoop::setReadCallback(DataCallback callback) {
    m_read_callback = callback;
}

void UnifiedEventLoop::setAcceptCallback(AcceptCallback callback) {
    m_accept_callback = callback;
}

void UnifiedEventLoop::setDisconnectCallback(DisconnectCallback callback) {
    m_disconnect_callback = callback;
}

void UnifiedEventLoop::pushEvent(SessionEvent event) {
    if (m_stopping.load(std::memory_order_acquire)) {
        return;
    }
    
    {
        std::lock_guard<std::mutex> lock(m_event_mutex);
        m_event_queue.push(std::move(event));
    }
    
    wakeup();
}

void UnifiedEventLoop::setTimerInterval(int interval_ms) {
    m_timer_interval_ms = interval_ms;
}

void UnifiedEventLoop::addScheduledEvent(const std::string& id, SessionEvent event,
                                         std::chrono::steady_clock::time_point due_time) {
    std::lock_guard<std::mutex> lock(m_scheduled_mutex);
    
    // Remove existing event with same ID
    m_scheduled_events.erase(
        std::remove_if(m_scheduled_events.begin(), m_scheduled_events.end(),
                       [&id](const ScheduledEvent& e) { return e.id == id; }),
        m_scheduled_events.end()
    );
    
    m_scheduled_events.push_back({id, std::move(event), due_time});
    
    // Sort by due time
    std::sort(m_scheduled_events.begin(), m_scheduled_events.end(),
              [](const ScheduledEvent& a, const ScheduledEvent& b) {
                  return a.due_time < b.due_time;
              });
    
    LOG_DEBUG("UnifiedEventLoop: Scheduled event added, id=" + id);
}

void UnifiedEventLoop::removeScheduledEvent(const std::string& id) {
    std::lock_guard<std::mutex> lock(m_scheduled_mutex);
    m_scheduled_events.erase(
        std::remove_if(m_scheduled_events.begin(), m_scheduled_events.end(),
                       [&id](const ScheduledEvent& e) { return e.id == id; }),
        m_scheduled_events.end()
    );
}

void UnifiedEventLoop::clearScheduledEvents() {
    std::lock_guard<std::mutex> lock(m_scheduled_mutex);
    m_scheduled_events.clear();
}

void UnifiedEventLoop::wakeup() {
    char c = 1;
    ssize_t n = write(m_wakeup_pipe[1], &c, 1);
    (void)n; // Ignore result
}

void UnifiedEventLoop::runLoop() {
    LOG_INFO("UnifiedEventLoop: Entering main loop");
    
    while (m_running.load(std::memory_order_acquire) && 
           !m_stopping.load(std::memory_order_acquire)) {
        
        int timeout_ms = calculateNextTimeout();
        
#ifdef __APPLE__
        // macOS: Use kqueue
        struct timespec timeout;
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_nsec = (timeout_ms % 1000) * 1000000;
        
        struct kevent events[64];
        int nev = kevent(m_kqueue_fd, nullptr, 0, events, 64, &timeout);
        
        if (nev < 0) {
            if (errno != EINTR) {
                UEL_LOG("kevent error");
            }
            continue;
        }
        
        for (int i = 0; i < nev; i++) {
            int fd = static_cast<int>(events[i].ident);
            
            // Handle wake-up pipe
            if (fd == m_wakeup_pipe[0]) {
                char buf[256];
                while (read(m_wakeup_pipe[0], buf, sizeof(buf)) > 0) {}
                continue;
            }
            
            // Check for errors/disconnect
            if (events[i].flags & (EV_EOF | EV_ERROR)) {
                // Never call user callbacks while holding m_fds_mutex.
                // Callbacks may register/unregister fds, which would deadlock.
                std::string peer_id;
                {
                    std::lock_guard<std::mutex> lock(m_fds_mutex);
                    auto it = m_fds.find(fd);
                    if (it != m_fds.end()) {
                        peer_id = it->second.peer_id;
                    }
                }
                if (!peer_id.empty() && m_disconnect_callback) {
                    m_disconnect_callback(fd, peer_id);
                }
                continue;
            }
            
            // Handle readable event
            if (events[i].filter == EVFILT_READ) {
                UnifiedEventLoop::FdType type;
                std::string peer_id;
                bool found = false;
                {
                    std::lock_guard<std::mutex> lock(m_fds_mutex);
                    auto it = m_fds.find(fd);
                    if (it != m_fds.end()) {
                        type = it->second.type;
                        peer_id = it->second.peer_id;
                        found = true;
                    }
                }

                if (found) {
                    if (type == FdType::TCP_LISTEN) {
                        if (m_accept_callback) {
                            m_accept_callback(fd);
                        }
                    } else {
                        if (m_read_callback) {
                            m_read_callback(fd, peer_id);
                        }
                    }
                }
            }
        }
#else
        // Linux/Android: Use poll
        rebuildPollFds();
        
        int nfds = poll(m_pollfds.data(), m_pollfds.size(), timeout_ms);
        
        if (nfds < 0) {
            if (errno != EINTR) {
                UEL_LOG("poll error");
            }
            continue;
        }
        
        for (size_t i = 0; i < m_pollfds.size() && nfds > 0; i++) {
            if (m_pollfds[i].revents == 0) continue;
            nfds--;
            
            int fd = m_pollfds[i].fd;
            
            // Handle wake-up pipe
            if (fd == m_wakeup_pipe[0]) {
                char buf[256];
                while (read(m_wakeup_pipe[0], buf, sizeof(buf)) > 0) {}
                continue;
            }
            
            // Check for errors/disconnect
            if (m_pollfds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                // Never call user callbacks while holding m_fds_mutex.
                // Callbacks may register/unregister fds, which would deadlock.
                std::string peer_id;
                {
                    std::lock_guard<std::mutex> lock(m_fds_mutex);
                    auto it = m_fds.find(fd);
                    if (it != m_fds.end()) {
                        peer_id = it->second.peer_id;
                    }
                }
                if (!peer_id.empty() && m_disconnect_callback) {
                    m_disconnect_callback(fd, peer_id);
                }
                continue;
            }
            
            // Handle readable event
            if (m_pollfds[i].revents & POLLIN) {
                UnifiedEventLoop::FdType type;
                std::string peer_id;
                bool found = false;
                {
                    std::lock_guard<std::mutex> lock(m_fds_mutex);
                    auto it = m_fds.find(fd);
                    if (it != m_fds.end()) {
                        type = it->second.type;
                        peer_id = it->second.peer_id;
                        found = true;
                    }
                }

                if (found) {
                    if (type == FdType::TCP_LISTEN) {
                        if (m_accept_callback) {
                            m_accept_callback(fd);
                        }
                    } else {
                        if (m_read_callback) {
                            m_read_callback(fd, peer_id);
                        }
                    }
                }
            }
        }
#endif
        
        // Process internal event queue
        processPendingEvents();
        
        // Process timers
        processTimers();
    }
    
    LOG_INFO("UnifiedEventLoop: Exited main loop");
}

void UnifiedEventLoop::processPendingEvents() {
    std::queue<SessionEvent> events_to_process;
    {
        std::lock_guard<std::mutex> lock(m_event_mutex);
        std::swap(events_to_process, m_event_queue);
    }
    
    while (!events_to_process.empty() && m_event_handler) {
        m_event_handler(events_to_process.front());
        events_to_process.pop();
    }
}

void UnifiedEventLoop::processTimers() {
    auto now = std::chrono::steady_clock::now();
    
    // Process scheduled events
    {
        std::lock_guard<std::mutex> lock(m_scheduled_mutex);
        while (!m_scheduled_events.empty() && 
               m_scheduled_events.front().due_time <= now) {
            if (m_event_handler) {
                m_event_handler(m_scheduled_events.front().event);
            }
            m_scheduled_events.erase(m_scheduled_events.begin());
        }
    }
    
    // Check periodic timer
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - m_last_timer_tick).count();
    
    if (elapsed >= m_timer_interval_ms) {
        m_last_timer_tick = now;
        if (m_event_handler) {
            m_event_handler(TimerTickEvent{});
        }
    }
}

int UnifiedEventLoop::calculateNextTimeout() {
    auto now = std::chrono::steady_clock::now();
    int timeout = m_timer_interval_ms;
    
    // Check for scheduled events
    {
        std::lock_guard<std::mutex> lock(m_scheduled_mutex);
        if (!m_scheduled_events.empty()) {
            auto next_due = m_scheduled_events.front().due_time;
            auto ms_until = std::chrono::duration_cast<std::chrono::milliseconds>(
                next_due - now).count();
            if (ms_until < timeout && ms_until > 0) {
                timeout = static_cast<int>(ms_until);
            } else if (ms_until <= 0) {
                timeout = 0;  // Process immediately
            }
        }
    }
    
    // Check remaining time until next periodic tick
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - m_last_timer_tick).count();
    int remaining = m_timer_interval_ms - static_cast<int>(elapsed);
    if (remaining < timeout && remaining > 0) {
        timeout = remaining;
    } else if (remaining <= 0) {
        timeout = 0;  // Process immediately
    }
    
    // Clamp to reasonable range
    if (timeout < 0) timeout = 0;
    if (timeout > 1000) timeout = 1000;  // Max 1 second
    
    return timeout;
}

#ifndef __APPLE__
void UnifiedEventLoop::rebuildPollFds() {
    if (!m_fds_dirty.load(std::memory_order_acquire)) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(m_fds_mutex);
    
    m_pollfds.clear();
    
    // Add wake-up pipe
    m_pollfds.push_back({m_wakeup_pipe[0], POLLIN, 0});
    
    // Add all registered file descriptors
    for (const auto& [fd, info] : m_fds) {
        m_pollfds.push_back({fd, POLLIN, 0});
    }
    
    m_fds_dirty.store(false, std::memory_order_release);
}
#endif
