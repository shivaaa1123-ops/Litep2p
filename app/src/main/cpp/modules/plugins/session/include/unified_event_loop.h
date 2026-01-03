#ifndef UNIFIED_EVENT_LOOP_H
#define UNIFIED_EVENT_LOOP_H

#include "session_events.h"
#include <functional>
#include <map>
#include <vector>
#include <queue>
#include <mutex>
#include <atomic>
#include <chrono>
#include <string>

#ifdef __APPLE__
#include <sys/event.h>
#else
#include <poll.h>
#endif

/**
 * @brief UnifiedEventLoop - Single-threaded event loop for minimal CPU/RAM footprint
 * 
 * This class consolidates all I/O and timer handling into a single poll()/kqueue() loop,
 * eliminating the need for multiple threads. This design is optimal for:
 * - Low CPU usage (no thread context switching)
 * - Minimal memory footprint (no per-connection thread stacks)
 * - Scalability to thousands of peers
 * 
 * Architecture:
 * - Uses poll() on Linux/Android, kqueue() on macOS for efficient I/O multiplexing
 * - Timers are implemented using the poll timeout or timerfd
 * - Events are processed inline in the main loop
 * - Event queue for internal events (discovery, FSM, etc.)
 */
class UnifiedEventLoop {
public:
    // Callback types
    using DataCallback = std::function<void(int fd, const std::string& peer_id)>;
    using AcceptCallback = std::function<void(int listen_fd)>;
    using TimerCallback = std::function<void()>;
    using EventHandler = std::function<void(const SessionEvent&)>;
    using DisconnectCallback = std::function<void(int fd, const std::string& peer_id)>;

    // File descriptor types for registration
    enum class FdType {
        TCP_LISTEN,      // TCP server socket (accept)
        TCP_CLIENT,      // TCP client socket (read/write)
        UDP_SOCKET       // UDP socket (read/write)
    };

    UnifiedEventLoop();
    ~UnifiedEventLoop();

    // Lifecycle
    void start(EventHandler handler);
    void stop();
    bool isRunning() const { return m_running.load(std::memory_order_acquire); }

    // File descriptor management
    void registerFd(int fd, FdType type, const std::string& peer_id = "");
    void unregisterFd(int fd);
    void setReadCallback(DataCallback callback);
    void setAcceptCallback(AcceptCallback callback);
    void setDisconnectCallback(DisconnectCallback callback);

    // Event queue (for internal events like discovery, FSM transitions)
    void pushEvent(SessionEvent event);

    // Timer management
    void setTimerInterval(int interval_ms);
    void addScheduledEvent(const std::string& id, SessionEvent event, 
                          std::chrono::steady_clock::time_point due_time);
    void removeScheduledEvent(const std::string& id);
    void clearScheduledEvents();

    // Wake up the event loop (e.g., when new events are pushed)
    void wakeup();

private:
    void runLoop();
    void processPendingEvents();
    void processTimers();
    void rebuildPollFds();
    int calculateNextTimeout();

    // Scheduled event structure
    struct ScheduledEvent {
        std::string id;
        SessionEvent event;
        std::chrono::steady_clock::time_point due_time;
    };

    // File descriptor info
    struct FdInfo {
        int fd;
        FdType type;
        std::string peer_id;
    };

    // State
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_stopping{false};

    // File descriptors
    std::map<int, FdInfo> m_fds;
    std::mutex m_fds_mutex;
    std::atomic<bool> m_fds_dirty{false};  // Rebuild poll array when true

#ifdef __APPLE__
    int m_kqueue_fd{-1};
#else
    std::vector<struct pollfd> m_pollfds;
#endif

    // Wake-up pipe for cross-thread signaling
    int m_wakeup_pipe[2]{-1, -1};

    // Event queue
    std::queue<SessionEvent> m_event_queue;
    std::mutex m_event_mutex;

    // Scheduled events (sorted by due time)
    std::vector<ScheduledEvent> m_scheduled_events;
    std::mutex m_scheduled_mutex;

    // Timer interval for periodic ticks
    int m_timer_interval_ms{500};  // Default 500ms
    std::chrono::steady_clock::time_point m_last_timer_tick;

    // Callbacks
    DataCallback m_read_callback;
    AcceptCallback m_accept_callback;
    DisconnectCallback m_disconnect_callback;
    EventHandler m_event_handler;
};

#endif // UNIFIED_EVENT_LOOP_H
