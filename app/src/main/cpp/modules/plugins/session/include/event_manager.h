#ifndef EVENT_MANAGER_H
#define EVENT_MANAGER_H

#include "session_events.h"
#include "scheduled_event.h"
#include "unified_event_loop.h"
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <functional>
#include <map>
#include <chrono>

/**
 * @brief EventManager - Manages event processing and timer handling
 * 
 * This class provides a high-level interface for event-driven programming.
 * Internally, it uses UnifiedEventLoop for efficient single-threaded processing.
 * 
 * The design supports two modes:
 * 1. SINGLE_THREAD mode (default): Uses UnifiedEventLoop for all processing
 * 2. MULTI_THREAD mode: Uses traditional thread-per-task model (legacy)
 * 
 * Set LITEP2P_SINGLE_THREAD_MODE=1 environment variable for single-thread mode.
 */
class EventManager {
public:
    EventManager();
    ~EventManager();
    
    // Event queue management
    void pushEvent(SessionEvent event);
    void startEventProcessing(std::function<void(const SessionEvent&)> eventHandler);
    void stopEventProcessing();
    
    // Timer management
    void startTimerLoop();
    void stopTimerLoop();
    void addScheduledEvent(const std::string& peerId, SessionEvent event, 
                          std::chrono::steady_clock::time_point dueTime);
    void clearScheduledEvents();
    
    // Access to unified event loop (for I/O integration)
    UnifiedEventLoop* getUnifiedEventLoop() { return m_unified_loop.get(); }
    
    // Check if running in single-thread mode
    bool isSingleThreadMode() const { return m_single_thread_mode; }
    
private:
    // Event processing (multi-thread mode)
    void processEventQueue(std::function<void(const SessionEvent&)> eventHandler);
    void timerLoop();
    
    // Single-thread mode runner
    void runSingleThreadLoop(std::function<void(const SessionEvent&)> eventHandler);
    
    struct ScheduledEvent {
        SessionEvent event;
        std::chrono::steady_clock::time_point due_time;
    };
    
    // Unified event loop (single-thread mode)
    std::unique_ptr<UnifiedEventLoop> m_unified_loop;
    std::thread m_loop_thread;  // Thread that runs the unified loop
    bool m_single_thread_mode{false};
    
    // Event queues and synchronization (multi-thread mode)
    std::queue<SessionEvent> m_eventQueue;
    std::mutex m_eventMutex;
    std::condition_variable m_eventCv;

    // Allows waking the timer thread immediately on shutdown.
    std::mutex m_timerMutex;
    std::condition_variable m_timerCv;
    std::thread m_processingThread;
    std::thread m_timerThread;

    // Serializes start/stop to avoid races and double-start std::terminate.
    std::mutex m_lifecycleMutex;
    
    // Scheduled events
    std::map<std::string, ScheduledEvent> m_scheduledEvents;
    std::mutex m_scheduledEventsMutex;
    
    // State management
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_stopping{false};
};
#endif // EVENT_MANAGER_H