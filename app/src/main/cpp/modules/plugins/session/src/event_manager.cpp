#include "event_manager.h"
#include "logger.h"
#include "config_manager.h"
#include <chrono>
#include <iomanip>
#include <sstream>
#include <iostream>

#if HAVE_JNI
#include <android/log.h>

// Direct native logging to bypass any logging configuration issues
#define NATIVELOGD(msg) __android_log_write(ANDROID_LOG_DEBUG, "Litep2p", msg)
#define NATIVELOGV(msg) __android_log_write(ANDROID_LOG_VERBOSE, "Litep2p", msg)
#define NATIVELOGW(msg) __android_log_write(ANDROID_LOG_WARN, "Litep2p", msg)
#else
// Desktop stubs
#include <cstdio>
#include <cstdlib>

namespace {
inline bool em_native_logs_enabled() {
    static const bool enabled = []() {
        const char* v = std::getenv("LITEP2P_EM_NATIVELOG");
        if (!v) return false;
        // Treat any value other than an explicit "0" as enabled.
        return std::string(v) != "0";
    }();
    return enabled;
}
} // namespace
#define NATIVELOGD(msg) { \
    if (em_native_logs_enabled()) { \
        auto now = std::chrono::system_clock::now(); \
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000; \
        auto time = std::chrono::system_clock::to_time_t(now); \
        std::cout << "[" << std::put_time(std::localtime(&time), "%H:%M:%S") << "." << std::setfill('0') << std::setw(3) << ms.count() << "] DEBUG: " << msg << std::endl; \
    } \
}
#define NATIVELOGV(msg) { \
    if (em_native_logs_enabled()) { \
        auto now = std::chrono::system_clock::now(); \
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000; \
        auto time = std::chrono::system_clock::to_time_t(now); \
        std::cout << "[" << std::put_time(std::localtime(&time), "%H:%M:%S") << "." << std::setfill('0') << std::setw(3) << ms.count() << "] VERBOSE: " << msg << std::endl; \
    } \
}
#define NATIVELOGW(msg) { \
    if (em_native_logs_enabled()) { \
        auto now = std::chrono::system_clock::now(); \
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000; \
        auto time = std::chrono::system_clock::to_time_t(now); \
        std::cout << "[" << std::put_time(std::localtime(&time), "%H:%M:%S") << "." << std::setfill('0') << std::setw(3) << ms.count() << "] WARN: " << msg << std::endl; \
    } \
}
#endif

// Single-thread mode check - available on all platforms
namespace {
inline bool single_thread_mode_enabled() {
    static const bool enabled = []() {
#if defined(LITEP2P_SINGLE_THREAD_MODE_COMPILE) && LITEP2P_SINGLE_THREAD_MODE_COMPILE
        return true;  // Compile-time enabled
#else
        const char* v = std::getenv("LITEP2P_SINGLE_THREAD_MODE");
        if (!v) return false;
        return std::string(v) != "0";
#endif
    }();
    return enabled;
}
} // namespace

EventManager::EventManager() : m_running(false), m_stopping(false) {
    // Check if single-thread mode is enabled (respects compile-time flag)
    m_single_thread_mode = single_thread_mode_enabled();
    
    if (m_single_thread_mode) {
        m_unified_loop = std::make_unique<UnifiedEventLoop>();
        LOG_INFO("EM: Single-thread mode enabled - using UnifiedEventLoop");
    }
}

EventManager::~EventManager() {
    stopEventProcessing();
    stopTimerLoop();
}

void EventManager::pushEvent(SessionEvent event) {
    // Don't add new events when stopping
    if (m_stopping) {
        LOG_DEBUG("EM: Ignoring event push - event manager is stopping");
        return;
    }
    
    // In single-thread mode, push to unified loop
    if (m_single_thread_mode && m_unified_loop) {
        m_unified_loop->pushEvent(std::move(event));
        return;
    }
    
    std::string eventType = "Unknown";
    std::visit([&eventType](auto&& arg) {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, PeerDiscoveredEvent>) eventType = "PeerDiscoveredEvent";
        else if constexpr (std::is_same_v<T, DataReceivedEvent>) eventType = "DataReceivedEvent";
        else if constexpr (std::is_same_v<T, PeerDisconnectEvent>) eventType = "PeerDisconnectEvent";
        else if constexpr (std::is_same_v<T, ConnectToPeerEvent>) eventType = "ConnectToPeerEvent";
        else if constexpr (std::is_same_v<T, SendMessageEvent>) eventType = "SendMessageEvent";
        else if constexpr (std::is_same_v<T, TimerTickEvent>) eventType = "TimerTickEvent";
        else if constexpr (std::is_same_v<T, DiscoveryInitiatedEvent>) eventType = "DiscoveryInitiatedEvent";
        else if constexpr (std::is_same_v<T, MessageSendCompleteEvent>) eventType = "MessageSendCompleteEvent";
        else if constexpr (std::is_same_v<T, FSMEvent>) eventType = "FSMEvent";
    }, event);

    int queue_size = 0;
    {
        NATIVELOGW("EM_NATIVE: pushEvent - acquiring lock");
        std::lock_guard<std::mutex> lock(m_eventMutex);
        m_eventQueue.push(event);
        queue_size = m_eventQueue.size();
        NATIVELOGW("EM_NATIVE: pushEvent - releasing lock");
    }
    std::string msg = "EM_NATIVE: Event pushed to queue (" + eventType + "), size=" + std::to_string(queue_size);
    NATIVELOGW(msg.c_str());
    LOG_DEBUG("EM: Event pushed to queue (" + eventType + "), queue size now: " + std::to_string(queue_size));
    LOG_DEBUG("EM: Notifying event condition variable...");
    m_eventCv.notify_all();
    LOG_DEBUG("EM: Event notification sent");
}

void EventManager::startEventProcessing(std::function<void(const SessionEvent&)> eventHandler) {
    std::lock_guard<std::mutex> lifecycle_lock(m_lifecycleMutex);
    NATIVELOGW("EM_NATIVE: startEventProcessing called");
    LOG_INFO("EM: startEventProcessing called");

    // If already running, ignore duplicate start requests.
    if (m_running.load(std::memory_order_acquire) && !m_stopping.load(std::memory_order_acquire)) {
        LOG_WARN("EM: startEventProcessing called while already running - ignoring");
        return;
    }

    // Single-thread mode: use UnifiedEventLoop
    if (m_single_thread_mode && m_unified_loop) {
        LOG_INFO("EM: Starting in SINGLE-THREAD mode with UnifiedEventLoop");
        
        // Stop any previous run
        if (m_loop_thread.joinable()) {
            m_unified_loop->stop();
            m_loop_thread.join();
        }
        
        m_running = true;
        m_stopping = false;
        
        // Set timer interval from config
        int timer_interval = ConfigManager::getInstance().getTimerTickIntervalMs();
        m_unified_loop->setTimerInterval(timer_interval);
        
        // Start the unified loop in a dedicated thread
        // Note: The loop itself is single-threaded, but we run it in a thread
        // so that start() returns immediately (non-blocking API)
        m_loop_thread = std::thread([this, eventHandler]() {
            LOG_INFO("EM: UnifiedEventLoop thread started");
            m_unified_loop->start(eventHandler);
            LOG_INFO("EM: UnifiedEventLoop thread finished");
        });
        
        NATIVELOGW("EM_NATIVE: Single-thread event loop started");
        LOG_INFO("EM: Event processing started (single-thread mode)");
        return;
    }

    // Multi-thread mode (legacy)
    // If threads are still joinable from a previous run (or concurrent stop), stop them first.
    if (m_processingThread.joinable() || m_timerThread.joinable()) {
        LOG_WARN("EM: startEventProcessing found joinable threads - stopping previous run first");
        m_stopping = true;
        m_eventCv.notify_all();
        m_timerCv.notify_all();
        if (m_processingThread.joinable()) {
            m_processingThread.join();
        }
        if (m_timerThread.joinable()) {
            m_timerThread.join();
        }
        m_running = false;
    }

    m_running = true;
    m_stopping = false;
    
    // Start event processing thread
    NATIVELOGW("EM_NATIVE: About to create processing thread");
    LOG_INFO("EM: Starting event processing thread...");
    m_processingThread = std::thread([this, eventHandler]() {
        NATIVELOGW("EM_NATIVE: Processing thread lambda STARTED!");
        LOG_INFO("EM: Event processing thread lambda started - about to call processEventQueue");
        processEventQueue(eventHandler);
        NATIVELOGW("EM_NATIVE: Processing thread lambda FINISHED!");
        LOG_INFO("EM: Event processing thread lambda finished");
    });
    NATIVELOGW("EM_NATIVE: Processing thread created");
    LOG_INFO("EM: Event processing thread created, joinable=" + std::to_string(m_processingThread.joinable()));
    
    // Start timer thread
    NATIVELOGW("EM_NATIVE: About to create timer thread");
    LOG_INFO("EM: Starting timer thread...");
    m_timerThread = std::thread([this]() {
        NATIVELOGW("EM_NATIVE: Timer thread lambda STARTED!");
        timerLoop();
        NATIVELOGW("EM_NATIVE: Timer thread lambda FINISHED!");
    });
    NATIVELOGW("EM_NATIVE: Timer thread created");
    LOG_INFO("EM: Timer thread created, joinable=" + std::to_string(m_timerThread.joinable()));
    
    NATIVELOGW("EM_NATIVE: Event processing threads started - returning from startEventProcessing");
    LOG_INFO("EM: Event processing threads started");
}

void EventManager::stopEventProcessing() {
    std::lock_guard<std::mutex> lifecycle_lock(m_lifecycleMutex);
    LOG_INFO("EM: stopEventProcessing called, setting m_stopping=true");
    m_stopping = true;
    
    // Single-thread mode: stop unified loop
    if (m_single_thread_mode && m_unified_loop) {
        LOG_INFO("EM: Stopping UnifiedEventLoop...");
        m_unified_loop->stop();
        
        if (m_loop_thread.joinable()) {
            m_loop_thread.join();
            LOG_INFO("EM: UnifiedEventLoop thread joined successfully");
        }
        
        m_running = false;
        LOG_INFO("EM: Event processing stopped (single-thread mode)");
        return;
    }
    
    // Multi-thread mode
    m_eventCv.notify_all();
    m_timerCv.notify_all();
    
    LOG_INFO("EM: Joining processing thread...");
    if (m_processingThread.joinable()) {
        m_processingThread.join();
        LOG_INFO("EM: Processing thread joined successfully");
    } else {
        LOG_INFO("EM: Processing thread was not joinable");
    }
    
    LOG_INFO("EM: Joining timer thread...");
    if (m_timerThread.joinable()) {
        m_timerThread.join();
        LOG_INFO("EM: Timer thread joined successfully");
    } else {
        LOG_INFO("EM: Timer thread was not joinable");
    }
    
    m_running = false;
    
    LOG_INFO("EM: Event processing threads stopped");
}

void EventManager::processEventQueue(std::function<void(const SessionEvent&)> eventHandler) {
    NATIVELOGW("EM_NATIVE: processEventQueue STARTED");
    LOG_INFO("EM: Event processing thread started");
    
    const int QUEUE_WAIT_TIMEOUT_MS = ConfigManager::getInstance().getEventQueueWaitTimeoutMs();
    int event_count = 0;
    int empty_iterations = 0;
    while (m_running && !m_stopping) {
        {
            NATIVELOGW("EM_NATIVE: processEventQueue - acquiring lock");
            std::unique_lock<std::mutex> lock(m_eventMutex);
            // NATIVELOGW("EM_NATIVE: processEventQueue - lock acquired, waiting");
            // Add timeout to prevent indefinite blocking during shutdown
            bool has_event = m_eventCv.wait_for(lock, std::chrono::milliseconds(QUEUE_WAIT_TIMEOUT_MS), 
                              [this] { return !m_eventQueue.empty() || !m_running || m_stopping; });
            
            // NATIVELOGW("EM_NATIVE: processEventQueue - wait returned");

            if (!m_running || m_stopping) {
                NATIVELOGW("EM_NATIVE: Breaking from loop - not running");
                LOG_INFO("EM: Event processing thread stopping - event manager not running");
                break;
            }
            
            if (m_eventQueue.empty()) {
                empty_iterations++;
                if (empty_iterations % 50 == 0) {  // Log every 50 empty iterations (~5 seconds)
                    std::string msg = "EM_NATIVE: Queue empty after " + std::to_string(empty_iterations) + " iterations";
                    NATIVELOGW(msg.c_str());
                }
                continue;
            }
            
            empty_iterations = 0;  // Reset counter when we get an event
            SessionEvent event = std::move(m_eventQueue.front());
            m_eventQueue.pop();
            
            event_count++;
            
            // IMPORTANT: Unlock before logging and calling eventHandler to avoid blocking new events from being pushed
            lock.unlock();
            
            std::string eventType = "Unknown";
            std::visit([&eventType](auto&& arg) {
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, PeerDiscoveredEvent>) eventType = "PeerDiscoveredEvent";
                else if constexpr (std::is_same_v<T, DataReceivedEvent>) eventType = "DataReceivedEvent";
                else if constexpr (std::is_same_v<T, PeerDisconnectEvent>) eventType = "PeerDisconnectEvent";
                else if constexpr (std::is_same_v<T, ConnectToPeerEvent>) eventType = "ConnectToPeerEvent";
                else if constexpr (std::is_same_v<T, SendMessageEvent>) eventType = "SendMessageEvent";
                else if constexpr (std::is_same_v<T, TimerTickEvent>) eventType = "TimerTickEvent";
                else if constexpr (std::is_same_v<T, DiscoveryInitiatedEvent>) eventType = "DiscoveryInitiatedEvent";
                else if constexpr (std::is_same_v<T, MessageSendCompleteEvent>) eventType = "MessageSendCompleteEvent";
                else if constexpr (std::is_same_v<T, FSMEvent>) eventType = "FSMEvent";
            }, event);
            
            // Extremely verbose native logging (esp. TimerTick) is gated behind an env var on desktop.
            // On Android, this is intentionally suppressed to avoid logcat spam.
#if !HAVE_JNI
            if (eventType != "TimerTickEvent" && em_native_logs_enabled()) {
                std::string msg = "EM_NATIVE: PROCESSING EVENT #" + std::to_string(event_count) + " (" + eventType + ")";
                NATIVELOGW(msg.c_str());
            }
#endif
            LOG_DEBUG("EM: Processing event #" + std::to_string(event_count) + " (" + eventType + ") from queue");
            
            // Check stopping state again before processing event
            if (m_stopping) {
                NATIVELOGW("EM_NATIVE: Stopping flag set, skipping event");
                LOG_INFO("EM: Skipping event processing - event manager is stopping");
                continue;
            }
            
            LOG_DEBUG("EM: Calling eventHandler for event #" + std::to_string(event_count));
            try {
                // Process event using the provided handler
#if !HAVE_JNI
                if (em_native_logs_enabled() && eventType != "TimerTickEvent") {
                    fprintf(stderr, "EM_NATIVE: About to call eventHandler for event #%d\n", event_count);
                    NATIVELOGW("EM_NATIVE: About to call eventHandler");
                }
#endif
                eventHandler(event);
#if !HAVE_JNI
                if (em_native_logs_enabled() && eventType != "TimerTickEvent") {
                    NATIVELOGW("EM_NATIVE: eventHandler returned successfully");
                }
#endif
                LOG_DEBUG("EM: eventHandler returned for event #" + std::to_string(event_count));
            } catch (const std::exception& e) {
                std::string err_msg = std::string("EM_NATIVE: Exception in eventHandler: ") + e.what();
                NATIVELOGW(err_msg.c_str());
                LOG_WARN("EM: Error processing event: " + std::string(e.what()));
            }
        }  // Lock released here
    }
    
#if HAVE_JNI
    NATIVELOGW(("EM_NATIVE: processEventQueue EXITED - processed " + std::to_string(event_count) + " events").c_str());
#else
    if (em_native_logs_enabled()) {
        NATIVELOGW(("EM_NATIVE: processEventQueue EXITED - processed " + std::to_string(event_count) + " events").c_str());
    }
#endif
    LOG_INFO("EM: Event processing thread stopped (processed " + std::to_string(event_count) + " events)");
}

void EventManager::timerLoop() {
    LOG_INFO("EM: Timer thread started");
    
    // Timer interval for maintenance tasks (heartbeat, batching, cleanup) - from config
    const int TIMER_INTERVAL_MS = ConfigManager::getInstance().getTimerTickIntervalMs();
    const int THREAD_SLEEP_MS = ConfigManager::getInstance().getEventThreadSleepMs();
    auto last_tick_time = std::chrono::steady_clock::now();
    
    while (m_running && !m_stopping) {
        // LOG_DEBUG("EM: Timer thread loop iteration, m_running=" + std::to_string(m_running.load()) + ", m_stopping=" + std::to_string(m_stopping.load()));
        {
            std::unique_lock<std::mutex> lock(m_timerMutex);
            (void)m_timerCv.wait_for(lock, std::chrono::milliseconds(THREAD_SLEEP_MS), [this] {
                return m_stopping.load(std::memory_order_acquire) || !m_running.load(std::memory_order_acquire);
            });
        }
        
        // Check if we're stopping before processing events
        // LOG_DEBUG("EM: Checking m_stopping flag: " + std::to_string(m_stopping.load()));
        if (m_stopping) {
            LOG_INFO("EM: Timer thread stopping - event manager is stopping");
            break;
        }
        
        // Process scheduled events (heartbeat timers, reconnect timers, etc.)
        // NOTE: Only push scheduled events, NOT generic TimerTickEvent
        // TimerTickEvent was being pushed every 100ms and causing queue accumulation
        {
            std::lock_guard<std::mutex> lock(m_scheduledEventsMutex);
            auto now = std::chrono::steady_clock::now();
            auto it = m_scheduledEvents.begin();
            while (it != m_scheduledEvents.end()) {
                if (now >= it->second.due_time) {
                    // Only push events if not stopping
                    if (!m_stopping) {
                        pushEvent(it->second.event);
                    }
                    it = m_scheduledEvents.erase(it);
                } else {
                    ++it;
                }
            }
        }
        
        // Push periodic TimerTickEvent for maintenance tasks (every TIMER_INTERVAL_MS)
        // Maintenance manager will use this to:
        // - Send heartbeat PING every 10 seconds
        // - Flush message batches
        // - Clean up expired sessions
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_tick_time).count();
        
        if (elapsed >= TIMER_INTERVAL_MS) {
            last_tick_time = now;
            if (!m_stopping) {
                LOG_DEBUG("EM: Pushing TimerTickEvent (elapsed=" + std::to_string(elapsed) + "ms)");
                pushEvent(TimerTickEvent{});
            }
        }
    }
    
    LOG_INFO("EM: Timer thread stopped, m_running=" + std::to_string(m_running.load()) + ", m_stopping=" + std::to_string(m_stopping.load()));
}

void EventManager::stopTimerLoop() {
    // The timer loop will stop automatically when m_stopping is set to true
    // and the thread checks this condition in its loop
    LOG_INFO("EM: Timer loop stop requested");

    // Also wake it immediately in case it's currently sleeping.
    m_timerCv.notify_all();
}

void EventManager::addScheduledEvent(const std::string& peerId, SessionEvent event, 
                                    std::chrono::steady_clock::time_point dueTime) {
    // Single-thread mode: delegate to unified loop
    if (m_single_thread_mode && m_unified_loop) {
        m_unified_loop->addScheduledEvent(peerId, event, dueTime);
        LOG_INFO("EM: Scheduled event added for peer (unified loop): " + peerId);
        return;
    }
    
    // Multi-thread mode
    std::lock_guard<std::mutex> lock(m_scheduledEventsMutex);
    m_scheduledEvents[peerId] = {event, dueTime};
    LOG_INFO("EM: Scheduled event added for peer: " + peerId);
}

void EventManager::clearScheduledEvents() {
    // Single-thread mode: delegate to unified loop
    if (m_single_thread_mode && m_unified_loop) {
        m_unified_loop->clearScheduledEvents();
        LOG_INFO("EM: Scheduled events cleared (unified loop)");
        return;
    }
    
    // Multi-thread mode
    std::lock_guard<std::mutex> lock(m_scheduledEventsMutex);
    m_scheduledEvents.clear();
    LOG_INFO("EM: Scheduled events cleared");
}