#include "logger.h"
#include <mutex>
#include <random>
#include <algorithm>
#include <string>
#include <iostream>
#include <cstring>
#include <queue>
#include <thread>
#include <condition_variable>
#include <atomic>

#ifdef HAVE_JNI
#include "jni_bridge.h"
#include <android/log.h>
#endif

/**
 * @brief The session ID for logging.
 */
static std::string g_sessionId = "NO_SESSION";

/**
 * @brief Mutex for protecting the logger.
 */
static std::mutex g_logMutex;

/**
 * @brief Global log level (for conditional logging)
 * Default: INFO (skips DEBUG messages)
 */
static LogLevel g_log_level = LogLevel::INFO;

/**
 * @brief Global async logging state
 */
static std::atomic<bool> g_async_logging_enabled(false);
static std::queue<std::string> g_log_queue;
static std::mutex g_log_queue_mutex;
static std::condition_variable g_log_queue_cv;
static std::atomic<bool> g_log_thread_running(false);
static std::unique_ptr<std::thread> g_log_thread;

/**
 * @brief Generates a random session ID.
 * @param len The length of the session ID to generate.
 * @return The generated session ID.
 */
std::string generate_session_id(size_t len) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    std::string tmp_s;
    tmp_s.reserve(len);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, sizeof(alphanum) - 2);

    for (size_t i = 0; i < len; ++i) {
        tmp_s += alphanum[distrib(gen)];
    }

    return tmp_s;
}

/**
 * @brief Sets the session ID for logging.
 * @param session_id The session ID to set.
 */
void setSessionId(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    g_sessionId = session_id;
}

/**
 * @brief Sets the global log level (for conditional logging)
 * @param level The log level to set.
 */
void set_log_level(LogLevel level) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    g_log_level = level;
}

/**
 * @brief Gets the current global log level
 * @return The current log level.
 */
LogLevel get_log_level() {
    std::lock_guard<std::mutex> lock(g_logMutex);
    return g_log_level;
}

/**
 * @brief Background thread worker for async logging
 */
void async_log_worker() {
    while (g_log_thread_running) {
        std::unique_lock<std::mutex> lock(g_log_queue_mutex);
        g_log_queue_cv.wait(lock, [&] { return !g_log_queue.empty() || !g_log_thread_running; });
        
        if (!g_log_queue.empty()) {
            auto msg = std::move(g_log_queue.front());
            g_log_queue.pop();
            lock.unlock();
            
            // Send log message without holding lock
            // This allows new messages to be queued while we're logging
#ifdef HAVE_JNI
            __android_log_print(ANDROID_LOG_INFO, "LiteP2P_Native", "%s", msg.c_str());
            sendToLogUI(msg);
#else
            std::cerr << msg << std::endl;
#endif
        }
    }
}

/**
 * @brief Enables async logging (non-blocking)
 */
void enable_async_logging() {
    if (g_async_logging_enabled) return;
    
    std::lock_guard<std::mutex> lock(g_logMutex);
    g_async_logging_enabled = true;
    g_log_thread_running = true;
    g_log_thread = std::make_unique<std::thread>(async_log_worker);
}

/**
 * @brief Disables async logging and flushes remaining messages
 */
void disable_async_logging() {
    if (!g_async_logging_enabled) return;
    
    g_log_thread_running = false;
    g_log_queue_cv.notify_all();
    
    if (g_log_thread && g_log_thread->joinable()) {
        g_log_thread->join();
    }
    
    g_async_logging_enabled = false;
}

/**
 * @brief Check if async logging is enabled
 */
bool is_async_logging_enabled() {
    return g_async_logging_enabled.load();
}

/**
 * @brief Logs a message to the native log.
 * @param message The message to log.
 */
void nativeLog(const std::string& message) {
    std::string log_message = "[" + g_sessionId + "] " + message;
    
    if (is_async_logging_enabled()) {
        // OPTIMIZATION: Non-blocking push to queue
        {
            std::lock_guard<std::mutex> lock(g_log_queue_mutex);
            g_log_queue.push(log_message);
        }
        g_log_queue_cv.notify_one();
    } else {
        // Synchronous logging (original behavior)
        std::lock_guard<std::mutex> lock(g_logMutex);
#ifdef HAVE_JNI
        __android_log_print(ANDROID_LOG_INFO, "LiteP2P_Native", "%s", log_message.c_str());
        sendToLogUI(log_message);
#else
        std::cerr << log_message << std::endl;
#endif
    }
}

