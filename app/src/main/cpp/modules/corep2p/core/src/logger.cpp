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
#include <chrono>
#include <iomanip>
#include <sstream>
#include <cstdio>
#include <ctime>
#include <unistd.h>

#if HAVE_JNI
#include "jni_bridge.h"
#include <android/log.h>
#else
// Forward declaration for desktop builds
void sendToLogUI(const std::string& message) {
    // No-op on desktop
}
#endif

/**
 * @brief The session ID for logging.
 */
#if HAVE_JNI
static std::string g_sessionId = "NO_SESSION";
#else
static std::string g_sessionId = "DESKTOP";
#endif

/**
 * @brief Mutex for protecting the logger.
 */
// NOTE: We intentionally allocate the logger mutex dynamically and never destroy it.
// This avoids static destruction order issues where other global/static destructors
// attempt to log after the logger has been torn down, which can throw
// `std::system_error: mutex lock failed` on some platforms/libc++ builds.
static std::mutex& log_mutex() {
    static std::mutex* m = new std::mutex();
    return *m;
}
static std::function<void(const std::string&)> g_logCallback;

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
#if HAVE_JNI
    std::lock_guard<std::mutex> lock(log_mutex());
#endif
    g_sessionId = session_id;
}

void setLogCallback(std::function<void(const std::string&)> callback) {
#if HAVE_JNI
    std::lock_guard<std::mutex> lock(log_mutex());
#endif
    g_logCallback = callback;
}

/**
 * @brief Sets the global log level (for conditional logging)
 * @param level The log level to set.
 */
void set_log_level(LogLevel level) {
#if HAVE_JNI
    std::lock_guard<std::mutex> lock(log_mutex());
#endif
    g_log_level = level;
}

/**
 * @brief Gets the current global log level
 * @return The current log level.
 */
LogLevel get_log_level() {
#if HAVE_JNI
    std::lock_guard<std::mutex> lock(log_mutex());
#endif
    return g_log_level;
}

/**
 * @brief Get current timestamp for logging (used on desktop)
 */
static std::string get_timestamp() {
#if HAVE_JNI
    return "";  // Android uses system timestamp
#else
    // Avoid iostream/locale machinery here: during shutdown, locale/iostream internals may be
    // partially torn down and can throw std::system_error related to mutex locking.
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    auto t = std::chrono::system_clock::to_time_t(now);

    struct tm tm_buf;
    localtime_r(&t, &tm_buf);

    char time_buf[16]; // HH:MM:SS\0
    if (std::strftime(time_buf, sizeof(time_buf), "%H:%M:%S", &tm_buf) == 0) {
        return "00:00:00.000";
    }

    char out[32];
    std::snprintf(out, sizeof(out), "%s.%03d", time_buf, static_cast<int>(ms.count()));
    return std::string(out);
#endif
}

static std::string sanitize_log_message(const std::string& input) {
    std::ostringstream oss;
    for (unsigned char c : input) {
        if (c < 32 && c != '\t' && c != '\n' && c != '\r') {
            oss << "\\x" << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        } else if (c >= 127) {
            oss << "\\x" << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        } else {
            oss << c;
        }
    }
    return oss.str();
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
#if HAVE_JNI
            __android_log_print(ANDROID_LOG_INFO, "LiteP2P_Native", "%s", msg.c_str());
            sendToLogUI(sanitize_log_message(msg));
#else
            // Desktop: output with timestamp
            // Desktop: best-effort logging without mutex to avoid shutdown-order issues.
            if (g_logCallback) {
                g_logCallback(sanitize_log_message(msg));
            } else {
                std::cout << sanitize_log_message(msg) << std::endl;
                std::cout.flush();
            }
#endif
        }
    }
}

/**
 * @brief Enables async logging (non-blocking)
 */
void enable_async_logging() {
    if (g_async_logging_enabled) return;
    
#if HAVE_JNI
    std::lock_guard<std::mutex> lock(log_mutex());
#endif
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
#if HAVE_JNI
    return g_async_logging_enabled.load();
#else
    // Desktop build: keep logging synchronous to avoid shutdown-order issues with
    // the async queue mutex/condition_variable.
    return false;
#endif
}

/**
 * @brief Logs a message to the native log.
 * @param message The message to log.
 */
void nativeLog(const std::string& message) {
    // Logging must never be allowed to terminate the process.
    // In particular, shutdown ordering issues can cause mutex operations to fail.
    try {
#if HAVE_JNI
    // Android: Use session ID format
    std::string log_message = "[" + g_sessionId + "] " + message;
#else
    // Desktop: Add timestamp
    std::string log_message = "[" + get_timestamp() + "] " + message;
#endif
    
    if (is_async_logging_enabled()) {
        // OPTIMIZATION: Non-blocking push to queue
        {
            std::lock_guard<std::mutex> lock(g_log_queue_mutex);
            g_log_queue.push(log_message);
        }
        g_log_queue_cv.notify_one();
    } else {
        // Synchronous logging (original behavior)
#if HAVE_JNI
        std::lock_guard<std::mutex> lock(log_mutex());
        __android_log_print(ANDROID_LOG_INFO, "LiteP2P_Native", "%s", log_message.c_str());
        sendToLogUI(log_message);
#else
        // Desktop: output raw message to stdout or callback
        if (g_logCallback) {
            g_logCallback(log_message);
        } else {
            const std::string out = log_message + "\n";
            (void)::write(1, out.c_str(), out.size());
        }
#endif
    }
    } catch (const std::exception& e) {
        // Best-effort fallback: avoid throwing from logger and avoid iostreams during shutdown.
        const std::string out = std::string("[LOGGER_ERROR] ") + e.what() + "\n";
        (void)::write(2, out.c_str(), out.size());
    } catch (...) {
        // Swallow all exceptions to prevent termination.
    }
}

