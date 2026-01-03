#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <queue>
#include <mutex>
#include <thread>
#include <memory>
#include <functional>

// Log level enumeration for conditional logging
enum class LogLevel {
    DEBUG = 0,     // Every message (most verbose)
    INFO = 1,      // Important events
    WARNING = 2,   // Problems only
    ERROR = 3,     // Errors only
    NONE = 4,      // Disable all logging (best performance)
};

// --- Add a function to set the session ID ---
void setSessionId(const std::string& session_id);
void nativeLog(const std::string& message);

// Set a callback for log messages (useful for desktop CLI)
void setLogCallback(std::function<void(const std::string&)> callback);

// Set global log level for production optimization
// Default: INFO (skips debug messages)
void set_log_level(LogLevel level);
LogLevel get_log_level();

// Async logging for non-blocking performance
// Call this to enable async mode (log messages go to queue, processed by background thread)
void enable_async_logging();
void disable_async_logging();
bool is_async_logging_enabled();

// Logging macros for conditional compilation
#define LOG_DEBUG(msg) if (get_log_level() <= LogLevel::DEBUG) nativeLog(msg)
#define LOG_INFO(msg)  if (get_log_level() <= LogLevel::INFO) nativeLog(msg)
#define LOG_WARN(msg)  if (get_log_level() <= LogLevel::WARNING) nativeLog(msg)
#define LOG_ERROR(msg) if (get_log_level() <= LogLevel::ERROR) nativeLog(msg)

#endif // LOGGER_H
