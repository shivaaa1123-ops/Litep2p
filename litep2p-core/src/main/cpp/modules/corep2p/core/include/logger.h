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
// Level-aware variant: the level is carried through the async queue and the
// external sinks (Android logcat priority, C ABI on_log callback).
void nativeLog(LogLevel level, const std::string& message);

// Set a callback for log messages (useful for desktop CLI).
// The message-only variant is kept for backwards compatibility; when both are
// registered the leveled callback wins.
void setLogCallback(std::function<void(const std::string&)> callback);

// Leveled log callback (level matches the LogLevel enum / C ABI on_log levels:
// 0=DEBUG 1=INFO 2=WARN 3=ERROR). Used by the public C ABI to feed on_log.
using LeveledLogCallback = std::function<void(LogLevel, const std::string&)>;
void set_leveled_log_callback(LeveledLogCallback callback);

// Set global log level for production optimization
// Default: INFO (skips debug messages)
void set_log_level(LogLevel level);
LogLevel get_log_level();

// Async logging for non-blocking performance
// Call this to enable async mode (log messages go to queue, processed by background thread)
void enable_async_logging();
void disable_async_logging();
bool is_async_logging_enabled();

// Logging macros for conditional compilation.
// The level is passed through so sinks (logcat priority, on_log) see it.
#define LOG_DEBUG(msg) if (get_log_level() <= LogLevel::DEBUG) nativeLog(LogLevel::DEBUG, msg)
#define LOG_INFO(msg)  if (get_log_level() <= LogLevel::INFO) nativeLog(LogLevel::INFO, msg)
#define LOG_WARN(msg)  if (get_log_level() <= LogLevel::WARNING) nativeLog(LogLevel::WARNING, msg)
#define LOG_ERROR(msg) if (get_log_level() <= LogLevel::ERROR) nativeLog(LogLevel::ERROR, msg)

#endif // LOGGER_H
