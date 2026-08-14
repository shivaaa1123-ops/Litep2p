# LiteP2P: Implementation Code Templates

Quick copy-paste starting templates for the top 5 improvements.

---

## 1. Fix Detached Threads (P0)

### Before:
```cpp
// session_manager.cpp
void SessionManager::Impl::start() {
    std::thread([this]() { ip_monitor_loop(); }).detach();
    std::thread([this]() { event_loop(); }).detach();
}

void SessionManager::Impl::stop() {
    m_shutting_down.store(true);
    // No join! Threads may still be running.
}
```

### After:
```cpp
// session_manager.h
class SessionManager::Impl {
private:
    std::optional<std::thread> m_ip_monitor_thread;
    std::optional<std::thread> m_event_loop_thread;
    std::optional<std::thread> m_listen_loop_thread;
};

// session_manager.cpp
void SessionManager::Impl::start() {
    m_shutting_down.store(false);
    m_ip_monitor_thread.emplace([this]() { ip_monitor_loop(); });
    m_event_loop_thread.emplace([this]() { event_loop(); });
    m_listen_loop_thread.emplace([this]() { listen_loop(); });
}

void SessionManager::Impl::stop() {
    m_shutting_down.store(true, std::memory_order_release);
    
    // Join all threads
    if (m_ip_monitor_thread && m_ip_monitor_thread->joinable()) {
        m_ip_monitor_thread->join();
    }
    if (m_event_loop_thread && m_event_loop_thread->joinable()) {
        m_event_loop_thread->join();
    }
    if (m_listen_loop_thread && m_listen_loop_thread->joinable()) {
        m_listen_loop_thread->join();
    }
}

~SessionManager::Impl() {
    // Threads guaranteed joined before destruction
    assert(!m_ip_monitor_thread || !m_ip_monitor_thread->joinable());
}
```

---

## 2. Mutex Ordering Guards (P0)

### New Header:
```cpp
// app/src/main/cpp/modules/plugins/session/include/mutex_guard_ordered.h
#pragma once

#include <mutex>
#include <thread>

enum class LockOrder {
    PEERS = 1,
    NETWORK_INDEX = 2,
    SIGNALING = 3,
    FSM_EVENTS = 4,
    FILE_TRANSFERS = 5,
};

#ifdef LITEP2P_DEBUG_LOCKS

class MutexGuardOrdered {
    static thread_local LockOrder s_last_acquired;
    std::unique_lock<std::mutex> m_lock;
    
public:
    MutexGuardOrdered(std::mutex& m, LockOrder order) 
        : m_lock(m, std::defer_lock) {
        
        if (order <= s_last_acquired) {
            LOG_ERROR("Mutex ordering violation! Current=" 
                + std::to_string((int)order) 
                + ", Last=" + std::to_string((int)s_last_acquired));
            std::abort();
        }
        s_last_acquired = order;
        m_lock.lock();
    }
    
    ~MutexGuardOrdered() {
        s_last_acquired = LockOrder(0);
    }
};

#else

// Release mode: just use regular lock_guard
#define MutexGuardOrdered std::lock_guard

#endif
```

### Usage:
```cpp
// session_manager.cpp
void SessionManager::Impl::heartbeat_loop() {
    MutexGuardOrdered peers_lock(m_peers_mutex, LockOrder::PEERS);
    MutexGuardOrdered network_lock(m_network_index_mutex, LockOrder::NETWORK_INDEX);
    
    for (auto& [peer_id, peer] : m_peers) {
        send_heartbeat(peer);
    }
}
```

---

## 3. Typed Error Results + Retry Policy (P1)

### Header:
```cpp
// app/src/main/cpp/modules/plugins/session/include/error_types.h
#pragma once

#include <variant>
#include <string>

enum class ErrorCategory {
    TRANSIENT,      // Retry with backoff
    FATAL,          // Give up (invalid peer ID, decrypt failure)
    DEGRADED,       // Try alternative (relay fallback)
};

struct SystemError {
    ErrorCategory category;
    std::string code;        // "STUN_TIMEOUT", "DECRYPT_FAILED", etc.
    std::string message;
    int errno_value = 0;
    std::string peer_id;
    std::string failed_method;  // "TCP", "UDP", "RELAY"
    
    static SystemError transient(const std::string& code, 
                                 const std::string& msg) {
        return {ErrorCategory::TRANSIENT, code, msg};
    }
    
    static SystemError fatal(const std::string& code,
                            const std::string& msg) {
        return {ErrorCategory::FATAL, code, msg};
    }
};

// Result type
template<typename T>
using Result = std::variant<T, SystemError>;

template<typename T>
bool is_error(const Result<T>& r) {
    return std::holds_alternative<SystemError>(r);
}

template<typename T>
SystemError get_error(const Result<T>& r) {
    return std::get<SystemError>(r);
}
```

### RetryPolicy Header:
```cpp
// app/src/main/cpp/modules/plugins/routing/include/retry_policy.h
#pragma once

#include "error_types.h"
#include <unordered_map>

class RetryPolicy {
public:
    struct Config {
        int max_attempts = 5;
        int initial_backoff_ms = 100;
        int max_backoff_ms = 30000;
        bool use_jitter = true;
        bool use_circuit_breaker = true;
        int circuit_breaker_threshold = 5;
        int circuit_breaker_reset_ms = 60000;
    };
    
    struct RetryStrategy {
        bool should_retry;
        uint32_t backoff_ms;
        std::string reason;
    };
    
    explicit RetryPolicy(const Config& cfg = Config()) : config(cfg) {}
    
    RetryStrategy compute_next_backoff(
        const std::string& key,
        int attempt_number,
        ErrorCategory error_category) {
        
        // Don't retry fatal errors
        if (error_category == ErrorCategory::FATAL) {
            return {false, 0, "fatal_error"};
        }
        
        // Check circuit breaker
        auto& stats = m_stats[key];
        if (stats.consecutive_failures >= config.circuit_breaker_threshold) {
            uint64_t now = get_time_ms();
            if (now - stats.circuit_breaker_opened_ms < config.circuit_breaker_reset_ms) {
                uint32_t remaining = config.circuit_breaker_reset_ms 
                    - (now - stats.circuit_breaker_opened_ms);
                return {false, remaining, "circuit_breaker_open"};
            } else {
                stats.consecutive_failures = 0;  // Reset
            }
        }
        
        // Exponential backoff
        int base_backoff = config.initial_backoff_ms << std::min(attempt_number, 4);
        base_backoff = std::min(base_backoff, config.max_backoff_ms);
        
        int jitter_ms = config.use_jitter ? (rand() % (base_backoff / 2)) : 0;
        
        return {
            attempt_number < config.max_attempts,
            base_backoff + jitter_ms,
            "retry_with_backoff"
        };
    }
    
    void on_success(const std::string& key) {
        m_stats[key].consecutive_failures = 0;
    }
    
    void on_failure(const std::string& key) {
        auto& stats = m_stats[key];
        stats.consecutive_failures++;
        if (stats.consecutive_failures >= config.circuit_breaker_threshold) {
            stats.circuit_breaker_opened_ms = get_time_ms();
        }
    }
    
private:
    struct Stats {
        int consecutive_failures = 0;
        uint64_t circuit_breaker_opened_ms = 0;
    };
    std::unordered_map<std::string, Stats> m_stats;
    Config config;
};
```

### Usage:
```cpp
RetryPolicy retry_policy;

for (int attempt = 0; attempt < 100; attempt++) {
    Result<Peer> result = connect_peer(peer_id);
    
    if (!is_error(result)) {
        retry_policy.on_success(peer_id);
        LOG_INFO("Connected to " + peer_id);
        break;
    }
    
    auto error = get_error(result);
    retry_policy.on_failure(peer_id);
    
    auto strategy = retry_policy.compute_next_backoff(
        peer_id, attempt, error.category);
    
    if (!strategy.should_retry) {
        LOG_ERROR("Giving up on " + peer_id + ": " + strategy.reason);
        break;
    }
    
    LOG_INFO("Retrying " + peer_id + " in " + std::to_string(strategy.backoff_ms) + "ms");
    std::this_thread::sleep_for(std::chrono::milliseconds(strategy.backoff_ms));
}
```

---

## 4. Lock-Free Event Queue (P1)

### Download moodycamel:
```bash
# Add to app/src/main/cpp/include/
curl -o concurrentqueue.h https://raw.githubusercontent.com/cameron314/concurrentqueue/master/concurrentqueue.h
```

### Usage:
```cpp
// session_manager.h
#include "concurrentqueue.h"

class SessionManager::Impl {
private:
    moodycamel::ConcurrentQueue<FSMEvent> m_event_queue;
};

// session_manager.cpp
void SessionManager::Impl::dispatch_event(const FSMEvent& event) {
    m_event_queue.enqueue(event);  // Lock-free, O(1)
}

void SessionManager::Impl::event_loop_thread() {
    FSMEvent event;
    while (!m_shutting_down.load(std::memory_order_acquire)) {
        if (m_event_queue.try_dequeue(event)) {
            process_event(event);
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
}
```

---

## 5. Bounded Message Queue (P2)

### Header:
```cpp
// app/src/main/cpp/modules/plugins/session/include/bounded_queue.h
#pragma once

#include <deque>
#include <mutex>
#include <condition_variable>

template<typename T>
class BoundedMessageQueue {
public:
    struct Config {
        size_t max_messages = 10000;
        size_t max_bytes = 100 * 1024 * 1024;  // 100 MB
        bool drop_oldest_on_full = false;
    };
    
    explicit BoundedMessageQueue(const Config& cfg = Config()) 
        : config(cfg) {}
    
    bool try_enqueue(const T& item, int timeout_ms = -1) {
        std::unique_lock<std::mutex> lock(m_mutex);
        
        size_t item_size = estimate_size(item);
        
        while (m_queue.size() >= config.max_messages ||
               m_current_bytes + item_size > config.max_bytes) {
            
            if (config.drop_oldest_on_full && !m_queue.empty()) {
                m_current_bytes -= estimate_size(m_queue.front());
                m_queue.pop_front();
                break;
            }
            
            if (timeout_ms == 0) {
                return false;
            }
            
            if (timeout_ms < 0) {
                m_has_space_cv.wait(lock, [this, item_size]() {
                    return m_queue.size() < config.max_messages &&
                           m_current_bytes + item_size <= config.max_bytes;
                });
            } else {
                if (!m_has_space_cv.wait_for(lock,
                    std::chrono::milliseconds(timeout_ms),
                    [this, item_size]() {
                        return m_queue.size() < config.max_messages &&
                               m_current_bytes + item_size <= config.max_bytes;
                    })) {
                    return false;
                }
            }
        }
        
        m_queue.push_back(item);
        m_current_bytes += item_size;
        return true;
    }
    
    bool try_dequeue(T& item) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_queue.empty()) {
            return false;
        }
        item = m_queue.front();
        m_queue.pop_front();
        m_current_bytes -= estimate_size(item);
        m_has_space_cv.notify_all();
        return true;
    }
    
    size_t current_bytes() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_current_bytes;
    }
    
    size_t size() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_queue.size();
    }
    
private:
    size_t estimate_size(const T& item) const {
        // Specialize per type; default implementation
        return sizeof(T);
    }
    
    std::deque<T> m_queue;
    size_t m_current_bytes = 0;
    std::condition_variable m_has_space_cv;
    mutable std::mutex m_mutex;
    Config config;
};
```

### Usage:
```cpp
BoundedMessageQueue<Message> queue({
    .max_messages = 10000,
    .max_bytes = 100 * 1024 * 1024,
    .drop_oldest_on_full = false  // Block if full
});

// Enqueue (may block if queue full)
bool ok = queue.try_enqueue(msg, 5000);  // Wait up to 5s
if (!ok) {
    LOG_WARN("Message queue full, backpressure!");
}

// Dequeue
Message msg;
while (queue.try_dequeue(msg)) {
    send(msg);
}
```

---

## Testing Template

```cpp
// tests/test_reliability_improvements.cpp
#include <gtest/gtest.h>
#include "session_manager.h"

class ReliabilityTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Compile with ASAN: -fsanitize=address
        // Run with: ASAN_OPTIONS=detect_leaks=1
    }
};

// Test 1: Threads join cleanly
TEST_F(ReliabilityTest, ThreadsJoinOnStop) {
    SessionManager sm;
    sm.start(5555, "peer1", "HYBRID");
    
    // Give threads time to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Stop should join all threads (no hanging threads)
    sm.stop();
    
    // If ASAN is enabled, it will detect if threads are still running
    // during object destruction
}

// Test 2: No deadlock under concurrent access
TEST_F(ReliabilityTest, NoConcurrentDeadlock) {
    SessionManager sm;
    sm.start(5555, "peer1", "HYBRID");
    
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; i++) {
        threads.emplace_back([&sm, i]() {
            for (int j = 0; j < 100; j++) {
                sm.send_message_to_peer("peer_" + std::to_string(i), 
                                       "msg_" + std::to_string(j));
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    sm.stop();
    // ThreadSanitizer will flag any potential races
}

// Test 3: Retry policy with circuit breaker
TEST_F(ReliabilityTest, RetryPolicyCircuitBreaker) {
    RetryPolicy policy({
        .max_attempts = 5,
        .circuit_breaker_threshold = 3,
    });
    
    // Simulate 3 failures → opens circuit breaker
    for (int i = 0; i < 3; i++) {
        policy.on_failure("peer_bad");
    }
    
    auto strategy = policy.compute_next_backoff("peer_bad", 1, 
                                                ErrorCategory::TRANSIENT);
    EXPECT_FALSE(strategy.should_retry);
    EXPECT_EQ(strategy.reason, "circuit_breaker_open");
}
```

---

## Compilation Flags

```cmake
# CMakeLists.txt
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(
        -g -O0
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
        -DLITEP2P_DEBUG_LOCKS  # Enable mutex ordering checks
    )
    add_link_options(-fsanitize=address,undefined)
endif()

# Threading
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(litep2p PUBLIC Threads::Threads)
```

---

## Next Steps

1. **Start with Task #1** (detached threads) — easiest, highest-impact
2. Create PR, get code review
3. Add tests (unit + stress tests)
4. Run with ASAN/TSan before merge
5. Benchmark before/after
6. Move to Task #2, repeat

Good luck! 🚀
