#ifndef EVENT_THREAD_POOL_H
#define EVENT_THREAD_POOL_H

#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <functional>
#include <memory>
#include <atomic>

/**
 * Multi-threaded event processing pool
 * Distributes events across worker threads for parallel processing
 * Uses consistent hashing to route related events to same worker
 * Prevents load imbalance while maintaining event ordering per peer
 */
class EventThreadPool {
public:
    using Task = std::function<void()>;

    /**
     * Create thread pool with specified worker count
     * num_workers: number of worker threads (default: CPU count)
     */
    explicit EventThreadPool(size_t num_workers = 0);
    ~EventThreadPool();

    /**
     * Submit a task to pool
     * key: routing key (e.g., peer_id) for consistent hashing
     * task: lambda/function to execute
     * 
     * Tasks with same key are processed sequentially (order preserved)
     * Different keys can be processed in parallel
     */
    void submit(const std::string& key, Task task);

    /**
     * Submit task with no specific ordering requirement
     * (uses round-robin distribution)
     */
    void submit_any(Task task);

    /**
     * Stop all workers and wait for pending tasks
     * blocking: if true, waits for all tasks to complete
     */
    void shutdown(bool blocking = true);

    /**
     * Get number of active workers
     */
    size_t worker_count() const { return m_num_workers; }

    /**
     * Get approximate queue size
     */
    size_t pending_tasks() const;

private:
    void worker_loop(size_t worker_id);
    size_t get_worker_id(const std::string& key) const;

    size_t m_num_workers;
    std::vector<std::queue<Task>> m_queues;  // One queue per worker
    std::vector<std::mutex> m_queue_mutexes;
    std::vector<std::condition_variable> m_queue_cvs;
    std::vector<std::thread> m_workers;
    std::atomic<bool> m_running;
    std::atomic<int> m_round_robin_counter;
};

#endif // EVENT_THREAD_POOL_H
