#include "event_thread_pool.h"
#include <thread>
#include <functional>
#include <numeric>
#include <string>

EventThreadPool::EventThreadPool(size_t num_workers)
    : m_num_workers(num_workers > 0 ? num_workers : std::thread::hardware_concurrency()),
      m_queues(m_num_workers),
      m_queue_mutexes(m_num_workers),
      m_queue_cvs(m_num_workers),
      m_running(true),
      m_round_robin_counter(0) {
    
    // Start worker threads
    for (size_t i = 0; i < m_num_workers; ++i) {
        m_workers.emplace_back([this, i] { worker_loop(i); });
    }
}

EventThreadPool::~EventThreadPool() {
    shutdown(true);
}

void EventThreadPool::submit(const std::string& key, Task task) {
    if (!m_running) return;
    
    size_t worker_id = get_worker_id(key);
    
    {
        std::lock_guard<std::mutex> lock(m_queue_mutexes[worker_id]);
        m_queues[worker_id].push(task);
    }
    m_queue_cvs[worker_id].notify_one();
}

void EventThreadPool::submit_any(Task task) {
    if (!m_running) return;
    
    size_t worker_id = m_round_robin_counter.fetch_add(1) % m_num_workers;
    
    {
        std::lock_guard<std::mutex> lock(m_queue_mutexes[worker_id]);
        m_queues[worker_id].push(task);
    }
    m_queue_cvs[worker_id].notify_one();
}

void EventThreadPool::shutdown(bool blocking) {
    if (!m_running) return;
    
    m_running = false;
    
    // Wake all workers
    for (auto& cv : m_queue_cvs) {
        cv.notify_all();
    }
    
    // Wait for all workers to finish
    if (blocking) {
        for (auto& worker : m_workers) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    }
}

size_t EventThreadPool::pending_tasks() const {
    size_t total = 0;
    for (size_t i = 0; i < m_num_workers; ++i) {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(m_queue_mutexes[i]));
        total += m_queues[i].size();
    }
    return total;
}

void EventThreadPool::worker_loop(size_t worker_id) {
    while (m_running) {
        std::unique_lock<std::mutex> lock(m_queue_mutexes[worker_id]);
        
        // Wait for task or shutdown
        m_queue_cvs[worker_id].wait(lock, [this, worker_id] {
            return !m_queues[worker_id].empty() || !m_running;
        });
        
        if (!m_running && m_queues[worker_id].empty()) {
            break;
        }
        
        if (m_queues[worker_id].empty()) {
            continue;
        }
        
        Task task = m_queues[worker_id].front();
        m_queues[worker_id].pop();
        lock.unlock();
        
        // Execute task outside lock
        try {
            task();
        } catch (const std::exception& e) {
            // Prevent one task's exception from killing the worker
            // In production, log this error
        }
    }
}

size_t EventThreadPool::get_worker_id(const std::string& key) const {
    // Consistent hashing: same key always goes to same worker
    // Simple hash: sum of character values
    size_t hash_val = 0;
    for (char c : key) {
        hash_val = hash_val * 31 + static_cast<unsigned char>(c);
    }
    return hash_val % m_num_workers;
}
