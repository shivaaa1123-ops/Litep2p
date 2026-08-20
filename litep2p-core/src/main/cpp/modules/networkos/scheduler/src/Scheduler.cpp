// Scheduler.cpp — Network OS Phase 1 scheduler skeleton.
//
// A thread-safe priority queue of tasks with event-driven dispatch. Per the
// Phase 1 rule, the scheduler owns NO thread: the Runtime calls process(now)
// at event boundaries (network change, peer available, maintenance, …), and
// due tasks run inline. Independent subsystem timers are forbidden; all
// deferred work must come through here (Phase 8 replaces nothing — it only
// routes the scheduler to WorkManager for background execution).

#include "networkos/IScheduler.h"

#include <algorithm>
#include <mutex>
#include <vector>

namespace networkos {

namespace {

struct Entry {
    Task task;
    int64_t due_ms{0};
};

// Sort so the highest-priority, earliest task is at the back (pop_back cheap).
class Scheduler : public IScheduler {
public:
    Result schedule(Task task) override {
        if (task.id.empty() || !task.run) return Result::kInvalidArg;
        std::lock_guard<std::mutex> lock(m_mu);
        // Replace an existing task with the same id (idempotent re-schedule).
        for (auto it = m_tasks.begin(); it != m_tasks.end(); ++it) {
            if (it->task.id == task.id) {
                it->task = std::move(task);
                it->due_ms = earliest(it->task);
                std::push_heap(m_tasks.begin(), m_tasks.end(), HeapCmp{});
                return Result::kOk;
            }
        }
        Entry e;
        e.task = std::move(task);
        e.due_ms = earliest(e.task);
        m_tasks.push_back(std::move(e));
        std::push_heap(m_tasks.begin(), m_tasks.end(), HeapCmp{});
        return Result::kOk;
    }

    Result cancel(const std::string& id) override {
        std::lock_guard<std::mutex> lock(m_mu);
        for (size_t i = 0; i < m_tasks.size(); ++i) {
            if (m_tasks[i].task.id == id) {
                m_tasks.erase(m_tasks.begin() + static_cast<long>(i));
                std::make_heap(m_tasks.begin(), m_tasks.end(), HeapCmp{});
                return Result::kOk;
            }
        }
        return Result::kNotFound;
    }

    void setEvents(const SchedulerEvents& events) override {
        std::lock_guard<std::mutex> lock(m_ev_mu);
        m_events = events;
    }

    Result process(int64_t now_ms) override {
        std::vector<Task> to_run;
        {
            std::lock_guard<std::mutex> lock(m_mu);
            while (!m_tasks.empty()) {
                const Entry& top = m_tasks.front();
                if (top.due_ms <= now_ms) {
                    to_run.push_back(top.task);
                    std::pop_heap(m_tasks.begin(), m_tasks.end(), HeapCmp{});
                    m_tasks.pop_back();
                } else {
                    break;
                }
            }
        }
        for (auto& t : to_run) {
            if (t.run) t.run();
        }
        return Result::kOk;
    }

    size_t pendingCount() const override {
        std::lock_guard<std::mutex> lock(m_mu);
        return m_tasks.size();
    }

private:
    struct HeapCmp {
        bool operator()(const Entry& a, const Entry& b) const {
            // Max-heap by (priority, then earliest due). Higher priority first.
            if (a.task.priority != b.task.priority) {
                return static_cast<uint8_t>(a.task.priority) <
                       static_cast<uint8_t>(b.task.priority);
            }
            return a.due_ms > b.due_ms;  // earlier due = "larger"
        }
    };

    static int64_t earliest(const Task& t) {
        return t.earliest_run_ms > 0 ? t.earliest_run_ms : 0;
    }

    std::vector<Entry> m_tasks;
    mutable std::mutex m_mu;

    SchedulerEvents m_events;
    mutable std::mutex m_ev_mu;
};

} // namespace

std::unique_ptr<IScheduler> createScheduler() {
    return std::make_unique<Scheduler>();
}

} // namespace networkos
