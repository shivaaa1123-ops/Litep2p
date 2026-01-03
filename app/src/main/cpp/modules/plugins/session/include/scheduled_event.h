#ifndef SCHEDULED_EVENT_H
#define SCHEDULED_EVENT_H

#include "session_events.h"
#include <chrono>

struct ScheduledEvent {
    SessionEvent event;
    std::chrono::steady_clock::time_point due_time;
};

#endif // SCHEDULED_EVENT_H