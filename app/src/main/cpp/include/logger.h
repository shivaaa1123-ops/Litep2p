#ifndef LOGGER_H
#define LOGGER_H

#include <string>

// --- Add a function to set the session ID ---
void setSessionId(const std::string& session_id);
void nativeLog(const std::string& message);

#endif // LOGGER_H
