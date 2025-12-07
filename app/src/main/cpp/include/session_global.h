#ifndef SESSION_GLOBAL_H
#define SESSION_GLOBAL_H

#include "session_manager.h"

SessionManager* getGlobalSessionManager();
void destroyGlobalSessionManager();

#endif
