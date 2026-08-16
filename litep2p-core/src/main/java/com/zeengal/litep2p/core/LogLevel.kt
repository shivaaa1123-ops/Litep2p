package com.zeengal.litep2p.core

/**
 * Logging verbosity, mirroring the C ABI `litep2p_set_log_level` levels
 * (litep2p.h §3.13): 0=DEBUG 1=INFO 2=WARN 3=ERROR.
 */
enum class LogLevel(val level: Int) {
    DEBUG(0),
    INFO(1),
    WARN(2),
    ERROR(3);

    companion object {
        @JvmStatic
        fun fromLevel(level: Int): LogLevel =
            values().firstOrNull { it.level == level } ?: INFO
    }
}