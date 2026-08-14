#pragma once

#include <cstdint>
#include <iostream>
#include <string>

// Minimal assertion-based test harness shared by desktop test binaries.
//
// Every assertion records a pass/fail and *continues* execution, so a single
// bad check does not hide the rest of the suite. The binary's exit code is
// non-zero if any assertion failed. This replaces the old "exit-code only" and
// "manual if/else + tests_failed++" styles with a uniform, countable harness.

struct TestSuite {
    int passed = 0;
    int failed = 0;
};

// One suite instance per translation unit (each desktop test binary is a
// single .cpp, so internal linkage is fine).
static TestSuite g_suite;

#define CHECK(cond, msg)                                                        \
    do {                                                                        \
        if (cond) {                                                             \
            ++g_suite.passed;                                                   \
            std::cout << "PASS: " << msg << std::endl;                          \
        } else {                                                                \
            ++g_suite.failed;                                                   \
            std::cerr << "FAIL: " << msg << " [" << __FILE__ << ":" << __LINE__ \
                      << "]" << std::endl;                                      \
        }                                                                       \
    } while (0)

#define CHECK_EQ(a, b, msg)                                                     \
    do {                                                                        \
        const auto& _a = (a);                                                   \
        const auto& _b = (b);                                                   \
        if (_a == _b) {                                                         \
            ++g_suite.passed;                                                   \
            std::cout << "PASS: " << msg << std::endl;                          \
        } else {                                                                \
            ++g_suite.failed;                                                   \
            std::cerr << "FAIL: " << msg << " [" << __FILE__ << ":" << __LINE__ \
                      << "] (got=" << _a << " want=" << _b << ")" << std::endl; \
        }                                                                       \
    } while (0)

#define CHECK_NE(a, b, msg)                                                     \
    do {                                                                        \
        const auto& _a = (a);                                                   \
        const auto& _b = (b);                                                   \
        if (_a != _b) {                                                         \
            ++g_suite.passed;                                                   \
            std::cout << "PASS: " << msg << std::endl;                          \
        } else {                                                                \
            ++g_suite.failed;                                                   \
            std::cerr << "FAIL: " << msg << " [" << __FILE__ << ":" << __LINE__ \
                      << "] (unexpectedly equal: " << _a << ")" << std::endl;   \
        }                                                                       \
    } while (0)

inline int suite_exit(const char* name) {
    std::cout << "\n========================================" << std::endl;
    std::cout << name << " summary:" << std::endl;
    std::cout << "  Passed: " << g_suite.passed << std::endl;
    std::cout << "  Failed: " << g_suite.failed << std::endl;
    std::cout << "========================================" << std::endl;
    return g_suite.failed > 0 ? 1 : 0;
}
