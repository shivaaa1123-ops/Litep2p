/**
 * terminal_cli.cpp - Multi-Panel Fixed-Layout TUI
 * 
 * CRITICAL FIX: Uses alternate screen buffer and redirects stdout/stderr
 * to /dev/null. ALL terminal output goes through write_tty() which writes
 * directly to /dev/tty, completely bypassing any stream redirection.
 */

#include "terminal_cli.h"
#include "p2p_node.h"
#include "logger.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <ctime>
#include <cctype>
#include <thread>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <cstring>
#include <vector>
#include <sys/statvfs.h>
#include <nlohmann/json.hpp>
#include "telemetry.h"
#include <sys/resource.h>

#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/processor_info.h>
#include <mach/mach_host.h>
#include <sys/sysctl.h>
#include <libproc.h>
#else
#include <sys/sysinfo.h>
#include <fstream>
#include <dirent.h>
#endif

struct ParsedPeerEntry {
    std::string peer_id;
    std::string network_id;
    std::string status;
    std::string transport;
    bool connected = false;
};

// ═══════════════════════════════════════════════════════════════════════════
// ANSI ESCAPE CODES
// ═══════════════════════════════════════════════════════════════════════════

#define ESC_ALT_SCREEN_ON   "\033[?1049h"
#define ESC_ALT_SCREEN_OFF  "\033[?1049l"
#define ESC_CLEAR           "\033[2J"
#define ESC_HOME            "\033[H"
#define ESC_HIDE_CURSOR     "\033[?25l"
#define ESC_SHOW_CURSOR     "\033[?25h"
#define ESC_CLEAR_LINE      "\033[2K"

#define C_RESET      "\033[0m"
#define C_BOLD       "\033[1m"
#define C_DIM        "\033[2m"
#define C_RED        "\033[31m"
#define C_GREEN      "\033[32m"
#define C_YELLOW     "\033[33m"
#define C_BLUE       "\033[34m"
#define C_MAGENTA    "\033[35m"
#define C_CYAN       "\033[36m"
#define C_WHITE      "\033[37m"
#define C_BRED       "\033[91m"
#define C_BGREEN     "\033[92m"
#define C_BYELLOW    "\033[93m"
#define C_BCYAN      "\033[96m"
#define C_BG_BLUE    "\033[44m"

#define BOX_TL  "╔"
#define BOX_TR  "╗"
#define BOX_BL  "╚"
#define BOX_BR  "╝"
#define BOX_H   "═"
#define BOX_V   "║"
#define BOX_LT  "╠"
#define BOX_RT  "╣"
#define BOX_TT  "╦"
#define BOX_BT  "╩"

// ═══════════════════════════════════════════════════════════════════════════
// GLOBAL STATE
// ═══════════════════════════════════════════════════════════════════════════

static TerminalCLI* g_cli = nullptr;
static struct termios g_orig_termios;
static bool g_raw_mode = false;
static int g_tty_fd = -1;
static int g_saved_stdout = -1;
static int g_saved_stderr = -1;
static int g_null_fd = -1;

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

static std::string safe_substr(const std::string& s, size_t pos, size_t len = std::string::npos) {
    if (pos >= s.length()) return "";
    return s.substr(pos, std::min(len, s.length() - pos));
}

static std::string repeat_str(const std::string& s, int n) {
    std::string r;
    for (int i = 0; i < n; i++) r += s;
    return r;
}

static size_t visible_len(const std::string& s) {
    size_t len = 0;
    bool esc = false;
    for (char c : s) {
        if (c == '\033') esc = true;
        else if (esc && c == 'm') esc = false;
        else if (!esc) len++;
    }
    return len;
}

static std::string truncate_str(const std::string& s, size_t max_len) {
    if (max_len < 3) return "..";
    size_t vis = visible_len(s);
    if (vis <= max_len) return s;
    
    size_t cut = 0, v = 0;
    bool esc = false;
    for (size_t i = 0; i < s.length() && v < max_len - 2; i++) {
        if (s[i] == '\033') esc = true;
        else if (esc && s[i] == 'm') esc = false;
        else if (!esc) v++;
        cut = i + 1;
    }
    return s.substr(0, cut) + ".." + C_RESET;
}

static std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
    localtime_r(&t, &tm);
    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(2) << tm.tm_hour << ":"
        << std::setw(2) << tm.tm_min << ":" << std::setw(2) << tm.tm_sec;
    return oss.str();
}

static std::string get_short_time() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
    localtime_r(&t, &tm);
    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(2) << tm.tm_hour << ":"
        << std::setw(2) << tm.tm_min;
    return oss.str();
}

static std::string trim_copy(const std::string& s) {
    size_t b = 0;
    while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b]))) b++;
    size_t e = s.size();
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) e--;
    return s.substr(b, e - b);
}

static ParsedPeerEntry parse_peer_entry(const std::string& line) {
    ParsedPeerEntry p;
    const std::string marker = " (";
    size_t m = line.find(marker);
    if (m == std::string::npos) {
        p.peer_id = trim_copy(line);
        return p;
    }

    p.peer_id = trim_copy(line.substr(0, m));

    size_t lparen = m + 1; // points at '('
    size_t rparen = line.find(')', lparen);
    if (rparen != std::string::npos && rparen > lparen + 1) {
        p.network_id = trim_copy(line.substr(lparen + 1, rparen - (lparen + 1)));
    }

    size_t lbr = line.find('[', rparen == std::string::npos ? m : rparen);
    size_t rbr = (lbr == std::string::npos) ? std::string::npos : line.find(']', lbr);
    if (lbr != std::string::npos && rbr != std::string::npos && rbr > lbr + 1) {
        p.status = trim_copy(line.substr(lbr + 1, rbr - (lbr + 1)));
    }

    // Optional transport suffix inside the status field.
    // Expected format: "CONNECTED|UDP" / "DISCONNECTED|TCP" etc.
    // We keep p.status as the connection state token and store the remainder in p.transport.
    if (!p.status.empty()) {
        const size_t bar = p.status.find('|');
        if (bar != std::string::npos) {
            p.transport = trim_copy(p.status.substr(bar + 1));
            p.status = trim_copy(p.status.substr(0, bar));
        }
    }

    if (!p.status.empty()) {
        std::string up = p.status;
        std::transform(up.begin(), up.end(), up.begin(), ::toupper);
        // IMPORTANT: "DISCONNECTED" contains the substring "CONNECTED".
        // Check DISCONNECTED first to avoid false positives.
        if (up.find("DISCONNECTED") != std::string::npos) {
            p.connected = false;
        } else if (up.find("CONNECTED") != std::string::npos) {
            p.connected = true;
        } else {
            p.connected = false;
        }
    }

    return p;
}

static std::string normalize_peer_prefix(std::string s) {
    s = trim_copy(s);
    while (!s.empty() && s.back() == '.') s.pop_back();
    return s;
}

// ═══════════════════════════════════════════════════════════════════════════
// SYSTEM RESOURCE MONITORING
// ═══════════════════════════════════════════════════════════════════════════

struct SystemResources {
    uint64_t total_ram_mb = 0;
    uint64_t available_ram_mb = 0;
    uint64_t used_ram_mb = 0;
    int cpu_count = 0;
    double cpu_usage_percent = 0.0; // system CPU utilization (0..100)
    double load_1 = 0.0;
    double load_5 = 0.0;
    double load_15 = 0.0;
    uint64_t uptime_sec = 0;
    uint64_t total_disk_mb = 0;
    uint64_t free_disk_mb = 0;
    uint64_t total_swap_mb = 0;
    uint64_t free_swap_mb = 0;
};

struct EngineResources {
    int pid = 0;
    uint64_t resident_memory_mb = 0;
    uint64_t virtual_memory_mb = 0;
    uint64_t peak_resident_memory_mb = 0;
    double cpu_time_sec = 0.0;
    double cpu_usage_percent = 0.0; // process CPU utilization (can exceed 100 on multi-core)
    int thread_count = 0;
    int open_fds = 0;
    long voluntary_ctx_switches = 0;
    long involuntary_ctx_switches = 0;
};

static std::string format_uptime(uint64_t sec) {
    uint64_t days = sec / 86400;
    sec %= 86400;
    uint64_t hrs = sec / 3600;
    sec %= 3600;
    uint64_t mins = sec / 60;
    sec %= 60;
    std::ostringstream oss;
    if (days > 0) oss << days << "d";
    oss << hrs << "h" << mins << "m" << sec << "s";
    return oss.str();
}

#ifndef __APPLE__
static bool read_linux_cpu_times(uint64_t& idle_ticks, uint64_t& total_ticks) {
    std::ifstream stat("/proc/stat");
    if (!stat.is_open()) return false;
    std::string cpu;
    uint64_t user = 0, nice = 0, system = 0, idle = 0, iowait = 0, irq = 0, softirq = 0, steal = 0;
    stat >> cpu >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal;
    if (cpu != "cpu") return false;
    idle_ticks = idle + iowait;
    total_ticks = user + nice + system + idle + iowait + irq + softirq + steal;
    return total_ticks > 0;
}
#endif

static SystemResources get_system_resources() {
    SystemResources res;

    // Disk info (root filesystem)
    {
        struct statvfs vfs;
        if (statvfs("/", &vfs) == 0) {
            uint64_t total = static_cast<uint64_t>(vfs.f_frsize) * static_cast<uint64_t>(vfs.f_blocks);
            uint64_t freeb = static_cast<uint64_t>(vfs.f_frsize) * static_cast<uint64_t>(vfs.f_bavail);
            res.total_disk_mb = total / (1024 * 1024);
            res.free_disk_mb = freeb / (1024 * 1024);
        }
    }
    
#ifdef __APPLE__
    // Get total RAM
    int64_t mem_size;
    size_t len = sizeof(mem_size);
    if (sysctlbyname("hw.memsize", &mem_size, &len, nullptr, 0) == 0) {
        res.total_ram_mb = static_cast<uint64_t>(mem_size) / (1024 * 1024);
    }
    
    // Get available/used RAM via vm_statistics
    vm_size_t page_size;
    mach_port_t mach_port = mach_host_self();
    host_page_size(mach_port, &page_size);
    
    vm_statistics64_data_t vm_stats;
    mach_msg_type_number_t count = sizeof(vm_stats) / sizeof(natural_t);
    if (host_statistics64(mach_port, HOST_VM_INFO64, (host_info64_t)&vm_stats, &count) == KERN_SUCCESS) {
        uint64_t free_pages = vm_stats.free_count + vm_stats.inactive_count;
        res.available_ram_mb = (free_pages * page_size) / (1024 * 1024);
        res.used_ram_mb = res.total_ram_mb - res.available_ram_mb;
    }
    
    // Get CPU count
    int cpu_count;
    len = sizeof(cpu_count);
    if (sysctlbyname("hw.ncpu", &cpu_count, &len, nullptr, 0) == 0) {
        res.cpu_count = cpu_count;
    }

    // Uptime
    {
        struct timeval boottime;
        size_t blen = sizeof(boottime);
        int mib[2] = { CTL_KERN, KERN_BOOTTIME };
        if (sysctl(mib, 2, &boottime, &blen, nullptr, 0) == 0) {
            time_t now = time(nullptr);
            if (now >= boottime.tv_sec) {
                res.uptime_sec = static_cast<uint64_t>(now - boottime.tv_sec);
            }
        }
    }

    // Swap usage
    {
        struct xsw_usage swap;
        size_t slen = sizeof(swap);
        if (sysctlbyname("vm.swapusage", &swap, &slen, nullptr, 0) == 0) {
            res.total_swap_mb = static_cast<uint64_t>(swap.xsu_total) / (1024 * 1024);
            res.free_swap_mb = static_cast<uint64_t>(swap.xsu_avail) / (1024 * 1024);
        }
    }

    // CPU usage (system-wide) via host_processor_info deltas
    {
        static uint64_t last_total = 0;
        static uint64_t last_idle = 0;
        natural_t cpu_count_n = 0;
        processor_info_array_t cpu_info = nullptr;
        mach_msg_type_number_t num_cpu_info = 0;
        if (host_processor_info(mach_host_self(), PROCESSOR_CPU_LOAD_INFO, &cpu_count_n, &cpu_info, &num_cpu_info) == KERN_SUCCESS) {
            uint64_t total = 0;
            uint64_t idle = 0;
            for (natural_t i = 0; i < cpu_count_n; i++) {
                const size_t base = i * CPU_STATE_MAX;
                const uint64_t user = cpu_info[base + CPU_STATE_USER];
                const uint64_t sys = cpu_info[base + CPU_STATE_SYSTEM];
                const uint64_t nice = cpu_info[base + CPU_STATE_NICE];
                const uint64_t idl = cpu_info[base + CPU_STATE_IDLE];
                total += (user + sys + nice + idl);
                idle += idl;
            }

            if (last_total > 0 && total > last_total) {
                const uint64_t d_total = total - last_total;
                const uint64_t d_idle = idle - last_idle;
                if (d_total > 0 && d_total >= d_idle) {
                    res.cpu_usage_percent = (double)(d_total - d_idle) / (double)d_total * 100.0;
                }
            }
            last_total = total;
            last_idle = idle;

            vm_deallocate(mach_task_self(), (vm_address_t)cpu_info, num_cpu_info * sizeof(integer_t));
        }
    }
    
    // Load average
    double la[3] = {0.0, 0.0, 0.0};
    if (getloadavg(la, 3) == 3) {
        res.load_1 = la[0];
        res.load_5 = la[1];
        res.load_15 = la[2];
    }
#else
    // Linux
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        res.total_ram_mb = (si.totalram * si.mem_unit) / (1024 * 1024);
        res.available_ram_mb = (si.freeram * si.mem_unit) / (1024 * 1024);
        res.used_ram_mb = res.total_ram_mb - res.available_ram_mb;
        res.uptime_sec = static_cast<uint64_t>(si.uptime);
        res.total_swap_mb = (si.totalswap * si.mem_unit) / (1024 * 1024);
        res.free_swap_mb = (si.freeswap * si.mem_unit) / (1024 * 1024);
    }
    
    res.cpu_count = sysconf(_SC_NPROCESSORS_ONLN);

    // CPU usage (system-wide) from /proc/stat deltas
    {
        static uint64_t last_idle = 0;
        static uint64_t last_total = 0;
        uint64_t idle = 0, total = 0;
        if (read_linux_cpu_times(idle, total)) {
            if (last_total > 0 && total > last_total) {
                const uint64_t d_total = total - last_total;
                const uint64_t d_idle = idle - last_idle;
                if (d_total > 0 && d_total >= d_idle) {
                    res.cpu_usage_percent = (double)(d_total - d_idle) / (double)d_total * 100.0;
                }
            }
            last_idle = idle;
            last_total = total;
        }
    }

    // Load average
    double la[3] = {0.0, 0.0, 0.0};
    if (getloadavg(la, 3) == 3) {
        res.load_1 = la[0];
        res.load_5 = la[1];
        res.load_15 = la[2];
    }
#endif
    
    return res;
}

static EngineResources get_engine_resources() {
    EngineResources res;

    res.pid = (int)getpid();
    
#ifdef __APPLE__
    // Get process memory info via Mach API
    struct mach_task_basic_info info;
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info, &count) == KERN_SUCCESS) {
        res.resident_memory_mb = info.resident_size / (1024 * 1024);
        res.virtual_memory_mb = info.virtual_size / (1024 * 1024);
    }

    // Thread count via Mach API
    {
        thread_act_array_t threads = nullptr;
        mach_msg_type_number_t thread_count = 0;
        if (task_threads(mach_task_self(), &threads, &thread_count) == KERN_SUCCESS) {
            res.thread_count = static_cast<int>(thread_count);
            if (threads && thread_count > 0) {
                vm_deallocate(mach_task_self(), (vm_address_t)threads, thread_count * sizeof(thread_act_t));
            }
        }
    }

    // Open FD count via libproc
    {
        const pid_t pid = getpid();
        const int bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nullptr, 0);
        if (bytes > 0) {
            std::vector<char> buf((size_t)bytes);
            const int got = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, buf.data(), bytes);
            if (got > 0) {
                res.open_fds = got / (int)sizeof(proc_fdinfo);
            }
        }
    }
#else
    // Linux: read from /proc/self/status
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("VmRSS:", 0) == 0) {
            uint64_t kb = 0;
            sscanf(line.c_str(), "VmRSS: %lu kB", &kb);
            res.resident_memory_mb = kb / 1024;
        } else if (line.rfind("VmSize:", 0) == 0) {
            uint64_t kb = 0;
            sscanf(line.c_str(), "VmSize: %lu kB", &kb);
            res.virtual_memory_mb = kb / 1024;
        } else if (line.rfind("Threads:", 0) == 0) {
            sscanf(line.c_str(), "Threads: %d", &res.thread_count);
        }
    }

    // Open FD count via /proc/self/fd
    {
        int cnt = 0;
        DIR* d = opendir("/proc/self/fd");
        if (d) {
            while (readdir(d) != nullptr) {
                cnt++;
            }
            closedir(d);
            // discount . and ..
            res.open_fds = std::max(0, cnt - 2);
        }
    }
#endif
    
    // Get CPU time via getrusage
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        res.cpu_time_sec = usage.ru_utime.tv_sec + usage.ru_stime.tv_sec +
                          (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) / 1000000.0;

        res.voluntary_ctx_switches = usage.ru_nvcsw;
        res.involuntary_ctx_switches = usage.ru_nivcsw;

        // Peak RSS
#ifdef __APPLE__
        res.peak_resident_memory_mb = static_cast<uint64_t>(usage.ru_maxrss) / (1024 * 1024);
#else
        res.peak_resident_memory_mb = static_cast<uint64_t>(usage.ru_maxrss) / 1024;
#endif
    }

    // Process CPU utilization (delta-based)
    {
        static double last_cpu_sec = 0.0;
        static auto last_wall = std::chrono::steady_clock::now();
        const auto now = std::chrono::steady_clock::now();
        const double wall_sec = std::chrono::duration_cast<std::chrono::duration<double>>(now - last_wall).count();
        const double cpu_sec = res.cpu_time_sec;
        if (last_cpu_sec > 0.0 && wall_sec > 0.05 && cpu_sec >= last_cpu_sec) {
            res.cpu_usage_percent = (cpu_sec - last_cpu_sec) / wall_sec * 100.0;

            int cpus = 1;
#ifdef __APPLE__
            int ncpu = 1;
            size_t len = sizeof(ncpu);
            if (sysctlbyname("hw.ncpu", &ncpu, &len, nullptr, 0) == 0 && ncpu > 0) cpus = ncpu;
#else
            long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
            if (ncpu > 0) cpus = (int)ncpu;
#endif
            const double max_pct = (double)cpus * 100.0;
            if (res.cpu_usage_percent < 0.0) res.cpu_usage_percent = 0.0;
            if (res.cpu_usage_percent > max_pct) res.cpu_usage_percent = max_pct;
        }
        last_cpu_sec = cpu_sec;
        last_wall = now;
    }
    
    return res;
}

// ═══════════════════════════════════════════════════════════════════════════
// TERMINAL CLI
// ═══════════════════════════════════════════════════════════════════════════

TerminalCLI::TerminalCLI(P2PNode& p2p_node, bool force_plain, bool daemon_mode)
    : node(p2p_node)
    , force_plain_cli(force_plain)
    , daemon_mode_(daemon_mode)
    , running(false)
    , tui_ready_(false)
    , term_width(100)
    , term_height(30)
    , cursor_pos(0)
    , log_filter_level(CLILogLevel::DEBUG)
{
    g_cli = this;
    
    // Set up log callback EARLY so we capture logs even during engine startup.
    // This must happen before any engine operations that might log.
    setLogCallback([this](const std::string& msg) {
        this->capture_log_line(msg);
    });
    
    // Enable INFO level logging so we see engine activity
    set_log_level(LogLevel::INFO);

    // Wire engine events into the TUI so panels update in real time.
    // These callbacks may be invoked from engine threads.
    node.setPeerEventCallbacks(
        [this](const std::string& peer_id) { this->on_peer_discovered(peer_id); },
        [this](const std::string& peer_id) { this->on_peer_connected(peer_id); },
        [this](const std::string& peer_id) { this->on_peer_disconnected(peer_id); }
    );
    node.setMessageEventCallback(
        [this](const std::string& peer_id, const std::string& message) { this->on_message_received(peer_id, message); }
    );

    last_telemetry_draw_ = std::chrono::steady_clock::now();
}

TerminalCLI::~TerminalCLI() {
    // Prevent callbacks into a destroyed UI.
    node.clearEventCallbacks();
    restore_terminal();
    g_cli = nullptr;
}

void TerminalCLI::setTelemetryRefreshIntervalMs(int ms) {
    if (ms < 100) ms = 100;
    if (ms > 60000) ms = 60000;
    telemetry_draw_interval_ms_ = ms;
}

void TerminalCLI::setup_terminal() {
    // Open /dev/tty for DIRECT terminal access - this NEVER gets redirected
    g_tty_fd = open("/dev/tty", O_RDWR);
    if (g_tty_fd < 0) {
        g_tty_fd = STDOUT_FILENO;
    }
    
    // Save original stdout/stderr
    g_saved_stdout = dup(STDOUT_FILENO);
    g_saved_stderr = dup(STDERR_FILENO);
    
    // Redirect stdout and stderr to /dev/null - ALL engine output goes here
    g_null_fd = open("/dev/null", O_WRONLY);
    if (g_null_fd >= 0) {
        dup2(g_null_fd, STDOUT_FILENO);
        dup2(g_null_fd, STDERR_FILENO);
    }
    
    // Enable raw mode on the TTY
    if (!g_raw_mode) {
        tcgetattr(g_tty_fd, &g_orig_termios);
        struct termios raw = g_orig_termios;
        raw.c_lflag &= ~(ICANON | ECHO);
        raw.c_cc[VMIN] = 0;
        raw.c_cc[VTIME] = 1;
        tcsetattr(g_tty_fd, TCSAFLUSH, &raw);
        g_raw_mode = true;
    }
    
    update_terminal_size();
    calculate_layout();
    
    // Switch to alternate screen buffer
    write_tty(ESC_ALT_SCREEN_ON);
    write_tty(ESC_HIDE_CURSOR);
    write_tty(ESC_CLEAR);
    write_tty(ESC_HOME);
}

void TerminalCLI::restore_terminal() {
    write_tty(ESC_SHOW_CURSOR);
    write_tty(ESC_ALT_SCREEN_OFF);
    
    if (g_raw_mode && g_tty_fd >= 0) {
        tcsetattr(g_tty_fd, TCSAFLUSH, &g_orig_termios);
        g_raw_mode = false;
    }
    
    // Restore stdout/stderr
    if (g_saved_stdout >= 0) {
        dup2(g_saved_stdout, STDOUT_FILENO);
        close(g_saved_stdout);
        g_saved_stdout = -1;
    }
    if (g_saved_stderr >= 0) {
        dup2(g_saved_stderr, STDERR_FILENO);
        close(g_saved_stderr);
        g_saved_stderr = -1;
    }
    if (g_null_fd >= 0) {
        close(g_null_fd);
        g_null_fd = -1;
    }
    if (g_tty_fd >= 0 && g_tty_fd != STDOUT_FILENO) {
        close(g_tty_fd);
        g_tty_fd = -1;
    }
}

void TerminalCLI::write_tty(const std::string& s) {
    if (g_tty_fd >= 0) {
        ssize_t written = write(g_tty_fd, s.c_str(), s.length());
        (void)written;
    }
}

void TerminalCLI::update_terminal_size() {
    struct winsize ws;
    int fd = (g_tty_fd >= 0) ? g_tty_fd : STDIN_FILENO;
    if (ioctl(fd, TIOCGWINSZ, &ws) == 0) {
        term_width = std::max((int)ws.ws_col, 80);
        term_height = std::max((int)ws.ws_row, 24);
    }
}

void TerminalCLI::calculate_layout() {
    int w = std::max(term_width, 80);
    int h = std::max(term_height, 24);
    
    // PEERS panel width:
    // - make it wide enough to show meaningful peer ids (often 20-25 chars)
    // - keep the MESSAGES panel usable
    const int min_messages_w = 20;
    const int target_peers_w = 100; // user preference: show full id + ip + status
    int max_peers_w = std::max(25, w - min_messages_w - 3);
    peers_panel_width = std::min(target_peers_w, max_peers_w);
    peers_panel_width = std::max(25, peers_panel_width);

    messages_panel_width = w - peers_panel_width - 3;
    
    header_row = 1;
    peers_start_row = 3;

    // Height budgeting
    // Rows used outside the variable panels:
    // - Header: 2 rows (top border + content)
    // - Panel top borders: peers + output + logs = 3 rows
    // - Prompt box: 3 rows (top + content + bottom)
    // Total fixed rows = 2 + 3 + 3 = 8
    const int fixed_rows = 8;
    int remaining = std::max(0, h - fixed_rows);

    const int min_cmd = 3;
    const int min_logs = 3;

    // Compute a stable base allocation first (this defines the LOGS height).
    // We'll then grow OUTPUT by borrowing space from the peers/messages area,
    // while keeping LOGS unchanged.
    int base_peers_h = std::max(4, remaining / 3);
    int base_cmd_h = std::max(3, std::min(5, remaining / 6));
    base_peers_h = std::min(base_peers_h, std::max(4, remaining - base_cmd_h - min_logs));
    int base_logs_h = std::max(min_logs, remaining - base_peers_h - base_cmd_h);

    // User preference: make OUTPUT taller (>= 8 rows, up to 16) and take that space
    // from the logs height (shrink logs by 4 rows).
    logs_panel_height = std::max(min_logs, base_logs_h - 4);

    // Try to grow OUTPUT as much as possible (up to 16) while keeping peers/messages >= 4.
    // This makes the growth obvious even on medium terminals.
    cmd_output_height = remaining - logs_panel_height - 4;
    cmd_output_height = std::max(8, cmd_output_height);
    cmd_output_height = std::min(16, cmd_output_height);
    cmd_output_height = std::max(min_cmd, cmd_output_height);

    // Ensure peers/messages panel remains usable.
    peers_panel_height = remaining - logs_panel_height - cmd_output_height;
    if (peers_panel_height < 4) {
        // First, shrink OUTPUT down (but keep at least 3).
        cmd_output_height = std::max(min_cmd, remaining - logs_panel_height - 4);
        cmd_output_height = std::min(16, cmd_output_height);
        peers_panel_height = remaining - logs_panel_height - cmd_output_height;
    }
    peers_panel_height = std::max(4, peers_panel_height);
    
    // Split the output row into 3 panels horizontally:
    // OUTPUT (left) | SYSTEM RESOURCES (middle) | ENGINE RESOURCES (right)
    // Each gets roughly 1/3 of the width
    int output_row_width = w - 2;  // subtract left and right borders
    sys_resources_width = output_row_width / 3;
    engine_resources_width = output_row_width / 3;
    // cmd_output uses the panel width in draw function, no separate width needed
    // since it shares the row with the resource panels
    
    cmd_output_start_row = peers_start_row + peers_panel_height + 1;
    resources_start_row = cmd_output_start_row;  // Same row as output
    logs_start_row = cmd_output_start_row + cmd_output_height + 1;
    prompt_row = logs_start_row + logs_panel_height + 1;
}

void TerminalCLI::run() {
    running = true;
    tui_ready_ = false;

    if (daemon_mode_) {
        run_daemon();
        return;
    }

    if (force_plain_cli) {
        run_plain();
        return;
    }
    
    // Log callback already set in constructor
    
    setup_terminal();
    {
        // Ensure callbacks don't interleave with the initial draw.
        std::lock_guard<std::mutex> lock(display_mutex);
        full_redraw();
    }
    tui_ready_ = true;
    
    while (running) {
        // Read from TTY directly
        char c;
        ssize_t n = read(g_tty_fd, &c, 1);
        if (n == 1) {
            handle_keypress(c);
        }

        // Periodic telemetry refresh (keep it smooth but not noisy).
        const auto now = std::chrono::steady_clock::now();
        if (tui_ready_ && std::chrono::duration_cast<std::chrono::milliseconds>(now - last_telemetry_draw_).count() >= telemetry_draw_interval_ms_) {
            std::lock_guard<std::mutex> lock(display_mutex);
            refresh_telemetry_buffer_locked();
            draw_messages_panel();
            draw_prompt();
            last_telemetry_draw_ = now;
        }
    }
    
    // Clear log callback before restoring terminal
    setLogCallback(nullptr);

    tui_ready_ = false;
    
    restore_terminal();
    std::cout << C_CYAN << "Goodbye!" << C_RESET << std::endl;
}

void TerminalCLI::run_plain() {
    // Plain, line-oriented interface:
    // - No /dev/tty requirements
    // - No stdout/stderr redirection
    // - Suitable for Docker, background logs, and scripting

    std::cout << "LiteP2P (plain mode). Type 'help' for commands. Ctrl-D/Ctrl-C to exit." << std::endl;

    std::string line;
    while (running) {
        // Prompt
        std::cout << "litep2p> " << std::flush;
        if (!std::getline(std::cin, line)) {
            break;
        }
        if (line.empty()) {
            continue;
        }
        process_command(line);
    }

    std::cout << "Goodbye!" << std::endl;
}

void TerminalCLI::run_daemon() {
    // Daemon mode: no stdin reading, just run forever
    // Suitable for background processes and automated testing
    
    std::cout << "LiteP2P daemon mode started. Use 'kill -TERM " << getpid() << "' to stop." << std::endl;
    std::cout << "Peer ID: " << node.getPeerId() << std::endl;
    std::cout << std::flush;
    
    // Just sleep and let the engine run in its threads
    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    std::cout << "Goodbye!" << std::endl;
}

void TerminalCLI::stop() {
    tui_ready_ = false;
    running = false;
}

void TerminalCLI::capture_log_line(const std::string& line) {
    // In daemon or plain mode, just output to stdout and skip TUI rendering
    if (daemon_mode_ || force_plain_cli) {
        // Apply log level filtering
        if (line.find("ERROR") != std::string::npos) {
            if (log_filter_level < CLILogLevel::ERROR) return;
        } else if (line.find("WARN") != std::string::npos) {
            if (log_filter_level < CLILogLevel::WARNING) return;
        } else if (line.find("INFO") != std::string::npos) {
            if (log_filter_level < CLILogLevel::INFO) return;
        } else {
            if (log_filter_level < CLILogLevel::DEBUG) return;
        }
        if (log_filter_level == CLILogLevel::NONE) return;
        
        // Output directly to stdout (or log file if redirected)
        std::cout << line << std::endl;
        return;
    }
    
    // TUI mode: If terminal not yet set up, just buffer logs and don't draw.
    // They'll be shown when run() calls full_redraw().
    const char* color = C_DIM;
    
    if (line.find("ERROR") != std::string::npos) {
        color = C_BRED;
        if (log_filter_level < CLILogLevel::ERROR) return;
    } else if (line.find("WARN") != std::string::npos) {
        color = C_BYELLOW;
        if (log_filter_level < CLILogLevel::WARNING) return;
    } else if (line.find("INFO") != std::string::npos) {
        color = C_BGREEN;
        if (log_filter_level < CLILogLevel::INFO) return;
    } else {
        if (log_filter_level < CLILogLevel::DEBUG) return;
    }
    
    if (log_filter_level == CLILogLevel::NONE) return;
    
    std::lock_guard<std::mutex> lock(display_mutex);
    std::string formatted = std::string(color) + "[" + get_timestamp() + "] " + line + C_RESET;
    log_buffer.push_front(formatted);
    while (log_buffer.size() > 100) log_buffer.pop_back();
    
    // Only draw if terminal is set up.
    if (tui_ready_) {
        draw_logs_panel();
        draw_prompt();
    }
}

void TerminalCLI::handle_keypress(char c) {
    // The UI mutex is also used by log/event callbacks. We must not hold it while
    // executing commands, otherwise nested rendering (add_cmd_output/add_message)
    // can deadlock the TUI.
    std::unique_lock<std::mutex> lock(display_mutex);

    if (c == '\n' || c == '\r') {
        if (!current_input.empty()) {
            std::string cmd = current_input;
            current_input.clear();
            cursor_pos = 0;
            draw_prompt();

            // Release UI lock while processing commands.
            lock.unlock();
            process_command(cmd);
            lock.lock();
            draw_prompt();
        }
    } else if (c == 127 || c == 8) {
        if (cursor_pos > 0) {
            current_input.erase(cursor_pos - 1, 1);
            cursor_pos--;
            draw_prompt();
        }
    } else if (c == 27) {
        char seq[2];
        if (read(g_tty_fd, &seq[0], 1) == 1 && seq[0] == '[') {
            if (read(g_tty_fd, &seq[1], 1) == 1) {
                if (seq[1] == 'D' && cursor_pos > 0) { cursor_pos--; draw_prompt(); }
                else if (seq[1] == 'C' && cursor_pos < current_input.length()) { cursor_pos++; draw_prompt(); }
            }
        }
    } else if (c == 3) {
        running = false;
    } else if (c == 12) {
        full_redraw();
    } else if (c >= 32 && c < 127) {
        current_input.insert(cursor_pos, 1, c);
        cursor_pos++;
        draw_prompt();
    }
}

void TerminalCLI::full_redraw() {
    update_terminal_size();
    calculate_layout();
    update_peer_list();
    
    write_tty(ESC_HIDE_CURSOR);
    write_tty(ESC_CLEAR);
    write_tty(ESC_HOME);
    
    draw_header();
    draw_peers_panel();
    refresh_telemetry_buffer_locked();
    draw_messages_panel();
    draw_cmd_output_panel();
    draw_sys_resources_panel();
    draw_engine_resources_panel();
    draw_logs_panel();
    draw_prompt();
    
    write_tty(ESC_SHOW_CURSOR);
}

void TerminalCLI::refresh_telemetry_buffer_locked() {
    // Must be called with display_mutex held.
    telemetry_buffer.clear();

    // Snapshot telemetry JSON and render a compact, stable set of fields.
    try {
        const std::string js = Telemetry::getInstance().snapshot_json("cli");
        if (js.empty() || js == "{}") {
            telemetry_buffer.push_back(std::string(C_DIM) + "telemetry: disabled" + C_RESET);
            return;
        }
        auto j = nlohmann::json::parse(js, nullptr, false);
        if (j.is_discarded() || !j.is_object()) {
            telemetry_buffer.push_back(std::string(C_BRED) + "telemetry: parse error" + C_RESET);
            return;
        }

        auto get_i64 = [&](const nlohmann::json& obj, const std::string& k, int64_t def = 0) -> int64_t {
            if (!obj.is_object()) return def;
            auto it = obj.find(k);
            if (it == obj.end()) return def;
            if (it->is_number_integer()) return it->get<int64_t>();
            if (it->is_number_unsigned()) return static_cast<int64_t>(it->get<uint64_t>());
            if (it->is_number_float()) return static_cast<int64_t>(it->get<double>());
            return def;
        };

        const int64_t uptime_ms = get_i64(j, "uptime_ms", 0);
        const int64_t up_s = uptime_ms / 1000;
        const int64_t up_m = up_s / 60;
        const int64_t up_h = up_m / 60;

        telemetry_buffer.push_back(std::string(C_BCYAN) + "uptime " + C_RESET +
                                   std::to_string(up_h) + "h" + std::to_string(up_m % 60) + "m" + std::to_string(up_s % 60) + "s");

        const auto& counters = j.value("counters", nlohmann::json::object());
        const auto& gauges = j.value("gauges", nlohmann::json::object());

        auto g = [&](const std::string& k) -> int64_t { return get_i64(gauges, k, 0); };
        auto c = [&](const std::string& k) -> int64_t { return get_i64(counters, k, 0); };

        telemetry_buffer.push_back(std::string(C_MAGENTA) + "peers" + C_RESET +
                                   " total=" + std::to_string(g("peers_total")) +
                                   " conn=" + std::to_string(g("peers_connected")));
        telemetry_buffer.push_back("state C=" + std::to_string(g("peers_state_connecting")) +
                                   " H=" + std::to_string(g("peers_state_handshaking")) +
                                   " R=" + std::to_string(g("peers_state_ready")));
        telemetry_buffer.push_back("pending msgs=" + std::to_string(g("pending_messages_total")));

        telemetry_buffer.push_back(std::string(C_GREEN) + "connect" + C_RESET +
                                   " ok=" + std::to_string(c("connect_success_total")) +
                                   " fail=" + std::to_string(c("connect_failed_total")) +
                                   " sup=" + std::to_string(c("connect_suppressed_total")));
        telemetry_buffer.push_back(std::string(C_GREEN) + "handshake" + C_RESET +
                                   " ok=" + std::to_string(c("handshake_success_total")) +
                                   " fail=" + std::to_string(c("handshake_failed_total")));

        telemetry_buffer.push_back(std::string(C_YELLOW) + "noise" + C_RESET +
                                   " decrypt_fail=" + std::to_string(c("noise_decrypt_fail_total")) +
                                   " reset=" + std::to_string(c("noise_session_reset_total")));

        telemetry_buffer.push_back(std::string(C_CYAN) + "tx" + C_RESET +
                                   " msgs=" + std::to_string(c("tx_messages_total")) +
                                   " bytes=" + std::to_string(c("tx_bytes_total")));
        telemetry_buffer.push_back(std::string(C_CYAN) + "rx" + C_RESET +
                                   " ev=" + std::to_string(c("rx_events_total")) +
                                   " bytes=" + std::to_string(c("rx_bytes_total")));

        telemetry_buffer.push_back("netchg total=" + std::to_string(c("network_change_total")));
    } catch (...) {
        telemetry_buffer.push_back(std::string(C_BRED) + "telemetry: exception" + C_RESET);
    }
}

void TerminalCLI::draw_header() {
    int w = term_width;
    std::ostringstream oss;
    
    oss << "\033[1;1H" << C_CYAN << C_BOLD << BOX_TL << repeat_str(BOX_H, w - 2) << BOX_TR << C_RESET;
    
    std::string pid = safe_substr(node.getPeerId(), 0, 14);
    if (node.getPeerId().length() > 14) pid += "..";
    
    oss << "\033[2;1H" << C_CYAN << BOX_V << C_RESET;
    oss << C_BOLD << C_BG_BLUE << " LiteP2P " << C_RESET
        << " │ ID:" << C_BCYAN << pid << C_RESET
        << " │ " << (node.isRunning() ? (std::string(C_BGREEN) + "●Run") : (std::string(C_RED) + "○Stop")) << C_RESET
        << " │ Filter:" << C_BYELLOW << get_log_level_name(log_filter_level) << C_RESET
        << " │ Peers:" << C_BCYAN << connected_peers.size() << "/" << peer_list.size() << C_RESET;
    oss << "\033[2;" << w << "H" << C_CYAN << BOX_V << C_RESET;
    
    write_tty(oss.str());
}

void TerminalCLI::draw_peers_panel() {
    int w = peers_panel_width;
    int h = peers_panel_height;
    int start = peers_start_row;
    
    std::ostringstream oss;
    
    oss << "\033[" << start << ";1H" << C_CYAN << BOX_LT << repeat_str(BOX_H, w) << BOX_TT << C_RESET;
    
    std::string title = " PEERS (" + std::to_string(peer_list.size()) + ") ";
    oss << "\033[" << start << ";3H" << C_CYAN << C_BOLD << title << C_RESET;
    
    for (int i = 0; i < h; i++) {
        int row = start + 1 + i;
        oss << "\033[" << row << ";1H" << ESC_CLEAR_LINE << C_CYAN << BOX_V << C_RESET;
        
        if (i < (int)peer_list.size()) {
            auto& p = peer_list[i];
            std::string icon = p.connected ? (std::string(C_BGREEN) + "●") : (std::string(C_DIM) + "○");
            const std::string status_label = p.connected ? "Conn" : "Disc";
            std::string status = p.connected ? (std::string(C_BGREEN) + status_label) : (std::string(C_DIM) + status_label);

            // Compose: " <icon> <id> (<ip:port>) [Conn]"
            // Keep status always visible; truncate the middle if needed.
            const std::string addr = p.network_id.empty() ? "?" : p.network_id;
            const std::string proto = p.transport;
            const std::string suffix_plain = " [" + status_label + (proto.empty() ? "" : (" " + proto)) + "]";
            const std::string status_suffix = " [" + status + C_RESET + (proto.empty() ? "" : (" " + proto)) + "]";

            // Visible fixed pieces (approx, excluding ANSI inside status):
            // leading: " " + icon + " " => 3
            // addr wrapper: " (" + addr + ")" => 3 + len(addr)
            // status wrapper: " [Conn]" or " [Conn UDP]" => suffix_plain.size()
            int inner = std::max(0, w - 1);
            int reserved = 3 /*lead*/ + 3 /*space+parens*/ + (int)addr.size() + (int)suffix_plain.size();
            int max_id_len = std::max(6, inner - reserved);

            std::string display_id = p.id;
            if ((int)visible_len(display_id) > max_id_len) {
                display_id = truncate_str(display_id, (size_t)max_id_len);
            }

            oss << " " << icon << C_RESET << " " << display_id << " (" << addr << ")" << status_suffix;
        }
        
        oss << "\033[" << row << ";" << (w + 1) << "H" << C_CYAN << BOX_V << C_RESET;
    }
    
    write_tty(oss.str());
}

void TerminalCLI::draw_messages_panel() {
    int start_col = peers_panel_width + 2;
    int w = term_width - peers_panel_width - 3;
    int h = peers_panel_height;
    int start = peers_start_row;
    
    std::ostringstream oss;
    
    // Split messages panel into: [messages | telemetry]
    int telemetry_w = std::min(42, std::max(26, w / 3));
    int msg_w = std::max(10, w - telemetry_w - 1); // 1 col separator
    int sep_col = start_col + msg_w;

    std::string title_left = " MESSAGES ";
    std::string title_right = " TELEMETRY ";
    oss << "\033[" << start << ";" << (start_col + 2) << "H" << C_MAGENTA << C_BOLD << title_left << C_RESET;
    oss << "\033[" << start << ";" << (sep_col + 2) << "H" << C_CYAN << C_BOLD << title_right << C_RESET;
    oss << "\033[" << start << ";" << term_width << "H" << C_CYAN << BOX_RT << C_RESET;
    
    for (int i = 0; i < h; i++) {
        int row = start + 1 + i;
        // Clear full row area
        oss << "\033[" << row << ";" << start_col << "H";
        for (int j = 0; j < w; j++) oss << " ";

        // Vertical separator
        if (sep_col > start_col && sep_col < term_width) {
            oss << "\033[" << row << ";" << sep_col << "H" << C_DIM << "│" << C_RESET;
        }

        // Messages (left)
        oss << "\033[" << row << ";" << start_col << "H";
        if (i < (int)message_buffer.size()) {
            oss << truncate_str(message_buffer[i], std::max(0, msg_w - 2));
        }

        // Telemetry (right)
        oss << "\033[" << row << ";" << (sep_col + 1) << "H";
        if (i < (int)telemetry_buffer.size()) {
            oss << truncate_str(telemetry_buffer[i], std::max(0, telemetry_w - 2));
        }
        
        oss << "\033[" << row << ";" << term_width << "H" << C_CYAN << BOX_V << C_RESET;
    }
    
    write_tty(oss.str());
}

void TerminalCLI::draw_cmd_output_panel() {
    // Output panel takes the left 1/3 of the row
    int panel_width = (term_width - 2) / 3;
    int h = cmd_output_height;
    int start = cmd_output_start_row;
    
    std::ostringstream oss;
    
    // Draw top border for OUTPUT section only (left portion)
    oss << "\033[" << start << ";1H" << C_CYAN << BOX_LT << repeat_str(BOX_H, panel_width - 1) << BOX_TT << C_RESET;
    
    std::string title = " OUTPUT ";
    oss << "\033[" << start << ";3H" << C_GREEN << C_BOLD << title << C_RESET;
    
    for (int i = 0; i < h; i++) {
        int row = start + 1 + i;
        oss << "\033[" << row << ";1H" << C_CYAN << BOX_V << C_RESET;
        
        // Clear the panel area
        for (int j = 0; j < panel_width - 2; j++) oss << " ";
        
        // Draw content
        oss << "\033[" << row << ";2H";
        if (i < (int)cmd_output_buffer.size()) {
            oss << " " << truncate_str(cmd_output_buffer[i], panel_width - 4);
        }
        
        // Right border of this panel (also serves as separator)
        oss << "\033[" << row << ";" << panel_width << "H" << C_CYAN << BOX_V << C_RESET;
    }
    
    write_tty(oss.str());
}

void TerminalCLI::draw_sys_resources_panel() {
    // System resources panel takes the middle 1/3 of the row
    int panel_width = (term_width - 2) / 3;
    int start_col = panel_width + 1;
    int h = cmd_output_height;
    int start = cmd_output_start_row;
    
    SystemResources sys = get_system_resources();
    
    std::ostringstream oss;
    
    // Draw top border for SYSTEM section
    oss << "\033[" << start << ";" << start_col << "H" << C_CYAN << repeat_str(BOX_H, panel_width - 1) << BOX_TT << C_RESET;
    
    std::string title = " RESOURCE AVAILABLE ";
    oss << "\033[" << start << ";" << (start_col + 2) << "H" << C_MAGENTA << C_BOLD << title << C_RESET;
    
    // Build resource lines
    std::vector<std::string> lines;
    {
        std::ostringstream line;
        line << C_DIM << "CPU: " << C_RESET << sys.cpu_count << " cores";
        if (sys.cpu_usage_percent > 0.0) {
            line << ", " << std::fixed << std::setprecision(1) << sys.cpu_usage_percent << "% used";
        }
        lines.push_back(line.str());
    }
    {
        std::ostringstream line;
        line << C_DIM << "Load: " << C_RESET
             << std::fixed << std::setprecision(2) << sys.load_1
             << " " << sys.load_5
             << " " << sys.load_15;
        lines.push_back(line.str());
    }
    {
        std::ostringstream line;
        line << C_DIM << "RAM: " << C_RESET << sys.used_ram_mb << "/" << sys.total_ram_mb << " MB";
        if (sys.total_ram_mb > 0) {
            const double pct = (double)sys.used_ram_mb / (double)sys.total_ram_mb * 100.0;
            line << " (" << std::fixed << std::setprecision(1) << pct << "%)";
        }
        lines.push_back(line.str());
    }
    {
        std::ostringstream line;
        line << C_DIM << "RAM Free: " << C_RESET << sys.available_ram_mb << " MB";
        lines.push_back(line.str());
    }
    {
        std::ostringstream line;
        if (sys.total_swap_mb > 0) {
            const uint64_t used_swap = (sys.total_swap_mb > sys.free_swap_mb) ? (sys.total_swap_mb - sys.free_swap_mb) : 0;
            line << C_DIM << "Swap: " << C_RESET << used_swap << "/" << sys.total_swap_mb << " MB";
        } else {
            line << C_DIM << "Swap: " << C_RESET << "n/a";
        }
        lines.push_back(line.str());
    }
    {
        std::ostringstream line;
        if (sys.total_disk_mb > 0) {
            line << C_DIM << "Disk(/): " << C_RESET << sys.free_disk_mb << "/" << sys.total_disk_mb << " MB free";
        } else {
            line << C_DIM << "Disk(/): " << C_RESET << "n/a";
        }
        lines.push_back(line.str());
    }
    {
        std::ostringstream line;
        if (sys.uptime_sec > 0) {
            line << C_DIM << "Uptime: " << C_RESET << format_uptime(sys.uptime_sec);
            lines.push_back(line.str());
        }
    }
    {
        // RAM usage bar
        int bar_width = panel_width - 10;
        if (bar_width > 5 && sys.total_ram_mb > 0) {
            double ratio = (double)sys.used_ram_mb / sys.total_ram_mb;
            int filled = static_cast<int>(ratio * bar_width);
            std::ostringstream line;
            line << C_DIM << "Usage: " << C_RESET << "[";
            for (int i = 0; i < bar_width; i++) {
                if (i < filled) line << (ratio > 0.8 ? C_RED : C_GREEN) << "█";
                else line << C_DIM << "░";
            }
            line << C_RESET << "]";
            lines.push_back(line.str());
        }
    }
    
    for (int i = 0; i < h; i++) {
        int row = start + 1 + i;
        oss << "\033[" << row << ";" << start_col << "H";
        
        // Clear panel area
        for (int j = 0; j < panel_width - 1; j++) oss << " ";
        
        // Draw content
        oss << "\033[" << row << ";" << (start_col + 1) << "H";
        if (i < (int)lines.size()) {
            oss << truncate_str(lines[i], panel_width - 4);
        }
        
        // Right border
        oss << "\033[" << row << ";" << (start_col + panel_width - 1) << "H" << C_CYAN << BOX_V << C_RESET;
    }
    
    write_tty(oss.str());
}

void TerminalCLI::draw_engine_resources_panel() {
    // Engine resources panel takes the right 1/3 of the row
    int panel_width = (term_width - 2) / 3;
    int start_col = panel_width * 2 + 1;
    int remaining_width = term_width - start_col;
    int h = cmd_output_height;
    int start = cmd_output_start_row;
    
    EngineResources eng = get_engine_resources();
    
    std::ostringstream oss;
    
    // Draw top border for ENGINE section
    oss << "\033[" << start << ";" << start_col << "H" << C_CYAN << repeat_str(BOX_H, remaining_width - 1) << BOX_RT << C_RESET;
    
    std::string title = " RESOURCE UTILIZATION ";
    oss << "\033[" << start << ";" << (start_col + 2) << "H" << C_BCYAN << C_BOLD << title << C_RESET;
    
    // Build resource lines
    std::vector<std::string> lines;
    {
        std::ostringstream line;
        line << C_DIM << "PID: " << C_RESET << eng.pid;
        lines.push_back(line.str());
    }
    {
        std::ostringstream line;
        line << C_DIM << "Resident Mem: " << C_RESET << eng.resident_memory_mb << " MB";
        lines.push_back(line.str());
    }
    {
        std::ostringstream line;
        line << C_DIM << "Virtual Mem:  " << C_RESET << eng.virtual_memory_mb << " MB";
        lines.push_back(line.str());
    }
    {
        std::ostringstream line;
        line << C_DIM << "CPU: " << C_RESET;
        if (eng.cpu_usage_percent > 0.0) {
            line << std::fixed << std::setprecision(1) << eng.cpu_usage_percent << "%";
            line << " (" << std::fixed << std::setprecision(2) << (eng.cpu_usage_percent / 100.0) << " cores)";
        } else {
            line << "n/a";
        }
        line << C_DIM << "  time=" << C_RESET << std::fixed << std::setprecision(2) << eng.cpu_time_sec << "s";
        lines.push_back(line.str());
    }
    {
        std::ostringstream line;
        line << C_DIM << "Threads: " << C_RESET;
        if (eng.thread_count > 0) line << eng.thread_count;
        else line << "n/a";
        line << C_DIM << "  FDs: " << C_RESET;
        if (eng.open_fds > 0) line << eng.open_fds;
        else line << "n/a";
        lines.push_back(line.str());
    }
    {
        std::ostringstream line;
        if (eng.peak_resident_memory_mb > 0) {
            line << C_DIM << "Peak RSS: " << C_RESET << eng.peak_resident_memory_mb << " MB";
            lines.push_back(line.str());
        }
    }
    {
        std::ostringstream line;
        if (eng.voluntary_ctx_switches > 0 || eng.involuntary_ctx_switches > 0) {
            line << C_DIM << "CtxSw: " << C_RESET << eng.voluntary_ctx_switches
                 << C_DIM << " vol, " << C_RESET << eng.involuntary_ctx_switches
                 << C_DIM << " invol" << C_RESET;
            lines.push_back(line.str());
        }
    }
    {
        // Memory indicator
        std::ostringstream line;
        if (eng.resident_memory_mb < 100) {
            line << C_GREEN << "● " << C_RESET << "Memory: Low";
        } else if (eng.resident_memory_mb < 500) {
            line << C_YELLOW << "● " << C_RESET << "Memory: Moderate";
        } else {
            line << C_RED << "● " << C_RESET << "Memory: High";
        }
        lines.push_back(line.str());
    }
    
    for (int i = 0; i < h; i++) {
        int row = start + 1 + i;
        oss << "\033[" << row << ";" << start_col << "H";
        
        // Clear panel area
        for (int j = 0; j < remaining_width - 1; j++) oss << " ";
        
        // Draw content
        oss << "\033[" << row << ";" << (start_col + 1) << "H";
        if (i < (int)lines.size()) {
            oss << truncate_str(lines[i], remaining_width - 4);
        }
        
        // Right border
        oss << "\033[" << row << ";" << term_width << "H" << C_CYAN << BOX_V << C_RESET;
    }
    
    write_tty(oss.str());
}

void TerminalCLI::draw_logs_panel() {
    int w = term_width;
    int h = logs_panel_height;
    int start = logs_start_row;
    
    std::ostringstream oss;
    
    oss << "\033[" << start << ";1H" << C_CYAN << BOX_LT << repeat_str(BOX_H, w - 2) << BOX_RT << C_RESET;
    
    std::string title = " LOGS ";
    oss << "\033[" << start << ";3H" << C_YELLOW << C_BOLD << title << C_RESET;
    
    for (int i = 0; i < h; i++) {
        int row = start + 1 + i;
        oss << "\033[" << row << ";1H" << ESC_CLEAR_LINE << C_CYAN << BOX_V << C_RESET;
        
        if (i < (int)log_buffer.size()) {
            oss << " " << truncate_str(log_buffer[i], w - 4);
        }
        
        oss << "\033[" << row << ";" << w << "H" << C_CYAN << BOX_V << C_RESET;
    }
    
    write_tty(oss.str());
}

void TerminalCLI::draw_prompt() {
    int w = term_width;
    int row = prompt_row;
    
    std::ostringstream oss;
    
    oss << "\033[" << row << ";1H" << C_CYAN << BOX_LT << repeat_str(BOX_H, w - 2) << BOX_RT << C_RESET;
    
    oss << "\033[" << (row + 1) << ";1H" << ESC_CLEAR_LINE << C_CYAN << BOX_V << C_RESET;
    oss << " " << C_GREEN << C_BOLD << "litep2p" << C_RESET << C_DIM << " > " << C_RESET << current_input;
    oss << "\033[" << (row + 1) << ";" << w << "H" << C_CYAN << BOX_V << C_RESET;
    
    oss << "\033[" << (row + 2) << ";1H" << C_CYAN << BOX_BL << repeat_str(BOX_H, w - 2) << BOX_BR << C_RESET;
    
    int cursor_col = 13 + cursor_pos;
    oss << "\033[" << (row + 1) << ";" << cursor_col << "H";
    
    write_tty(oss.str());
}

void TerminalCLI::add_log(const std::string& msg) {
    if (force_plain_cli) {
        std::cout << msg << std::endl;
        return;
    }
    log_buffer.push_front(msg);
    while (log_buffer.size() > 100) log_buffer.pop_back();
}

void TerminalCLI::add_cmd_output(const std::string& msg) {
    if (force_plain_cli) {
        std::cout << msg << std::endl;
        return;
    }
    std::lock_guard<std::mutex> lock(display_mutex);
    cmd_output_buffer.push_front(msg);
    while (cmd_output_buffer.size() > 20) cmd_output_buffer.pop_back();

    if (tui_ready_) {
        draw_cmd_output_panel();
        draw_prompt();
    }
}

void TerminalCLI::add_message(const std::string& msg) {
    if (force_plain_cli) {
        std::cout << msg << std::endl;
        return;
    }
    std::lock_guard<std::mutex> lock(display_mutex);
    message_buffer.push_front(msg);
    while (message_buffer.size() > 50) message_buffer.pop_back();

    if (tui_ready_) {
        draw_messages_panel();
        draw_prompt();
    }
}

void TerminalCLI::update_peer_list() {
    peer_list.clear();
    auto peers = node.getDiscoveredPeers();
    
    for (const auto& pid : peers) {
        ParsedPeerEntry parsed = parse_peer_entry(pid);
        if (parsed.peer_id.empty()) continue;

        PeerInfo info;
        info.id = parsed.peer_id;
        // Keep a moderately long short-id for places where we show a compact id.
        // Rendering in the peers panel uses the full id truncated-to-fit.
        info.short_id = safe_substr(parsed.peer_id, 0, 25);
        if (parsed.peer_id.length() > 25) info.short_id += "..";
        info.connected = parsed.connected || (connected_peers.count(parsed.peer_id) > 0);
        info.last_seen = get_short_time();
        info.network_id = parsed.network_id;
        info.transport = parsed.transport;
        peer_list.push_back(info);
    }
}

static std::string resolve_peer_id_from_list(const std::vector<PeerInfo>& peers, const std::string& user_input, std::vector<std::string>* matches_out = nullptr) {
    const std::string needle = normalize_peer_prefix(user_input);
    if (needle.empty()) return "";

    std::vector<std::string> matches;
    matches.reserve(peers.size());

    // Exact match first
    for (const auto& p : peers) {
        if (p.id == needle) {
            matches.push_back(p.id);
            break;
        }
    }
    if (!matches.empty()) {
        if (matches_out) *matches_out = matches;
        return matches.front();
    }

    // Prefix match (case-sensitive; IDs are expected to be stable strings)
    for (const auto& p : peers) {
        if (p.id.rfind(needle, 0) == 0) {
            matches.push_back(p.id);
        }
    }

    if (matches_out) *matches_out = matches;
    if (matches.size() == 1) return matches.front();
    return "";
}

bool TerminalCLI::should_show_log(const std::string& level) {
    if (log_filter_level == CLILogLevel::NONE) return false;
    if (log_filter_level == CLILogLevel::DEBUG) return true;
    
    CLILogLevel lvl = CLILogLevel::DEBUG;
    if (level == "ERROR") lvl = CLILogLevel::ERROR;
    else if (level == "WARNING" || level == "WARN") lvl = CLILogLevel::WARNING;
    else if (level == "INFO") lvl = CLILogLevel::INFO;
    
    return static_cast<int>(lvl) <= static_cast<int>(log_filter_level);
}

std::string TerminalCLI::get_log_level_name(CLILogLevel level) {
    switch (level) {
        case CLILogLevel::ERROR: return "ERR";
        case CLILogLevel::WARNING: return "WRN";
        case CLILogLevel::INFO: return "INF";
        case CLILogLevel::DEBUG: return "ALL";
        case CLILogLevel::NONE: return "OFF";
        default: return "ALL";
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ENGINE CALLBACKS
// ═══════════════════════════════════════════════════════════════════════════

void TerminalCLI::on_log_message(const std::string& message) {
    if (force_plain_cli) {
        std::cout << message << std::endl;
        return;
    }
    capture_log_line(message);
}

void TerminalCLI::on_peer_discovered(const std::string&) {
    if (force_plain_cli) {
        update_peer_list();
        return;
    }

    // Avoid heavy redraw storms during engine startup (e.g., DB bootstrap).
    if (!tui_ready_) {
        return;
    }

    std::lock_guard<std::mutex> lock(display_mutex);
    update_peer_list();
    draw_header();
    draw_peers_panel();
    draw_prompt();
}

void TerminalCLI::on_peer_connected(const std::string& peer_id) {
    connected_peers.insert(peer_id);

    if (force_plain_cli) {
        update_peer_list();
        add_cmd_output(std::string("✓ Connected: ") + peer_id);
        return;
    }

    if (!tui_ready_) {
        // Record the event for later visibility, but skip redraw.
        add_cmd_output(C_BGREEN "✓ Connected: " + safe_substr(peer_id, 0, 16) + C_RESET);
        return;
    }
    
    {
        std::lock_guard<std::mutex> lock(display_mutex);
        update_peer_list();
        draw_header();
        draw_peers_panel();
        draw_prompt();
    }

    // Must be outside the UI lock (add_cmd_output locks internally).
    add_cmd_output(C_BGREEN "✓ Connected: " + safe_substr(peer_id, 0, 16) + C_RESET);
}

void TerminalCLI::on_peer_disconnected(const std::string& peer_id) {
    connected_peers.erase(peer_id);

    if (force_plain_cli) {
        update_peer_list();
        add_cmd_output(std::string("⚠ Disconnected: ") + peer_id);
        return;
    }

    if (!tui_ready_) {
        // Record the event for later visibility, but skip redraw.
        add_cmd_output(C_BYELLOW "⚠ Disconnected: " + safe_substr(peer_id, 0, 16) + C_RESET);
        return;
    }
    
    {
        std::lock_guard<std::mutex> lock(display_mutex);
        update_peer_list();
        draw_header();
        draw_peers_panel();
        draw_prompt();
    }

    // Must be outside the UI lock (add_cmd_output locks internally).
    add_cmd_output(C_BYELLOW "⚠ Disconnected: " + safe_substr(peer_id, 0, 16) + C_RESET);
}

void TerminalCLI::on_message_received(const std::string& from, const std::string& message) {
    // Special-case control plane responses so they don't clutter the chat panel.
    if (!message.empty() && message.front() == '{' &&
        message.find("\"type\"") != std::string::npos &&
        message.find("LP_ADMIN_ACK") != std::string::npos) {
        try {
            using json = nlohmann::json;
            const json j = json::parse(message);
            if (j.value("type", "") == "LP_ADMIN_ACK") {
                const bool ok = j.value("ok", false);
                const std::string request_id = j.value("request_id", "");
                const std::string msg = j.value("message", "");

                std::string desc;
                if (!request_id.empty()) {
                    auto it = pending_admin_requests_.find(request_id);
                    if (it != pending_admin_requests_.end()) {
                        desc = it->second;
                        pending_admin_requests_.erase(it);
                    }
                }

                std::string line;
                line += ok ? C_BGREEN "✓ " C_RESET : C_BRED "✗ " C_RESET;
                line += "LP_ADMIN_ACK from ";
                line += safe_substr(from, 0, 16);
                if (!desc.empty()) {
                    line += " (";
                    line += desc;
                    line += ")";
                }
                if (!msg.empty()) {
                    line += ": ";
                    line += msg;
                }
                add_cmd_output(line);

                if (j.contains("applied_settings")) {
                    add_cmd_output(C_DIM "applied_settings: " C_RESET + j["applied_settings"].dump());
                }
                return;
            }
        } catch (...) {
            // Fall through and show as normal message.
        }
    }

    std::string short_from = safe_substr(from, 0, 10);
    if (from.length() > 10) short_from += "..";
    
    std::string formatted = C_CYAN "[" + get_short_time() + "] " + C_BGREEN + short_from + ": " + C_RESET + message;
    add_message(formatted);
}

// ═══════════════════════════════════════════════════════════════════════════
// COMMAND PROCESSING
// ═══════════════════════════════════════════════════════════════════════════

void TerminalCLI::process_command(const std::string& input) {
    std::istringstream iss(input);
    std::string cmd;
    iss >> cmd;
    std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);
    
    if (cmd == "help" || cmd == "h" || cmd == "?") {
        cmd_help();
    } else if (cmd == "quit" || cmd == "exit" || cmd == "q") {
        cmd_quit();
    } else if (cmd == "peers" || cmd == "list" || cmd == "ls") {
        cmd_list_peers();
    } else if (cmd == "connect" || cmd == "c") {
        std::string peer_id;
        iss >> peer_id;
        cmd_connect(peer_id);
    } else if (cmd == "send" || cmd == "msg" || cmd == "m") {
        std::string peer_id;
        iss >> peer_id;
        std::string message;
        std::getline(iss, message);
        if (!message.empty() && message[0] == ' ') message = message.substr(1);
        cmd_send(peer_id, message);
    } else if (cmd == "broadcast" || cmd == "bc") {
        std::string message;
        std::getline(iss, message);
        if (!message.empty() && message[0] == ' ') message = message.substr(1);
        cmd_broadcast(message);
    } else if (cmd == "status" || cmd == "stat" || cmd == "s") {
        cmd_status();
    } else if (cmd == "logfilter" || cmd == "log" || cmd == "lf") {
        std::string level;
        iss >> level;
        cmd_log_filter(level);
    } else if (cmd == "clear" || cmd == "cls") {
        cmd_clear();
    } else if (cmd == "proxy") {
        std::string sub;
        iss >> sub;
        cmd_proxy(sub);
    } else if (cmd == "admin_proxy" || cmd == "ap") {
        std::string peer_id;
        std::string role;
        iss >> peer_id >> role;
        cmd_admin_proxy(peer_id, role);
    } else if (cmd == "refresh" || cmd == "r") {
        if (force_plain_cli) {
            update_peer_list();
            add_cmd_output("Refreshed");
        } else {
            std::lock_guard<std::mutex> lock(display_mutex);
            full_redraw();
        }
    } else if (!cmd.empty()) {
        add_cmd_output(C_YELLOW "Unknown: " + cmd + " (type 'help')" C_RESET);
    }
}

void TerminalCLI::cmd_help() {
    cmd_output_buffer.clear();
    add_cmd_output(C_CYAN "═══════════ COMMANDS ═══════════" C_RESET);
    add_cmd_output(C_GREEN "help" C_RESET "       Show this help");
    add_cmd_output(C_GREEN "peers" C_RESET "      Refresh peer list");
    add_cmd_output(C_GREEN "connect" C_RESET " id Connect to peer");
    add_cmd_output(C_GREEN "send" C_RESET " id m  Send message");
    add_cmd_output(C_GREEN "broadcast" C_RESET " m Broadcast to all");
    add_cmd_output(C_GREEN "status" C_RESET "     Show status");
    add_cmd_output(C_GREEN "proxy" C_RESET " r    Local proxy: off|gateway|exit|client|both|status");
    add_cmd_output(C_GREEN "admin_proxy" C_RESET " id r  Remote proxy role via LP_ADMIN (alias: ap)");
    add_cmd_output(C_YELLOW "logfilter" C_RESET " l error/warn/info/debug/none");
    add_cmd_output(C_GREEN "clear" C_RESET "      Clear panels");
    add_cmd_output(C_RED "quit" C_RESET "       Exit");

    add_cmd_output(C_CYAN "═══════════ PROXY TIPS ═══════════" C_RESET);
    add_cmd_output(C_DIM "Local enable:   proxy gateway   (or: proxy off / proxy client / proxy status)" C_RESET);
    add_cmd_output(C_DIM "Remote enable:  admin_proxy <peer> gateway" C_RESET);
    add_cmd_output(C_DIM "Remote requires target config.json: remote_control.enabled=true and allowed_senders includes YOUR peer_id." C_RESET);
}

void TerminalCLI::cmd_proxy(const std::string& subcmd) {
    std::string sub = subcmd;
    std::transform(sub.begin(), sub.end(), sub.begin(), ::tolower);

    if (sub.empty() || sub == "status") {
        std::string err;
        const std::string s = node.getProxySettingsSummary(&err);
        if (!err.empty()) {
            add_cmd_output(C_BYELLOW "proxy: " C_RESET + err);
        }
        add_cmd_output(s);
        return;
    }

    // Convenience aliases.
    if (sub == "on") sub = "gateway";
    if (sub == "exit") sub = "gateway";

    std::string err;
    if (!node.setProxyRole(sub, &err)) {
        add_cmd_output(C_BRED "✗ proxy: " C_RESET + (err.empty() ? "failed" : err));
        return;
    }
    add_cmd_output(C_BGREEN "✓ " C_RESET + node.getProxySettingsSummary(nullptr));
}

void TerminalCLI::cmd_admin_proxy(const std::string& target_peer_id, const std::string& role) {
    if (target_peer_id.empty() || role.empty()) {
        add_cmd_output(C_YELLOW "Usage: admin_proxy <peer_id> <off|gateway|exit|client|both>" C_RESET);
        return;
    }

    std::vector<std::string> matches;
    const std::string resolved = resolve_peer_id_from_list(peer_list, target_peer_id, &matches);
    if (resolved.empty()) {
        if (matches.empty()) {
            add_cmd_output(C_YELLOW "No match for: " + target_peer_id + C_RESET);
            add_cmd_output(C_DIM "Try: peers (to list full IDs)" C_RESET);
        } else {
            add_cmd_output(C_YELLOW "Ambiguous peer id prefix. Matches:" C_RESET);
            for (const auto& m : matches) add_cmd_output("- " + m);
        }
        return;
    }

    std::string r = role;
    std::transform(r.begin(), r.end(), r.begin(), ::tolower);
    if (r == "on") r = "gateway";
    if (r == "exit") r = "gateway";

    using json = nlohmann::json;
    json msg;
    msg["type"] = "LP_ADMIN";
    msg["cmd"] = "SET_PROXY_SETTINGS";
    msg["target_peer_id"] = resolved;

    if (r == "both") {
        msg["settings"] = json{{"enable_gateway", true}, {"enable_client", true}, {"enable_test_echo", false}};
    } else if (r == "gateway" || r == "client" || r == "off") {
        msg["role"] = r;
    } else {
        add_cmd_output(C_YELLOW "Role must be one of: off|gateway|exit|client|both" C_RESET);
        return;
    }

    // Create a request_id for correlation.
    static std::atomic<uint64_t> seq{0};
    const uint64_t n = ++seq;
    const std::string request_id = node.getPeerId() + ":" + std::to_string((uint64_t)time(nullptr)) + ":" + std::to_string(n);
    msg["request_id"] = request_id;

    // Best effort: ensure we attempt a connection first.
    node.connectToPeer(resolved);

    pending_admin_requests_[request_id] = "admin_proxy " + safe_substr(resolved, 0, 10) + ".. " + r;
    node.sendMessageToPeer(resolved, msg.dump());
    add_cmd_output(C_BGREEN "✓ Sent LP_ADMIN to " C_RESET + safe_substr(resolved, 0, 16));
}

void TerminalCLI::cmd_quit() {
    add_cmd_output("Shutting down...");
    running = false;
}

void TerminalCLI::cmd_list_peers() {
    if (!force_plain_cli) {
        std::lock_guard<std::mutex> lock(display_mutex);
        update_peer_list();
        draw_header();
        draw_peers_panel();
        draw_prompt();
    } else {
        update_peer_list();
    }
    
    cmd_output_buffer.clear();
    add_cmd_output(C_CYAN "═══════════ PEERS (full) ═══════════" C_RESET);
    add_cmd_output(C_DIM "Tip: use 'connect <id-prefix>' then 'send <id-prefix> <msg>'" C_RESET);
    add_cmd_output(C_CYAN "Found: " + std::to_string(peer_list.size()) + " peer(s)" C_RESET);
    for (const auto& p : peer_list) {
        std::string line = p.id;
        line += "  [";
        line += (p.connected ? std::string("CONNECTED") : std::string("DISCONNECTED"));
        if (!p.transport.empty()) {
            line += "|" + p.transport;
        }
        line += "]";
        add_cmd_output(line);
    }
}

void TerminalCLI::cmd_connect(const std::string& peer_id) {
    if (peer_id.empty()) {
        add_cmd_output(C_YELLOW "Usage: connect <peer_id>" C_RESET);
        return;
    }

    std::vector<std::string> matches;
    std::string resolved = resolve_peer_id_from_list(peer_list, peer_id, &matches);
    if (resolved.empty()) {
        if (matches.empty()) {
            add_cmd_output(C_YELLOW "No match for: " + peer_id + C_RESET);
            add_cmd_output(C_DIM "Try: peers (to list full IDs)" C_RESET);
        } else {
            add_cmd_output(C_YELLOW "Ambiguous peer id prefix. Matches:" C_RESET);
            for (const auto& m : matches) add_cmd_output("- " + m);
        }
        return;
    }

    add_cmd_output("Connecting to " + safe_substr(resolved, 0, 24) + "...");
    node.connectToPeer(resolved);
}

void TerminalCLI::cmd_send(const std::string& peer_id, const std::string& message) {
    if (peer_id.empty() || message.empty()) {
        add_cmd_output(C_YELLOW "Usage: send <peer_id> <message>" C_RESET);
        return;
    }

    std::vector<std::string> matches;
    std::string resolved = resolve_peer_id_from_list(peer_list, peer_id, &matches);
    if (resolved.empty()) {
        if (matches.empty()) {
            add_cmd_output(C_YELLOW "No match for: " + peer_id + C_RESET);
            add_cmd_output(C_DIM "Try: peers (to list full IDs)" C_RESET);
        } else {
            add_cmd_output(C_YELLOW "Ambiguous peer id prefix. Matches:" C_RESET);
            for (const auto& m : matches) add_cmd_output("- " + m);
        }
        return;
    }
    
    node.sendMessageToPeer(resolved, message);
    
    std::string short_id = safe_substr(resolved, 0, 10);
    if (resolved.length() > 10) short_id += "..";
    
    std::string formatted = C_CYAN "[" + get_short_time() + "] " + C_BYELLOW "→ " + short_id + ": " + C_RESET + message;
    add_message(formatted);
    add_cmd_output(C_BGREEN "✓ Sent to " + short_id + C_RESET);
}

void TerminalCLI::cmd_broadcast(const std::string& message) {
    if (message.empty()) {
        add_cmd_output(C_YELLOW "Usage: broadcast <message>" C_RESET);
        return;
    }
    
    // node.getDiscoveredPeers() returns display-formatted entries; extract peer_id.
    auto peers = node.getDiscoveredPeers();
    size_t sent = 0;
    for (const auto& peer_line : peers) {
        ParsedPeerEntry parsed = parse_peer_entry(peer_line);
        if (parsed.peer_id.empty()) continue;
        node.sendMessageToPeer(parsed.peer_id, message);
        sent++;
    }
    
    std::string formatted = C_CYAN "[" + get_short_time() + "] " + C_MAGENTA "[BC]: " + C_RESET + message;
    add_message(formatted);
    add_cmd_output(C_BGREEN "✓ Broadcast to " + std::to_string(sent) + " peer(s)" C_RESET);
}

void TerminalCLI::cmd_status() {
    cmd_output_buffer.clear();
    add_cmd_output(C_CYAN "═══════════ STATUS ═══════════" C_RESET);
    add_cmd_output("Peer ID: " + node.getPeerId());
    add_cmd_output(std::string("Engine:  ") + (node.isRunning() ? C_BGREEN "Running" : C_RED "Stopped") + C_RESET);
    add_cmd_output("Discovered: " + std::to_string(peer_list.size()) + " peers");
    add_cmd_output("Connected:  " + std::to_string(connected_peers.size()) + " peers");
    add_cmd_output("Log Filter: " + get_log_level_name(log_filter_level));
}

void TerminalCLI::cmd_log_filter(const std::string& level) {
    std::string lvl = level;
    std::transform(lvl.begin(), lvl.end(), lvl.begin(), ::tolower);
    
    if (lvl.empty()) {
        add_cmd_output("Current: " + get_log_level_name(log_filter_level));
        return;
    }
    
    if (lvl == "error" || lvl == "e") log_filter_level = CLILogLevel::ERROR;
    else if (lvl == "warn" || lvl == "warning" || lvl == "w") log_filter_level = CLILogLevel::WARNING;
    else if (lvl == "info" || lvl == "i") log_filter_level = CLILogLevel::INFO;
    else if (lvl == "debug" || lvl == "d" || lvl == "all" || lvl == "a") log_filter_level = CLILogLevel::DEBUG;
    else if (lvl == "none" || lvl == "off" || lvl == "n") log_filter_level = CLILogLevel::NONE;
    else {
        add_cmd_output(C_YELLOW "Use: error, warn, info, debug, none" C_RESET);
        return;
    }
    
    add_cmd_output(C_BGREEN "✓ Filter: " + get_log_level_name(log_filter_level) + C_RESET);

    if (!force_plain_cli) {
        std::lock_guard<std::mutex> lock(display_mutex);
        draw_header();
        draw_prompt();
    }
}

void TerminalCLI::cmd_clear() {
    log_buffer.clear();
    cmd_output_buffer.clear();
    message_buffer.clear();

    if (force_plain_cli) {
        add_cmd_output("(cleared)");
        return;
    }

    {
        std::lock_guard<std::mutex> lock(display_mutex);
        full_redraw();
    }

    // Must be outside the UI lock (add_cmd_output locks internally).
    add_cmd_output(C_BGREEN "✓ Cleared" C_RESET);
}
