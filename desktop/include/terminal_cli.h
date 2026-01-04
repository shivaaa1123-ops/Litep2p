/**
 * terminal_cli.h - Multi-Panel Fixed-Layout TUI
 * 
 * Layout (minimum 80x24 terminal):
 * ╔═══════════════════════════════════════════════════════════════════════════════╗
 * ║  HEADER: Status bar with peer ID, status, filter level                        ║
 * ╠════════════════════════════════╦══════════════════════════════════════════════╣
 * ║  PEERS PANEL                   ║  MESSAGES PANEL                              ║
 * ║  List of peers with status     ║  Chat messages (sent/received)               ║
 * ╠════════════════════════════════╩══════════════════════════════════════════════╣
 * ║  COMMAND OUTPUT PANEL                                                         ║
 * ║  Results from help, status, etc.                                              ║
 * ╠═══════════════════════════════════════════════════════════════════════════════╣
 * ║  LOGS PANEL                                                                   ║
 * ║  Engine logs (newest at top)                                                  ║
 * ╠═══════════════════════════════════════════════════════════════════════════════╣
 * ║  PROMPT: litep2p > [input]                                                    ║
 * ╚═══════════════════════════════════════════════════════════════════════════════╝
 */

#ifndef TERMINAL_CLI_H
#define TERMINAL_CLI_H

#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <atomic>
#include <set>
#include <unordered_map>
#include <chrono>

class P2PNode;

enum class CLILogLevel {
    NONE = 0,
    ERROR = 1,
    WARNING = 2,
    INFO = 3,
    DEBUG = 4
};

// Peer info for display
struct PeerInfo {
    std::string id;
    std::string short_id;
    bool connected;
    std::string last_seen;
    std::string network_id; // ip:port
};

class TerminalCLI {
public:
    explicit TerminalCLI(P2PNode& node, bool force_plain = false, bool daemon_mode = false);
    ~TerminalCLI();
    
    void run();
    void stop();

    // TUI-only: controls how often the telemetry pane is refreshed/redrawn.
    // Clamped to [100, 60000] ms. No-op in plain/daemon mode.
    void setTelemetryRefreshIntervalMs(int ms);
    
    // Callbacks from engine
    void on_log_message(const std::string& message);
    void on_peer_discovered(const std::string& peer_id);
    void on_peer_connected(const std::string& peer_id);
    void on_peer_disconnected(const std::string& peer_id);
    void on_message_received(const std::string& from, const std::string& message);
    
    // Called by stdout capture thread
    void capture_log_line(const std::string& line);

private:
    P2PNode& node;
    bool force_plain_cli;
    bool daemon_mode_;  // Run without reading stdin
    std::atomic<bool> running;
    // True only after setup_terminal() + initial full_redraw() completed.
    // Engine callbacks may arrive before run() starts (or before terminal setup).
    std::atomic<bool> tui_ready_{false};
    
    // Terminal dimensions
    int term_width;
    int term_height;
    
    // Input state
    std::string current_input;
    size_t cursor_pos;
    
    // Log filtering
    CLILogLevel log_filter_level;
    
    // Panel buffers
    std::deque<std::string> log_buffer;         // Engine logs
    std::deque<std::string> cmd_output_buffer;  // Command results
    std::deque<std::string> message_buffer;     // Chat messages
    std::deque<std::string> telemetry_buffer;   // Telemetry (rendered lines)
    std::vector<PeerInfo> peer_list;            // Discovered peers
    std::set<std::string> connected_peers;      // Set of connected peer IDs

    // Track outstanding admin requests so ACKs can be surfaced nicely.
    // request_id -> short description
    std::unordered_map<std::string, std::string> pending_admin_requests_;
    
    // Display synchronization
    std::mutex display_mutex;
    
    // Layout dimensions (calculated)
    int peers_panel_width;
    int messages_panel_width;
    int peers_panel_height;
    int cmd_output_height;
    int logs_panel_height;
    
    // Row positions
    int header_row;
    int peers_start_row;
    int cmd_output_start_row;
    int logs_start_row;
    int prompt_row;
    
    // Terminal setup/teardown
    void setup_terminal();
    void restore_terminal();
    void update_terminal_size();
    void calculate_layout();

    // Plain (non-TUI) loop
    void run_plain();
    
    // Daemon (headless) loop - no stdin
    void run_daemon();
    
    // Direct TTY output (bypasses stdout/stderr)
    void write_tty(const std::string& s);
    
    // Drawing functions
    void full_redraw();
    void draw_header();
    void draw_peers_panel();
    void draw_messages_panel();
    void draw_cmd_output_panel();
    void draw_logs_panel();
    void draw_prompt();
    void refresh_telemetry_buffer_locked();

    // Telemetry rendering cadence (TUI mode only)
    std::chrono::steady_clock::time_point last_telemetry_draw_{};
    int telemetry_draw_interval_ms_{1000};
    
    // Buffer management
    void add_log(const std::string& msg);
    void add_cmd_output(const std::string& msg);
    void add_message(const std::string& msg);
    void update_peer_list();
    
    // Input handling
    void handle_keypress(char c);
    
    // Filtering
    bool should_show_log(const std::string& level);
    std::string get_log_level_name(CLILogLevel level);
    
    // Command processing
    void process_command(const std::string& input);
    
    // Command handlers
    void cmd_help();
    void cmd_quit();
    void cmd_list_peers();
    void cmd_connect(const std::string& peer_id);
    void cmd_send(const std::string& peer_id, const std::string& message);
    void cmd_broadcast(const std::string& message);
    void cmd_status();
    void cmd_log_filter(const std::string& level);
    void cmd_clear();

    // Proxy controls
    void cmd_proxy(const std::string& subcmd);
    void cmd_admin_proxy(const std::string& target_peer_id, const std::string& role);
};

#endif // TERMINAL_CLI_H
