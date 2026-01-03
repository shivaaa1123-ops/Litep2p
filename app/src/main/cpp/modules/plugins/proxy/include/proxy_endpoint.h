#pragma once

#include "message_types.h"
#include "wire_codec.h"

#include <nlohmann/json.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
#include <unordered_map>

namespace proxy {

using json = nlohmann::json;

// Control plane message "type" values inside the JSON payload.
// NOTE: Legacy types kept for backward compatibility with older tooling.
// The current target behavior is a *dumb proxy*: it must not emit proxy-level
// ACCEPT/REJECT responses.
inline constexpr const char* kProxyHello      = "PROXY_HELLO";
inline constexpr const char* kProxyAccept     = "PROXY_ACCEPT";
inline constexpr const char* kProxyOpenStream = "PROXY_OPEN_STREAM";
inline constexpr const char* kProxyCloseStream = "PROXY_CLOSE_STREAM";

struct ProxySettings {
    bool enable_gateway{false};
    bool enable_client{false};
    // Test harness only: enable deterministic echo behavior for tools like proxy_netbench.
    // Must remain false for real dumb-proxy deployments.
    bool enable_test_echo{false};
};

struct ProxyStreamDataView {
    uint32_t stream_id{0};
    bool is_close{false};
    std::string_view data;
};

// Encodes a proxy control JSON object into a wire message of type MessageType::PROXY_CONTROL.
std::string encode_proxy_control_wire(const json& control);

// Encodes proxy stream data into a wire message of type MessageType::PROXY_STREAM_DATA.
// Legacy payload format: [stream_id: uint32 big-endian][data bytes...]
std::string encode_proxy_stream_data_wire(uint32_t stream_id, std::string_view data);

// Decodes the payload of a MessageType::PROXY_STREAM_DATA frame.
// Supports both:
//  - Legacy framing: [stream_id:u32][data...]
//  - LPX1 framing (dumb-proxy mode): returns flow_id as stream_id and exposes only the opaque payload bytes.
bool decode_proxy_stream_data_payload(std::string_view payload, ProxyStreamDataView& out);

// A lightweight endpoint that can act as a proxy gateway and/or proxy client.
//
// Target behavior (see PROXY_TEST.md): the gateway is a *dumb forwarder*.
// It maintains minimal routing state and forwards bytes as-is. In particular:
//   - No proxy-level HELLO/ACCEPT handshakes
//   - No proxy-level OPEN_STREAM/ACCEPT or error replies
//
// OPEN_STREAM is treated as an optional one-way hint to establish/refresh routing state.
// STREAM_DATA carries opaque bytes; for tests/tools, the final hop may echo them.
class ProxyEndpoint {
public:
    using SendFn = std::function<void(const std::string& peer_id, const std::string& wire_message)>;
    using ControlCallback = std::function<void(const std::string& from_peer_id, const json& msg)>;
    using StreamDataCallback = std::function<void(const std::string& from_peer_id, uint32_t stream_id, std::string_view data, bool is_close)>;
    // Callback to request connection to a peer (for exit-node proxy model).
    // The gateway calls this when it needs to connect to a downstream peer.
    using ConnectFn = std::function<void(const std::string& peer_id)>;

    explicit ProxyEndpoint(SendFn send_fn);
    ~ProxyEndpoint();
    
    // Set optional connect callback for exit-node proxy model.
    // When the gateway receives OPEN_STREAM with a route, it will call this to connect to the downstream peer.
    void set_connect_callback(ConnectFn connect_fn);

    void configure(ProxySettings settings);
    ProxySettings settings() const;

    // Incoming frames (payloads are the decoded wire payloads).
    void on_control(const std::string& from_peer_id, std::string_view payload);
    void on_stream_data(const std::string& from_peer_id, std::string_view payload);

    // Optional: called when a PROXY_STREAM_DATA frame is received for a stream not tracked locally.
    // This is primarily useful for client-side consumers that want to observe echoed / proxied bytes.
    void set_stream_data_callback(StreamDataCallback cb);

    // Optional: observe decoded control plane JSON messages (including PROXY_ACCEPT errors).
    void set_control_callback(ControlCallback cb);

    // Client-side helpers (send to gateway). These methods are no-ops unless enable_client=true.
    void client_send_hello(const std::string& gateway_peer_id, int version = 1);
    void client_open_stream(const std::string& gateway_peer_id, uint32_t stream_id,
                            std::string_view protocol, std::string_view host, int port);
    void client_open_stream(const std::string& gateway_peer_id, uint32_t stream_id,
                            std::string_view protocol, std::string_view host, int port,
                            const std::vector<std::string>& route);
    void client_send_stream_data(const std::string& gateway_peer_id, uint32_t stream_id, std::string_view data);
    void client_close_stream(const std::string& gateway_peer_id, uint32_t stream_id, std::string_view reason);

    // Convenience builders for outgoing control frames.
    static json make_hello(std::string_view role, int version = 1);
    // If route is non-empty, the gateway will forward the stream to the next peer(s) in the route.
    // The final hop (route empty) performs the requested protocol action (e.g., TCP connect to host:port).
    static json make_open_stream(uint32_t stream_id, std::string_view protocol,
                                 std::string_view host, int port,
                                 const std::vector<std::string>& route = {});
    static json make_close_stream(uint32_t stream_id, std::string_view reason);

private:
    struct StreamKey {
        std::string peer_id;
        uint32_t stream_id{0};

        bool operator==(const StreamKey& o) const {
            return peer_id == o.peer_id && stream_id == o.stream_id;
        }
    };

    struct StreamKeyHash {
        std::size_t operator()(const StreamKey& k) const noexcept {
            return std::hash<std::string>{}(k.peer_id)
                   ^ (static_cast<std::size_t>(k.stream_id) * 0x9e3779b97f4a7c15ULL);
        }
    };

    struct Stream {
        // Upstream (the peer that opened this stream on us).
        std::string upstream_peer_id;
        uint32_t upstream_stream_id{0};

        // Downstream (optional): if this is a hop in a chain, we open another stream to downstream_peer_id.
        std::string downstream_peer_id;
        uint32_t downstream_stream_id{0};
        bool downstream_open{false};

        // Exit (optional): TCP socket for final hop.
        int tcp_fd{-1};
        // Exit (optional): UDP socket for final hop.
        int udp_fd{-1};

        std::string dest_host;
        int dest_port{0};
        std::string protocol;
        std::vector<std::string> route;

        // Lifecycle
        bool open{false};
        bool is_chain_hop{false};
        bool is_tcp_exit{false};
        bool is_udp_exit{false};
        bool use_lpx{false};

        // TCP I/O (used when is_tcp_exit=true)
        std::mutex out_mu;
        std::deque<std::string> out_q;
        std::atomic<bool> stop{false};
        std::thread io_thread;
    };

    void handle_open_stream_(const std::string& from_peer_id, const json& msg);
    void handle_close_stream_(const std::string& from_peer_id, const json& msg);

    void close_stream_(Stream& s, std::string_view reason);

    void send_control_(const std::string& peer_id, const json& control);
    void send_stream_data_(const std::string& peer_id, uint32_t stream_id, std::string_view data);

    struct ClientDest {
        enum class Kind : uint8_t { NONE = 0, PEER = 1, INET = 2 };
        Kind kind{Kind::NONE};
        std::string peer_id;
        std::string host;
        int port{0};
        std::string proto; // e.g. "TCP"
    };

    // Client-side: remember where a local flow should be encapsulated to.
    std::unordered_map<uint32_t, ClientDest> m_client_dests;

    SendFn m_send;
    ConnectFn m_connect;  // Optional: for exit-node proxy to connect to downstream peers
    ProxySettings m_settings{};

    // Keyed by (peer_id, stream_id) to avoid collisions between different peers.
    std::unordered_map<StreamKey, std::unique_ptr<Stream>, StreamKeyHash> m_streams;

    // For downstream accepts: (from_peer_id, downstream_stream_id) -> upstream StreamKey
    std::unordered_map<StreamKey, StreamKey, StreamKeyHash> m_downstream_to_upstream;

    StreamDataCallback m_stream_data_cb;
    ControlCallback m_control_cb;

    uint32_t m_next_local_stream_id{1000};
};

} // namespace proxy
