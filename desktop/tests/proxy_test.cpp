#include "proxy_endpoint.h"

#include <cassert>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>
#include <exception>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

using proxy::json;

namespace {
int fail(const std::string& msg) {
    std::cerr << "proxy_test FAIL: " << msg << std::endl;
    return 1;
}

template <typename T>
bool decode_wire_checked(const T& wire_msg, MessageType& t, std::string& payload, const std::string& ctx) {
    if (!wire::decode_message(wire_msg, t, payload)) {
        std::cerr << "proxy_test FAIL: wire decode failed (" << ctx << ")" << std::endl;
        return false;
    }
    return true;
}

bool parse_json_checked(const std::string& s, json& out, const std::string& ctx) {
    try {
        out = json::parse(s);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "proxy_test FAIL: JSON parse failed (" << ctx << "): " << e.what() << std::endl;
        return false;
    }
}

struct SentFrame {
    std::string from;
    std::string to;
    std::string wire;
};

struct Router {
    std::mutex mu;
    std::vector<SentFrame> frames;
    proxy::ProxyEndpoint* client = nullptr;
    proxy::ProxyEndpoint* gateway = nullptr;
    proxy::ProxyEndpoint* final = nullptr;

    void clear_frames() {
        std::lock_guard<std::mutex> lk(mu);
        frames.clear();
    }

    std::vector<SentFrame> snapshot_frames() {
        std::lock_guard<std::mutex> lk(mu);
        return frames;
    }

    void send(const std::string& from, const std::string& to, const std::string& wire_msg) {
        {
            std::lock_guard<std::mutex> lk(mu);
            frames.push_back(SentFrame{from, to, wire_msg});
        }

        proxy::ProxyEndpoint* dst = nullptr;
        if (to == "peer_client") {
            dst = client;
        } else if (to == "peer_gateway") {
            dst = gateway;
        } else if (to == "peer_final") {
            dst = final;
        }
        if (!dst) {
            return;
        }

        MessageType t;
        std::string payload;
        if (!wire::decode_message(wire_msg, t, payload)) {
            return;
        }
        if (t == MessageType::PROXY_CONTROL) {
            dst->on_control(from, payload);
        } else if (t == MessageType::PROXY_STREAM_DATA) {
            dst->on_stream_data(from, payload);
        }
    }
};
}

int main() {
#if !ENABLE_PROXY_MODULE
    std::cout << "proxy_test skipped (ENABLE_PROXY_MODULE=0)" << std::endl;
    return 0;
#else

    Router router;

    proxy::ProxyEndpoint client([&router](const std::string& peer_id, const std::string& wire_msg) {
        router.send("peer_client", peer_id, wire_msg);
    });
    proxy::ProxyEndpoint gateway([&router](const std::string& peer_id, const std::string& wire_msg) {
        router.send("peer_gateway", peer_id, wire_msg);
    });

    proxy::ProxyEndpoint final([&router](const std::string& peer_id, const std::string& wire_msg) {
        router.send("peer_final", peer_id, wire_msg);
    });

    router.client = &client;
    router.gateway = &gateway;
    router.final = &final;

    client.configure(proxy::ProxySettings{.enable_gateway = false, .enable_client = true});
    gateway.configure(proxy::ProxySettings{.enable_gateway = true, .enable_client = false});
    final.configure(proxy::ProxySettings{.enable_gateway = true, .enable_client = false, .enable_test_echo = true});

    // 1) Client establishes routing state to final (dumb-proxy mode).
    router.clear_frames();
    client.client_open_stream("peer_gateway", 123, "TCP", "", 0, std::vector<std::string>{"peer_final"});
    auto frames = router.snapshot_frames();
    if (frames.empty()) return fail("no frames after OPEN_STREAM");

    // Ensure gateway forwarded to final using PROXY_STREAM_DATA (LPX1 tunnel)
    // and did not emit any proxy-level control back to client.
    bool saw_forward = false;
    bool saw_unwanted_control = false;
    for (const auto& f : frames) {
        MessageType t;
        std::string payload;
        if (!wire::decode_message(f.wire, t, payload)) continue;
        if (f.from == "peer_gateway" && f.to == "peer_client" && t == MessageType::PROXY_CONTROL) {
            saw_unwanted_control = true;
        }
        if (f.from == "peer_gateway" && f.to == "peer_final" && t == MessageType::PROXY_STREAM_DATA) {
            proxy::ProxyStreamDataView view;
            if (!proxy::decode_proxy_stream_data_payload(payload, view)) return fail("failed to decode forwarded stream data");
            if (view.stream_id == 123u) {
                saw_forward = true;
            }
        }
    }
    if (!saw_forward) return fail("gateway did not forward initial flow frame to final");
    if (saw_unwanted_control) return fail("gateway emitted proxy-level control back to client (should be dumb)");

    // 2) Client STREAM_DATA -> gateway forwards -> final echoes -> gateway forwards back to client.
    router.clear_frames();
    const std::string data = "hello-over-proxy";
    client.client_send_stream_data("peer_gateway", 123, data);
    frames = router.snapshot_frames();
    if (frames.empty()) return fail("no frames after STREAM_DATA");
    {
        const SentFrame& f = frames.back();
        if (f.from != "peer_gateway") return fail("expected final->gateway->client forward from peer_gateway");
        if (f.to != "peer_client") return fail("expected data forwarded to peer_client");

        MessageType t;
        std::string payload;
        if (!decode_wire_checked(f.wire, t, payload, "STREAM_DATA/echo")) return 1;
        if (t != MessageType::PROXY_STREAM_DATA) return fail("expected PROXY_STREAM_DATA echo");

        proxy::ProxyStreamDataView view;
        if (!proxy::decode_proxy_stream_data_payload(payload, view)) return fail("failed to decode stream data payload");
        if (view.stream_id != 123u) return fail("stream_id mismatch");
        if (std::string(view.data) != data) return fail("echo payload mismatch");
    }

    // 3) Client CLOSE_STREAM then more data should not reach client.
    router.clear_frames();
    client.client_close_stream("peer_gateway", 123, "done");
    frames = router.snapshot_frames();
    const size_t frames_after_close = frames.size();
    client.client_send_stream_data("peer_gateway", 123, "should-not-echo");
    // No new gateway->client PROXY_STREAM_DATA frame should be produced.
    bool saw_echo = false;
    frames = router.snapshot_frames();
    for (size_t i = frames_after_close; i < frames.size(); ++i) {
        MessageType t;
        std::string payload;
        if (!wire::decode_message(frames[i].wire, t, payload)) continue;
        if (frames[i].from == "peer_gateway" && frames[i].to == "peer_client" && t == MessageType::PROXY_STREAM_DATA) {
            saw_echo = true;
            break;
        }
    }
    if (saw_echo) return fail("saw echo after CLOSE_STREAM");

    // 4) UDP exit-node: client->gateway sends a UDP datagram to a local UDP echo server.
    {
        std::atomic<bool> stop{false};
        int server_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (server_fd < 0) return fail("failed to create UDP server socket");

        sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0; // ephemeral
        if (::bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            ::close(server_fd);
            return fail("failed to bind UDP server");
        }

        socklen_t alen = sizeof(addr);
        if (::getsockname(server_fd, reinterpret_cast<sockaddr*>(&addr), &alen) != 0) {
            ::close(server_fd);
            return fail("failed to getsockname UDP server");
        }
        const int server_port = ntohs(addr.sin_port);

        std::thread server_thr([&]() {
            std::string buf;
            buf.resize(64 * 1024);
            while (!stop.load()) {
                struct pollfd pfd;
                pfd.fd = server_fd;
                pfd.events = POLLIN;
                pfd.revents = 0;
                const int rc = ::poll(&pfd, 1, 10);
                if (rc != 1 || !(pfd.revents & POLLIN)) {
                    continue;
                }
                sockaddr_in src;
                socklen_t slen = sizeof(src);
                const ssize_t n = ::recvfrom(server_fd, buf.data(), buf.size(), 0, reinterpret_cast<sockaddr*>(&src), &slen);
                if (n <= 0) {
                    continue;
                }
                (void)::sendto(server_fd, buf.data(), static_cast<size_t>(n), 0, reinterpret_cast<sockaddr*>(&src), slen);
            }
        });

        std::mutex cb_mu;
        std::condition_variable cb_cv;
        bool got = false;
        std::string got_data;

        client.set_stream_data_callback([&](const std::string& from, uint32_t stream_id, std::string_view data_view, bool is_close) {
            (void)is_close;
            if (from != "peer_gateway" || stream_id != 555u) {
                return;
            }
            std::lock_guard<std::mutex> lk(cb_mu);
            got_data.assign(data_view.data(), data_view.size());
            got = true;
            cb_cv.notify_one();
        });

        router.clear_frames();
        client.client_open_stream("peer_gateway", 555, "UDP_EXIT", "127.0.0.1", server_port);
        client.client_send_stream_data("peer_gateway", 555, "hello-udp");

        {
            std::unique_lock<std::mutex> lk(cb_mu);
            if (!cb_cv.wait_for(lk, std::chrono::seconds(2), [&] { return got; })) {
                stop.store(true);
                ::close(server_fd);
                if (server_thr.joinable()) server_thr.join();
                return fail("UDP_EXIT did not produce a response");
            }
        }

        if (got_data != "hello-udp") {
            stop.store(true);
            ::close(server_fd);
            if (server_thr.joinable()) server_thr.join();
            return fail("UDP_EXIT payload mismatch");
        }

        client.client_close_stream("peer_gateway", 555, "done");

        stop.store(true);
        ::close(server_fd);
        if (server_thr.joinable()) server_thr.join();
    }

    std::cout << "proxy_test passed" << std::endl;
    return 0;
#endif
}
