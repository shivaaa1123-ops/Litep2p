#include "proxy_endpoint.h"
#include "message_types.h"
#include "wire_codec.h"

#include "test_harness.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>

using proxy::json;

// Build a minimal LPX1 TUNNEL frame: magic "LPX1" + kind(2=TUNNEL) + flags +
// flow_id(u32be) + payload.
static std::string make_lpx_tunnel(uint32_t flow_id, uint8_t flags, std::string_view payload) {
    std::string s;
    s.reserve(10 + payload.size());
    s += "LPX1";
    s.push_back(static_cast<char>(2));  // TUNNEL
    s.push_back(static_cast<char>(flags));
    s.push_back(static_cast<char>((flow_id >> 24) & 0xFF));
    s.push_back(static_cast<char>((flow_id >> 16) & 0xFF));
    s.push_back(static_cast<char>((flow_id >> 8) & 0xFF));
    s.push_back(static_cast<char>(flow_id & 0xFF));
    s.append(payload.data(), payload.size());
    return s;
}

// ---------------------------------------------------------------------------
// Section 1: wire codec + proxy payload unit tests (pure logic, no sockets).
// ---------------------------------------------------------------------------
static void test_wire_codec() {
    std::cout << "\n--- wire codec + proxy payload unit tests ---" << std::endl;

    // 1.1 wire::encode_message -> decode_message roundtrip.
    {
        const std::string payload = "hello wire";
        const std::string w = wire::encode_message(MessageType::CONTROL_PING, payload);
        MessageType t = MessageType::CONTROL_PING;
        std::string out;
        CHECK(wire::decode_message(w, t, out), "wire decode roundtrip");
        CHECK(t == MessageType::CONTROL_PING, "wire type preserved");
        CHECK_EQ(out, payload, "wire payload preserved");
    }

    // 1.2 wire::decode_message rejects malformed input.
    {
        MessageType t = MessageType::CONTROL_PING;
        std::string_view out_view;
        CHECK(!wire::decode_message(std::string_view{}, t, out_view), "wire rejects empty input");
        CHECK(!wire::decode_message(std::string_view{"abc"}, t, out_view), "wire rejects short header");

        // Oversized declared length (> kMaxMessageSize).
        std::string oversized(5, '\0');
        oversized[0] = static_cast<char>(MessageType::CONTROL_PING);
        const uint32_t big = wire::kMaxMessageSize + 1;
        oversized[1] = static_cast<char>((big >> 24) & 0xFF);
        oversized[2] = static_cast<char>((big >> 16) & 0xFF);
        oversized[3] = static_cast<char>((big >> 8) & 0xFF);
        oversized[4] = static_cast<char>(big & 0xFF);
        CHECK(!wire::decode_message(oversized, t, out_view), "wire rejects oversized length");

        // Declared length exceeds available bytes.
        std::string truncated(8, '\0');
        truncated[0] = static_cast<char>(MessageType::CONTROL_PING);
        truncated[4] = static_cast<char>(10);  // claims 10-byte payload, only 3 present
        CHECK(!wire::decode_message(truncated, t, out_view), "wire rejects truncated payload");
    }

    // 1.3 proxy stream data encode -> decode roundtrip (legacy framing).
    {
        const std::string w = proxy::encode_proxy_stream_data_wire(123, "hello");
        MessageType t = MessageType::CONTROL_PING;
        std::string payload;
        CHECK(wire::decode_message(w, t, payload), "stream data wire decodes");
        CHECK(t == MessageType::PROXY_STREAM_DATA, "stream data wire type");

        proxy::ProxyStreamDataView view;
        CHECK(proxy::decode_proxy_stream_data_payload(payload, view), "stream data payload decodes");
        CHECK_EQ(view.stream_id, 123u, "stream_id roundtrip");
        CHECK_EQ(std::string(view.data), std::string("hello"), "stream data payload roundtrip");
        CHECK(!view.is_close, "legacy stream data is not close");
    }

    // 1.4 stream_id boundary value (0xFFFFFFFF) roundtrips.
    {
        const std::string w = proxy::encode_proxy_stream_data_wire(0xFFFFFFFFu, "x");
        MessageType t = MessageType::CONTROL_PING;
        std::string payload;
        CHECK(wire::decode_message(w, t, payload), "boundary stream data wire decodes");
        proxy::ProxyStreamDataView view;
        CHECK(proxy::decode_proxy_stream_data_payload(payload, view), "boundary stream data payload decodes");
        CHECK_EQ(view.stream_id, 0xFFFFFFFFu, "boundary stream_id roundtrip");
    }

    // 1.5 proxy control wire encode -> decode roundtrip.
    {
        const json ctrl = proxy::ProxyEndpoint::make_open_stream(7, "TCP", "example.com", 80);
        const std::string w = proxy::encode_proxy_control_wire(ctrl);
        MessageType t = MessageType::CONTROL_PING;
        std::string payload;
        CHECK(wire::decode_message(w, t, payload), "control wire decodes");
        CHECK(t == MessageType::PROXY_CONTROL, "control wire type");

        const json parsed = json::parse(payload);
        CHECK_EQ(parsed["type"].get<std::string>(), std::string("PROXY_OPEN_STREAM"), "control type field");
        CHECK_EQ(parsed["stream_id"].get<uint32_t>(), 7u, "control stream_id field");
    }

    // 1.6 make_open_stream / make_close_stream JSON shape.
    {
        const json os = proxy::ProxyEndpoint::make_open_stream(9, "TCP", "h", 443, {"a", "b"});
        CHECK_EQ(os["type"].get<std::string>(), std::string("PROXY_OPEN_STREAM"), "open_stream type");
        CHECK_EQ(os["stream_id"].get<uint32_t>(), 9u, "open_stream stream_id");
        CHECK_EQ(os["protocol"].get<std::string>(), std::string("TCP"), "open_stream protocol");
        CHECK_EQ(os["port"].get<int>(), 443, "open_stream port");
        CHECK(os["route"].is_array() && os["route"].size() == 2, "open_stream route array");

        const json cs = proxy::ProxyEndpoint::make_close_stream(9, "done");
        CHECK_EQ(cs["type"].get<std::string>(), std::string("PROXY_CLOSE_STREAM"), "close_stream type");
        CHECK_EQ(cs["reason"].get<std::string>(), std::string("done"), "close_stream reason");
    }

    // 1.7 LPX1 TUNNEL framing decode (dumb-proxy mode).
    {
        const std::string lpx = make_lpx_tunnel(0x12345678u, 0, "lpx-data");
        proxy::ProxyStreamDataView view;
        CHECK(proxy::decode_proxy_stream_data_payload(lpx, view), "LPX1 tunnel decodes");
        CHECK_EQ(view.stream_id, 0x12345678u, "LPX1 flow_id exposed as stream_id");
        CHECK(!view.is_close, "LPX1 no-close flag");
        CHECK_EQ(std::string(view.data), std::string("lpx-data"), "LPX1 payload");
    }

    // 1.8 LPX1 close flag.
    {
        const std::string lpx = make_lpx_tunnel(42u, 0x01, "bye");
        proxy::ProxyStreamDataView view;
        CHECK(proxy::decode_proxy_stream_data_payload(lpx, view), "LPX1 close frame decodes");
        CHECK(view.is_close, "LPX1 close flag set");
    }

    // 1.9 Malformed proxy payload is rejected.
    {
        proxy::ProxyStreamDataView view;
        CHECK(!proxy::decode_proxy_stream_data_payload(std::string_view{}, view), "empty payload rejected");
        CHECK(!proxy::decode_proxy_stream_data_payload(std::string_view{"abc"}, view), "short payload rejected");
    }
}

// ---------------------------------------------------------------------------
// Section 2: ProxyEndpoint routing integration tests (in-memory router).
// ---------------------------------------------------------------------------
namespace {

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
        if (to == "peer_client") dst = client;
        else if (to == "peer_gateway") dst = gateway;
        else if (to == "peer_final") dst = final;
        if (!dst) return;

        MessageType t;
        std::string payload;
        if (!wire::decode_message(wire_msg, t, payload)) return;
        if (t == MessageType::PROXY_CONTROL) dst->on_control(from, payload);
        else if (t == MessageType::PROXY_STREAM_DATA) dst->on_stream_data(from, payload);
    }
};

}  // namespace

static void test_proxy_routing() {
    std::cout << "\n--- ProxyEndpoint routing integration tests ---" << std::endl;

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

    // 2.1 Client establishes routing state to final (dumb-proxy mode): the
    //     gateway must forward to final and must NOT emit proxy-level control
    //     back to the client.
    {
        router.clear_frames();
        client.client_open_stream("peer_gateway", 123, "TCP", "", 0, std::vector<std::string>{"peer_final"});
        const auto frames = router.snapshot_frames();
        CHECK(!frames.empty(), "OPEN_STREAM produced frames");

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
                if (proxy::decode_proxy_stream_data_payload(payload, view) && view.stream_id == 123u) {
                    saw_forward = true;
                }
            }
        }
        CHECK(saw_forward, "gateway forwarded initial flow frame to final");
        CHECK(!saw_unwanted_control, "gateway emitted no proxy-level control back to client (dumb proxy)");
    }

    // 2.2 Client STREAM_DATA -> gateway forwards -> final echoes -> back to client.
    {
        router.clear_frames();
        const std::string data = "hello-over-proxy";
        client.client_send_stream_data("peer_gateway", 123, data);
        const auto frames = router.snapshot_frames();
        CHECK(!frames.empty(), "STREAM_DATA produced frames");

        const SentFrame& f = frames.back();
        CHECK_EQ(f.from, std::string("peer_gateway"), "echo forwarded from peer_gateway");
        CHECK_EQ(f.to, std::string("peer_client"), "echo forwarded to peer_client");

        MessageType t;
        std::string payload;
        CHECK(wire::decode_message(f.wire, t, payload), "echo wire decodes");
        CHECK(t == MessageType::PROXY_STREAM_DATA, "echo is PROXY_STREAM_DATA");

        proxy::ProxyStreamDataView view;
        CHECK(proxy::decode_proxy_stream_data_payload(payload, view), "echo payload decodes");
        CHECK_EQ(view.stream_id, 123u, "echo stream_id matches");
        CHECK_EQ(std::string(view.data), data, "echo payload matches");
    }

    // 2.3 CLOSE_STREAM then more data must not reach the client.
    {
        router.clear_frames();
        client.client_close_stream("peer_gateway", 123, "done");
        const auto frames_after_close = router.snapshot_frames().size();
        client.client_send_stream_data("peer_gateway", 123, "should-not-echo");

        const auto frames = router.snapshot_frames();
        bool saw_echo = false;
        for (size_t i = frames_after_close; i < frames.size(); ++i) {
            MessageType t;
            std::string payload;
            if (!wire::decode_message(frames[i].wire, t, payload)) continue;
            if (frames[i].from == "peer_gateway" && frames[i].to == "peer_client" &&
                t == MessageType::PROXY_STREAM_DATA) {
                saw_echo = true;
                break;
            }
        }
        CHECK(!saw_echo, "no echo after CLOSE_STREAM");
    }

    // 2.4 UDP exit-node: client->gateway sends a UDP datagram to a local UDP
    //     echo server and receives the echo back.
    {
        std::atomic<bool> stop{false};
        const int server_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        CHECK(server_fd >= 0, "UDP echo server socket created");
        if (server_fd < 0) return;

        sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        CHECK(::bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0, "UDP echo server bound");

        socklen_t alen = sizeof(addr);
        CHECK(::getsockname(server_fd, reinterpret_cast<sockaddr*>(&addr), &alen) == 0, "UDP echo server getsockname");
        const int server_port = ntohs(addr.sin_port);

        std::thread server_thr([&]() {
            std::string buf;
            buf.resize(64 * 1024);
            while (!stop.load()) {
                struct pollfd pfd;
                pfd.fd = server_fd;
                pfd.events = POLLIN;
                pfd.revents = 0;
                if (::poll(&pfd, 1, 10) != 1 || !(pfd.revents & POLLIN)) continue;
                sockaddr_in src;
                socklen_t slen = sizeof(src);
                const ssize_t n = ::recvfrom(server_fd, buf.data(), buf.size(), 0,
                                              reinterpret_cast<sockaddr*>(&src), &slen);
                if (n <= 0) continue;
                (void)::sendto(server_fd, buf.data(), static_cast<size_t>(n), 0,
                               reinterpret_cast<sockaddr*>(&src), slen);
            }
        });

        std::mutex cb_mu;
        std::condition_variable cb_cv;
        bool got = false;
        std::string got_data;

        client.set_stream_data_callback([&](const std::string& from, uint32_t stream_id,
                                            std::string_view data_view, bool is_close) {
            (void)is_close;
            if (from != "peer_gateway" || stream_id != 555u) return;
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
            CHECK(cb_cv.wait_for(lk, std::chrono::seconds(2), [&] { return got; }),
                  "UDP_EXIT produced a response");
        }
        CHECK_EQ(got_data, std::string("hello-udp"), "UDP_EXIT payload matches");

        client.client_close_stream("peer_gateway", 555, "done");

        stop.store(true);
        ::close(server_fd);
        if (server_thr.joinable()) server_thr.join();
    }
}

int main() {
#if !ENABLE_PROXY_MODULE
    std::cout << "proxy_test skipped (ENABLE_PROXY_MODULE=0)" << std::endl;
    return 0;
#else
    test_wire_codec();
    test_proxy_routing();
    return suite_exit("proxy");
#endif
}
