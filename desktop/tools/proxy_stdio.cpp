#include "proxy_endpoint.h"

#include "wire_codec.h"

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

std::string trim(std::string s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || std::isspace(static_cast<unsigned char>(s.back())))) {
        s.pop_back();
    }
    size_t i = 0;
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) {
        ++i;
    }
    if (i > 0) {
        s.erase(0, i);
    }
    return s;
}

std::vector<std::string> split_ws(const std::string& line) {
    std::istringstream iss(line);
    std::vector<std::string> out;
    std::string tok;
    while (iss >> tok) {
        out.push_back(tok);
    }
    return out;
}

int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

std::string hex_encode(std::string_view bytes) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (unsigned char b : bytes) {
        out.push_back(kHex[(b >> 4) & 0xF]);
        out.push_back(kHex[b & 0xF]);
    }
    return out;
}

std::optional<std::string> hex_decode(std::string_view hex) {
    if ((hex.size() % 2) != 0) return std::nullopt;
    std::string out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        const int hi = hex_val(hex[i]);
        const int lo = hex_val(hex[i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out.push_back(static_cast<char>((hi << 4) | lo));
    }
    return out;
}

void print_usage(const char* argv0) {
    std::cerr
        << "Usage: " << argv0 << " --role gateway|client [--self PEER_ID] [--gateway 0|1] [--client 0|1] [--echo 0|1]" << std::endl
        << "\n"
        << "Line protocol (stdin):" << std::endl
        << "  IN  <from_peer_id> <wire_hex>" << std::endl
        << "  CMD HELLO <gateway_peer_id> [version]   # deprecated/no-op in dumb-proxy mode" << std::endl
        << "  CMD OPEN_STREAM_ROUTE <gateway_peer_id> <stream_id> <target_peer_id>" << std::endl
        << "  CMD OPEN_STREAM <gateway_peer_id> <stream_id> <protocol> <host> <port>" << std::endl
        << "  CMD STREAM_DATA <gateway_peer_id> <stream_id> <data_hex>" << std::endl
        << "  CMD CLOSE_STREAM <gateway_peer_id> <stream_id> <reason...>" << std::endl
        << "  QUIT" << std::endl
        << "\n"
        << "Output (stdout):" << std::endl
        << "  OUT <to_peer_id> <wire_hex>" << std::endl
        << "\n"
        << "Diagnostics (stdout):" << std::endl
        << "  RECV_STREAM from=<peer> stream_id=<id> close=<0|1> len=<n> data_hex=<...>" << std::endl;
}

} // namespace

int main(int argc, char** argv) {
#if !ENABLE_PROXY_MODULE
    std::cerr << "proxy_stdio unavailable (ENABLE_PROXY_MODULE=0)" << std::endl;
    return 2;
#else
    std::string role;
    std::string self = "peer";
    std::optional<int> gateway_opt;
    std::optional<int> client_opt;
    std::optional<int> echo_opt;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--role" && i + 1 < argc) {
            role = argv[++i];
        } else if (a == "--self" && i + 1 < argc) {
            self = argv[++i];
        } else if (a == "--gateway" && i + 1 < argc) {
            gateway_opt = std::atoi(argv[++i]);
        } else if (a == "--client" && i + 1 < argc) {
            client_opt = std::atoi(argv[++i]);
        } else if (a == "--echo" && i + 1 < argc) {
            echo_opt = std::atoi(argv[++i]);
        } else if (a == "-h" || a == "--help") {
            print_usage(argv[0]);
            return 0;
        } else {
            std::cerr << "Unknown arg: " << a << std::endl;
            print_usage(argv[0]);
            return 2;
        }
    }

    if (role != "gateway" && role != "client") {
        std::cerr << "--role must be gateway|client" << std::endl;
        print_usage(argv[0]);
        return 2;
    }

    proxy::ProxySettings settings;
    if (role == "gateway") {
        settings.enable_gateway = true;
        settings.enable_client = false;
    } else {
        settings.enable_gateway = false;
        settings.enable_client = true;
    }

    if (gateway_opt.has_value()) settings.enable_gateway = (*gateway_opt != 0);
    if (client_opt.has_value()) settings.enable_client = (*client_opt != 0);

    const bool echo_stream = echo_opt.has_value() ? ((*echo_opt != 0)) : false;

    auto emit_out = [&](const std::string& peer_id, const std::string& wire_msg) {
        std::cout << "OUT " << peer_id << " " << hex_encode(wire_msg) << std::endl;
        std::cout.flush();
    };

    auto encode_lpx1_tunnel = [&](uint32_t flow_id, std::string_view data, uint8_t flags) -> std::string {
        auto put_u32_be = [](std::string& out, uint32_t v) {
            out.push_back(static_cast<char>((v >> 24) & 0xFF));
            out.push_back(static_cast<char>((v >> 16) & 0xFF));
            out.push_back(static_cast<char>((v >> 8) & 0xFF));
            out.push_back(static_cast<char>(v & 0xFF));
        };

        std::string payload;
        payload.reserve(4 + 1 + 1 + 4 + data.size());
        payload.append("LPX1", 4);
        payload.push_back(static_cast<char>(2));
        payload.push_back(static_cast<char>(flags));
        put_u32_be(payload, flow_id);
        payload.append(data.data(), data.size());
        return payload;
    };

    proxy::ProxyEndpoint ep([&](const std::string& peer_id, const std::string& wire_msg) {
        emit_out(peer_id, wire_msg);
    });
    ep.configure(settings);

    ep.set_stream_data_callback([&](const std::string& from_peer_id, uint32_t stream_id, std::string_view data, bool is_close) {
        std::cout << "RECV_STREAM from=" << from_peer_id
                  << " stream_id=" << stream_id
                  << " close=" << (is_close ? 1 : 0)
                  << " len=" << data.size()
                  << " data_hex=" << hex_encode(data)
                  << std::endl;
        std::cout.flush();

        if (echo_stream && !is_close) {
            const std::string lpx = encode_lpx1_tunnel(stream_id, data, 0);
            emit_out(from_peer_id, wire::encode_message(MessageType::PROXY_STREAM_DATA, lpx));
        }
    });

    std::string line;
    while (std::getline(std::cin, line)) {
        line = trim(line);
        if (line.empty()) continue;
        if (line.size() >= 1 && line[0] == '#') continue;

        // We sometimes need to preserve spaces (reason...), so we only do token splitting
        // for the leading fields and treat the remainder specially.
        auto toks = split_ws(line);
        if (toks.empty()) continue;

        if (toks[0] == "QUIT") {
            return 0;
        }

        if (toks[0] == "IN") {
            if (toks.size() != 3) {
                std::cerr << "ERR IN expects 2 args" << std::endl;
                return 2;
            }
            const std::string& from_peer = toks[1];
            const std::string& wire_hex = toks[2];
            auto wire = hex_decode(wire_hex);
            if (!wire.has_value()) {
                std::cerr << "ERR invalid hex" << std::endl;
                return 2;
            }

            MessageType t;
            std::string_view payload;
            if (!wire::decode_message(*wire, t, payload)) {
                std::cerr << "ERR wire decode failed" << std::endl;
                return 2;
            }

            if (t == MessageType::PROXY_CONTROL) {
                ep.on_control(from_peer, payload);
            } else if (t == MessageType::PROXY_STREAM_DATA) {
                ep.on_stream_data(from_peer, payload);
            } else {
                // Ignore unknown types.
            }
            continue;
        }

        if (toks[0] == "CMD") {
            if (!settings.enable_client) {
                std::cerr << "ERR CMD not allowed (client disabled)" << std::endl;
                return 2;
            }
            if (toks.size() < 2) {
                std::cerr << "ERR CMD missing subcommand" << std::endl;
                return 2;
            }
            const std::string& sub = toks[1];
            if (sub == "HELLO") {
                if (toks.size() < 3 || toks.size() > 4) {
                    std::cerr << "ERR CMD HELLO usage: CMD HELLO <gateway_peer_id> [version]" << std::endl;
                    return 2;
                }
                const std::string& gw = toks[2];
                const int version = (toks.size() == 4) ? std::atoi(toks[3].c_str()) : 1;
                std::cerr << "WARN: CMD HELLO is deprecated/no-op in dumb-proxy mode\n";
                ep.client_send_hello(gw, version);
                continue;
            }
            if (sub == "OPEN_STREAM_ROUTE") {
                if (toks.size() != 5) {
                    std::cerr << "ERR CMD OPEN_STREAM_ROUTE usage: CMD OPEN_STREAM_ROUTE <gateway> <stream_id> <target_peer_id>" << std::endl;
                    return 2;
                }
                const std::string& gw = toks[2];
                const uint32_t stream_id = static_cast<uint32_t>(std::strtoul(toks[3].c_str(), nullptr, 10));
                const std::string& target = toks[4];
                ep.client_open_stream(gw, stream_id, "TCP", "", 0, std::vector<std::string>{target});
                continue;
            }
            if (sub == "OPEN_STREAM") {
                if (toks.size() != 7) {
                    std::cerr << "ERR CMD OPEN_STREAM usage: CMD OPEN_STREAM <gateway> <stream_id> <protocol> <host> <port>" << std::endl;
                    return 2;
                }
                const std::string& gw = toks[2];
                const uint32_t stream_id = static_cast<uint32_t>(std::strtoul(toks[3].c_str(), nullptr, 10));
                const std::string& protocol = toks[4];
                const std::string& host = toks[5];
                const int port = std::atoi(toks[6].c_str());
                ep.client_open_stream(gw, stream_id, protocol, host, port);
                continue;
            }
            if (sub == "STREAM_DATA") {
                if (toks.size() != 5) {
                    std::cerr << "ERR CMD STREAM_DATA usage: CMD STREAM_DATA <gateway> <stream_id> <data_hex>" << std::endl;
                    return 2;
                }
                const std::string& gw = toks[2];
                const uint32_t stream_id = static_cast<uint32_t>(std::strtoul(toks[3].c_str(), nullptr, 10));
                auto data = hex_decode(toks[4]);
                if (!data.has_value()) {
                    std::cerr << "ERR invalid data_hex" << std::endl;
                    return 2;
                }
                ep.client_send_stream_data(gw, stream_id, *data);
                continue;
            }
            if (sub == "CLOSE_STREAM") {
                if (toks.size() < 5) {
                    std::cerr << "ERR CMD CLOSE_STREAM usage: CMD CLOSE_STREAM <gateway> <stream_id> <reason...>" << std::endl;
                    return 2;
                }
                const std::string& gw = toks[2];
                const uint32_t stream_id = static_cast<uint32_t>(std::strtoul(toks[3].c_str(), nullptr, 10));

                // Extract the reason as the substring after the first 4 tokens.
                // We can't reconstruct perfectly from split_ws() if there were extra spaces,
                // but that's fine for tests.
                size_t pos = line.find("CLOSE_STREAM");
                if (pos == std::string::npos) {
                    std::cerr << "ERR parsing reason" << std::endl;
                    return 2;
                }
                // Skip: "CMD CLOSE_STREAM <gw> <stream_id> "
                // Find the start of reason by scanning 4 whitespace-separated tokens.
                int seen = 0;
                size_t idx = 0;
                while (idx < line.size() && seen < 4) {
                    while (idx < line.size() && std::isspace(static_cast<unsigned char>(line[idx]))) ++idx;
                    while (idx < line.size() && !std::isspace(static_cast<unsigned char>(line[idx]))) ++idx;
                    ++seen;
                }
                while (idx < line.size() && std::isspace(static_cast<unsigned char>(line[idx]))) ++idx;
                const std::string reason = (idx < line.size()) ? line.substr(idx) : std::string();

                ep.client_close_stream(gw, stream_id, reason);
                continue;
            }

            std::cerr << "ERR unknown CMD subcommand: " << sub << std::endl;
            return 2;
        }

        std::cerr << "ERR unknown line" << std::endl;
        return 2;
    }

    // EOF
    return 0;
#endif
}
