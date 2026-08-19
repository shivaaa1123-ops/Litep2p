#include "voice_call_manager.h"
#include "logger.h"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

static int tests_failed = 0;

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "FAIL: " << msg << " [" << __FILE__ << ":" << __LINE__ << "]" << std::endl; \
            tests_failed++; \
            return false; \
        } \
    } while (0)

/**
 * Pairs two VoiceCallManagers back-to-back: A's outbound payloads are fed into
 * B's handle_incoming_message and vice versa. This exercises the exact wire
 * encoding/decoding and the offer/accept/decline/end state machine hermetic-
 * ally, without a session/transport.
 */
struct CallbackPair {
    VoiceCallManager* a = nullptr;
    VoiceCallManager* b = nullptr;

    // Event snapshots for A (the caller).
    std::string a_state;
    std::string a_detail;
    std::vector<std::string> a_offers;
    std::vector<uint8_t> a_frames;
    std::string a_last_call_id;
    std::vector<std::string> a_outbound;  // raw wire payloads A emitted

    // Event snapshots for B (the callee).
    std::string b_state;
    std::string b_detail;
    std::vector<std::string> b_offers;
    std::vector<uint8_t> b_frames;
    std::string b_last_call_id;

    std::mutex m;
};

static const char* state_label(VoiceCallState s) {
    switch (s) {
        case VoiceCallState::IDLE: return "IDLE";
        case VoiceCallState::OUTGOING: return "OUTGOING";
        case VoiceCallState::RINGING: return "RINGING";
        case VoiceCallState::IN_CALL: return "IN_CALL";
        case VoiceCallState::ENDED: return "ENDED";
    }
    return "?";
}


static void wire_pair(CallbackPair& pair) {
    pair.a->set_outbound_message_callback([&pair](const std::string& peer_id,
                                                  const std::string& payload) {
        {
            std::lock_guard<std::mutex> lk(pair.m);
            pair.a_outbound.push_back(payload);
        }
        // Deliver OUTSIDE the snapshot lock: the receiver's callbacks lock
        // pair.m again (non-recursive), and holding it here would deadlock.
        if (pair.b) pair.b->handle_incoming_message(peer_id, payload);
    });
    pair.b->set_outbound_message_callback([&pair](const std::string& peer_id,
                                                  const std::string& payload) {
        if (pair.a) pair.a->handle_incoming_message(peer_id, payload);
    });

    pair.a->on_call_offered([&pair](const std::string& call_id, const std::string& peer_id,
                                    const std::string& codec, uint16_t sample_rate,
                                    uint8_t channels, uint8_t frame_ms) {
        std::lock_guard<std::mutex> lk(pair.m);
        pair.a_offers.push_back(call_id + "|" + peer_id + "|" + codec +
                                "|" + std::to_string(sample_rate) +
                                "|" + std::to_string(channels) +
                                "|" + std::to_string(frame_ms));
    });
    pair.a->on_call_state([&pair](const std::string& call_id, const std::string& peer_id,
                                  VoiceCallState state, const std::string& detail) {
        std::lock_guard<std::mutex> lk(pair.m);
        pair.a_state = state_label(state);
        pair.a_detail = detail;
        pair.a_last_call_id = call_id;
    });
    pair.a->on_frame_received([&pair](const std::string& call_id, const std::string& peer_id,
                                      const uint8_t* data, size_t len) {
        std::lock_guard<std::mutex> lk(pair.m);
        pair.a_last_call_id = call_id;
        pair.a_frames.insert(pair.a_frames.end(), data, data + len);
    });

    pair.b->on_call_offered([&pair](const std::string& call_id, const std::string& peer_id,
                                    const std::string& codec, uint16_t sample_rate,
                                    uint8_t channels, uint8_t frame_ms) {
        std::lock_guard<std::mutex> lk(pair.m);
        pair.b_offers.push_back(call_id + "|" + peer_id + "|" + codec +
                                "|" + std::to_string(sample_rate) +
                                "|" + std::to_string(channels) +
                                "|" + std::to_string(frame_ms));
    });
    pair.b->on_call_state([&pair](const std::string& call_id, const std::string& peer_id,
                                  VoiceCallState state, const std::string& detail) {
        std::lock_guard<std::mutex> lk(pair.m);
        pair.b_state = state_label(state);
        pair.b_detail = detail;
        pair.b_last_call_id = call_id;
    });
    pair.b->on_frame_received([&pair](const std::string& call_id, const std::string& peer_id,
                                      const uint8_t* data, size_t len) {
        std::lock_guard<std::mutex> lk(pair.m);
        pair.b_last_call_id = call_id;
        pair.b_frames.insert(pair.b_frames.end(), data, data + len);
    });
}

static bool test_offer_accept_frame_flow() {
    VoiceCallManager::CallConfig cfg;
    cfg.ring_timeout_ms = 5000;
    VoiceCallManager a(cfg), b(cfg);
    CallbackPair pair;
    pair.a = &a;
    pair.b = &b;
    wire_pair(pair);

    // A offers a call to B.
    const std::string call_id = a.start_call("peer-b", "PCM_S16LE", 16000, 1, 20);
    TEST_ASSERT(!call_id.empty(), "start_call returned empty call id");
    TEST_ASSERT(a.get_call_state(call_id) == VoiceCallState::OUTGOING,
                "caller should be OUTGOING after offer");

    // Loopback delivery is synchronous, so snapshots are populated immediately.
    {
        std::lock_guard<std::mutex> lk(pair.m);
        TEST_ASSERT(pair.b_offers.size() == 1, "B should have received one offer");
        const std::string& offer = pair.b_offers[0];
        TEST_ASSERT(offer.find("PCM_S16LE") != std::string::npos, "offer should carry codec");
        TEST_ASSERT(offer.find("16000|1|20") != std::string::npos, "offer should carry profile");
    }
    // Incoming calls surface via the offered callback; the engine's local state
    // flips to RINGING (queryable, not a state callback).
    TEST_ASSERT(b.get_call_state(call_id) == VoiceCallState::RINGING,
                "callee should be RINGING");

    // B accepts -> both go IN_CALL.
    TEST_ASSERT(b.accept_call(call_id), "accept_call should succeed");
    TEST_ASSERT(a.get_call_state(call_id) == VoiceCallState::IN_CALL,
                "caller should be IN_CALL after accept");
    TEST_ASSERT(b.get_call_state(call_id) == VoiceCallState::IN_CALL,
                "callee should be IN_CALL after accept");
    {
        std::lock_guard<std::mutex> lk(pair.m);
        TEST_ASSERT(pair.a_state == "IN_CALL", "caller state callback should be IN_CALL");
        TEST_ASSERT(pair.b_state == "IN_CALL", "callee state callback should be IN_CALL");
    }

    // B sends audio frames -> A receives exact bytes.
    std::vector<uint8_t> audio(640, 0xAB);
    for (int i = 0; i < 10; i++) {
        audio[i] = static_cast<uint8_t>(i);
    }
    TEST_ASSERT(b.send_frame(call_id, audio.data(), audio.size()), "send_frame should succeed");
    TEST_ASSERT(b.send_frame(call_id, audio.data(), audio.size()), "second frame should succeed");
    {
        std::lock_guard<std::mutex> lk(pair.m);
        TEST_ASSERT(pair.a_frames.size() == audio.size() * 2,
                    "caller should receive both audio frames");
        TEST_ASSERT(std::memcmp(pair.a_frames.data(), audio.data(), audio.size()) == 0,
                    "frame bytes should arrive intact");
    }

    // Sending frames on a non-active call id is refused.
    TEST_ASSERT(!b.send_frame("no-such-call", audio.data(), audio.size()),
                "send_frame on unknown call should fail");

    // A hangs up -> B ends.
    TEST_ASSERT(a.end_call(call_id), "end_call should succeed");
    TEST_ASSERT(a.get_call_state(call_id) == VoiceCallState::IDLE, "caller call should be gone");
    {
        std::lock_guard<std::mutex> lk(pair.m);
        TEST_ASSERT(pair.b_state == "ENDED", "callee should see ENDED");
        TEST_ASSERT(pair.b_detail.find("ended") != std::string::npos,
                    "callee detail should say ended");
    }
    return true;
}


static bool test_decline_flow() {
    VoiceCallManager a, b;
    CallbackPair pair;
    pair.a = &a;
    pair.b = &b;
    wire_pair(pair);

    const std::string call_id = a.start_call("peer-b", "PCM_S16LE", 16000, 1, 20);
    TEST_ASSERT(!call_id.empty(), "start_call failed");

    TEST_ASSERT(b.decline_call(call_id), "decline_call should succeed");
    TEST_ASSERT(a.get_call_state(call_id) == VoiceCallState::IDLE, "caller call should be gone");
    {
        std::lock_guard<std::mutex> lk(pair.m);
        TEST_ASSERT(pair.a_state == "ENDED", "caller should see ENDED");
        TEST_ASSERT(pair.a_detail.find("declined") != std::string::npos,
                    "caller detail should say declined by peer");
        TEST_ASSERT(pair.b_state == "ENDED", "callee should see ENDED too");
    }
    return true;
}

static bool test_busy_auto_decline() {
    VoiceCallManager a, b;
    CallbackPair pair;
    pair.a = &a;
    pair.b = &b;
    wire_pair(pair);

    // A already has an active call with "peer-x".
    const std::string call1 = a.start_call("peer-x", "PCM_S16LE", 16000, 1, 20);
    TEST_ASSERT(!call1.empty(), "first call failed");

    // Inject a second OFFER claiming to come from "peer-x". A must auto-decline
    // it (busy) without disturbing call1. Building the wire payload directly
    // exercises the OFFER parser on top of the busy path.
    {
        std::string offer;
        offer.push_back(static_cast<char>(VoiceControlType::OFFER));
        const std::string fake_id = "newcall-2";
        offer.push_back(static_cast<char>(fake_id.size()));
        offer += fake_id;
        const std::string codec = "PCM_S16LE";
        offer.push_back(static_cast<char>(codec.size()));
        offer += codec;
        const uint16_t rate = 16000;
        offer.push_back(static_cast<char>(rate & 0xFF));
        offer.push_back(static_cast<char>((rate >> 8) & 0xFF));
        offer.push_back(1);  // channels
        offer.push_back(20); // frame_ms
        a.handle_incoming_message("peer-x", offer);
    }

    TEST_ASSERT(a.get_call_state(call1) == VoiceCallState::OUTGOING,
                "A's first call must survive the auto-decline");
    TEST_ASSERT(a.get_call_state("newcall-2") == VoiceCallState::IDLE,
                "the busy offer must not create a call");
    {
        std::lock_guard<std::mutex> lk(pair.m);
        // A should have emitted a DECLINE control frame for the busy offer.
        bool saw_decline = false;
        for (const auto& out : pair.a_outbound) {
            if (!out.empty() && static_cast<uint8_t>(out[0]) ==
                                    static_cast<uint8_t>(VoiceControlType::DECLINE)) {
                saw_decline = true;
                break;
            }
        }
        TEST_ASSERT(saw_decline, "A should emit a DECLINE for the busy offer");
    }
    return true;
}

static bool test_ring_timeout() {
    VoiceCallManager::CallConfig cfg;
    cfg.ring_timeout_ms = 300;  // fast watchdog for the test
    VoiceCallManager a(cfg), b(cfg);
    CallbackPair pair;
    pair.a = &a;
    pair.b = &b;
    wire_pair(pair);

    const std::string call_id = a.start_call("peer-b", "PCM_S16LE", 16000, 1, 20);
    TEST_ASSERT(!call_id.empty(), "start_call failed");

    // Nobody answers; the callee's watchdog auto-declines after the timeout.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        std::lock_guard<std::mutex> lk(pair.m);
        if (pair.a_state == "ENDED") break;
    }
    {
        std::lock_guard<std::mutex> lk(pair.m);
        TEST_ASSERT(pair.a_state == "ENDED", "caller should see ENDED after ring timeout");
        // The caller either self-reports "ring timeout" or observes the callee's
        // polite DECLINE control frame (watchdog race on the two sides).
        const bool ok_detail = pair.a_detail.find("timeout") != std::string::npos ||
                               pair.a_detail.find("declined") != std::string::npos;
        TEST_ASSERT(ok_detail, "caller detail should mention timeout or declined");
        TEST_ASSERT(pair.b_state == "ENDED", "callee should also see ENDED");
    }
    return true;
}

static bool test_media_timeout() {
    VoiceCallManager::CallConfig cfg;
    cfg.ring_timeout_ms = 5000;
    cfg.media_timeout_ms = 300;  // fast watchdog for the test
    VoiceCallManager a(cfg), b(cfg);
    CallbackPair pair;
    pair.a = &a;
    pair.b = &b;
    wire_pair(pair);

    const std::string call_id = a.start_call("peer-b", "PCM_S16LE", 16000, 1, 20);
    TEST_ASSERT(!call_id.empty(), "start_call failed");
    TEST_ASSERT(b.accept_call(call_id), "accept call failed");
    TEST_ASSERT(a.get_call_state(call_id) == VoiceCallState::IN_CALL, "call should connect");

    // Stop all media: no frames flow in either direction -> both sides end
    // locally after media_timeout_ms.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        std::lock_guard<std::mutex> lk(pair.m);
        if (pair.a_state == "ENDED" && pair.b_state == "ENDED") break;
    }
    {
        std::lock_guard<std::mutex> lk(pair.m);
        TEST_ASSERT(pair.a_state == "ENDED", "caller should end after media timeout");
        TEST_ASSERT(pair.b_state == "ENDED", "callee should end after media timeout");
        TEST_ASSERT(pair.a_detail.find("media") != std::string::npos ||
                        pair.a_detail.find("ended") != std::string::npos,
                    "caller detail should mention media inactivity");
    }
    return true;
}

int main() {
    std::cout << "=== Voice call tests ===" << std::endl;

    if (test_offer_accept_frame_flow()) std::cout << "PASS: offer/accept/frame flow" << std::endl;
    if (test_decline_flow()) std::cout << "PASS: decline flow" << std::endl;
    if (test_busy_auto_decline()) std::cout << "PASS: busy auto-decline" << std::endl;
    if (test_ring_timeout()) std::cout << "PASS: ring timeout" << std::endl;
    if (test_media_timeout()) std::cout << "PASS: media inactivity timeout" << std::endl;

    if (tests_failed > 0) {
        std::cerr << tests_failed << " voice call test(s) FAILED" << std::endl;
        return 1;
    }
    std::cout << "ALL VOICE CALL TESTS PASSED" << std::endl;
    return 0;
}
