// Network OS Phase 13 — gossip / cascade / push / QR verification.

#include "networkos/gossip/gossip_engine.h"
#include "networkos/gossip/discovery_cascade.h"
#include "networkos/gossip/push_bridge.h"
#include "networkos/gossip/qr_bootstrap.h"
#include "networkos/gossip/adaptive_keepalive.h"

#include <cstdio>
#include <cstring>
#include <set>
#include <sodium.h>

using namespace networkos;
using namespace networkos::gossip;

static int g_checks = 0, g_fail = 0;
#define CHECK(cond, msg)                                        \
    do {                                                        \
        ++g_checks;                                             \
        if (!(cond)) {                                          \
            ++g_fail;                                           \
            std::printf("FAIL: %s (line %d)\n", msg, __LINE__); \
        }                                                       \
    } while (0)

static const uint64_t NOW = 1'700'000'000;  // fixed test epoch (seconds)

static void test_peer_record_codec() {
    PeerRecord r;
    r.peer_id = std::string(64, 'a');
    r.primary_endpoint = "192.168.1.7:4500";
    r.token_version = 42;
    r.last_seen_utc = NOW;
    normalize_flags(r);

    std::string enc = encode_peer_record(r);
    PeerRecord d;
    CHECK(decode_peer_record(enc, d), "decode plain record");
    CHECK(d.peer_id == r.peer_id && d.primary_endpoint == r.primary_endpoint,
          "plain roundtrip fields");
    CHECK(!d.has_new_token() && !d.has_signaling(), "plain flags cleared");

    r.fcm_token_id = "fcm-token-abc-123";
    r.signaling_addr = "wss://sig.example.net:7900";
    normalize_flags(r);
    enc = encode_peer_record(r);
    CHECK(decode_peer_record(enc, d), "decode full record");
    CHECK(d.fcm_token_id == r.fcm_token_id &&
              d.signaling_addr == r.signaling_addr,
          "full roundtrip");

    for (size_t cut = 1; cut < enc.size(); cut += 7) {
        size_t o2 = 0;
        PeerRecord tmp;
        if (decode_peer_record_at(enc.substr(0, cut), o2, tmp)) {
            CHECK(false, "truncated record must not decode");
            break;
        }
    }
    PeerRecord tmp2;
    CHECK(!decode_peer_record(enc + std::string(1, '\x00'), tmp2),
          "trailing garbage rejected");

    PeerRecord base = d;
    PeerRecord older = d;
    older.token_version -= 1;
    CHECK(!merge_record(base, older), "older version rejected");
    CHECK(!merge_record(base, d), "equal version rejected");
    PeerRecord newer = d;
    newer.token_version += 5;
    newer.signaling_addr.clear();
    normalize_flags(newer);
    CHECK(merge_record(base, newer), "newer version accepted");
    CHECK(base.signaling_addr == d.signaling_addr,
          "locally-known signaling preserved");
}

static void test_engine_delta_and_pool() {
    GossipEngine::Config cfg;
    cfg.local_peer_id = "local-peer";
    GossipEngine e(cfg);

    e.setLocalPushToken("tok-1", NOW);
    CHECK(e.localRecord().token_version == 1, "token version bumped");
    e.setLocalPushToken("tok-1", NOW);
    CHECK(e.localRecord().token_version == 1, "same token no bump");

    std::string d1 = e.buildDeltaFor("peerA", NOW);
    CHECK(d1.size() > 1, "delta non-empty");
    std::string d2 = e.buildDeltaFor("peerA", NOW);
    CHECK(d2.size() == 1, "re-delta empty (per-peer cursor)");

    GossipEngine::Config rcfg;
    rcfg.local_peer_id = "peerA";
    GossipEngine remote(rcfg);
    CHECK(remote.ingestDelta(d1, NOW) == 1, "remote accepted 1 record");
    CHECK(remote.ingestDelta(d1, NOW) == 0, "re-ingest deduped");
    PeerRecord got;
    CHECK(remote.lookup("local-peer", got) && got.fcm_token_id == "tok-1",
          "remote lookup with token");

    PeerRecord sig;
    sig.peer_id = "carrier-1";
    sig.primary_endpoint = "10.0.0.1:1";
    sig.signaling_addr = "wss://pool-one:7900";
    sig.token_version = 9;
    sig.last_seen_utc = NOW;
    normalize_flags(sig);
    std::string batch(1, '\x01');
    batch.append(encode_peer_record(sig));
    remote.ingestDelta(batch, NOW);
    std::string url;
    CHECK(remote.signalingPoolNext(url) && url == "wss://pool-one:7900",
          "pool serves gossiped signaling addr");
    remote.signalingPoolMarkBad(url);
    CHECK(remote.signalingPoolNext(url), "pool serves after mark-bad");

    std::string q = GossipEngine::encodeFindPeer("local-peer", 0xDEADBEEFu);
    std::string t;
    uint32_t n = 0;
    CHECK(GossipEngine::decodeFindPeer(q, t, n) && t == "local-peer" &&
              n == 0xDEADBEEFu,
          "find query roundtrip");
    PeerRecord hit;
    remote.lookup("local-peer", hit);
    std::string rep = GossipEngine::encodeFindReply(&hit, n);
    PeerRecord rr;
    bool found = false;
    CHECK(GossipEngine::decodeFindReply(rep, rr, found, n) && found &&
              rr.peer_id == "local-peer",
          "find reply hit roundtrip");
    std::string miss = GossipEngine::encodeFindReply(nullptr, n);
    found = true;
    CHECK(GossipEngine::decodeFindReply(miss, rr, found, n) && !found,
          "find reply miss roundtrip");

    GossipEngine::Config scfg;
    scfg.local_peer_id = "p";
    scfg.stale_after_s = 100;
    GossipEngine se(scfg);
    PeerRecord old;
    old.peer_id = "old-peer";
    old.primary_endpoint = "1.2.3.4:5";
    old.token_version = 1;
    old.last_seen_utc = NOW - 1000;
    normalize_flags(old);
    std::string ob(1, '\x01');
    ob.append(encode_peer_record(old));
    se.ingestDelta(ob, NOW);
    CHECK(se.size() == 1, "record present before purge");
    CHECK(se.purgeStale(NOW) == 1, "stale record purged");
    CHECK(se.size() == 0, "directory empty after purge");

    GossipEngine::Config pcfg;
    pcfg.local_peer_id = "p";
    pcfg.persist_path = "/tmp/litep2p_gossip_test_dir.json";
    GossipEngine pe(pcfg);
    pe.setLocalPushToken("persist-tok", NOW);
    pe.ingestDelta(ob, NOW);
    CHECK(pe.save(NOW), "directory saved");
    GossipEngine::Config lcfg;
    lcfg.local_peer_id = "p";
    lcfg.persist_path = pcfg.persist_path;
    GossipEngine le(lcfg);
    CHECK(le.load(), "directory loaded");
    CHECK(le.lookup("old-peer", got) && got.primary_endpoint == "1.2.3.4:5",
          "persisted record restored");
    std::remove("/tmp/litep2p_gossip_test_dir.json");
}

// Regression tests for audit fixes: IPv6-safe persistence reload, delta
// convergence under batch truncation, no self-record on the wire, and
// empty-token rejection.
static void test_engine_audit_regressions() {
    // (1) A record whose endpoint contains ']' (IPv6 literal) followed by
    // another record: the naive find(']') reload dropped everything after it.
    GossipEngine::Config pcfg;
    pcfg.local_peer_id = "p";
    pcfg.persist_path = "/tmp/litep2p_gossip_test_dir2.json";
    GossipEngine pe(pcfg);
    PeerRecord v6;
    v6.peer_id = "v6-peer";
    v6.primary_endpoint = "[2001:db8::1]:4500";
    v6.token_version = 3;
    v6.last_seen_utc = NOW;
    normalize_flags(v6);
    PeerRecord after;
    after.peer_id = "after-v6";
    after.primary_endpoint = "9.9.9.9:9";
    after.token_version = 4;
    after.last_seen_utc = NOW;
    normalize_flags(after);
    std::string two(1, '\x02');
    two.append(encode_peer_record(v6));
    two.append(encode_peer_record(after));
    CHECK(pe.ingestDelta(two, NOW) == 2, "audit: both records ingested");
    CHECK(pe.save(NOW), "audit: saved");
    GossipEngine::Config lcfg;
    lcfg.local_peer_id = "p";
    lcfg.persist_path = pcfg.persist_path;
    GossipEngine le(lcfg);
    CHECK(le.load(), "audit: reloaded");
    PeerRecord got;
    CHECK(le.lookup("v6-peer", got) &&
              got.primary_endpoint == "[2001:db8::1]:4500",
          "audit: IPv6-endpoint record restored");
    CHECK(le.lookup("after-v6", got) && got.primary_endpoint == "9.9.9.9:9",
          "audit: record after IPv6 record restored");
    CHECK(le.size() == 2, "audit: no self record reloaded");
    std::remove("/tmp/litep2p_gossip_test_dir2.json");

    // (2) Batch truncation must converge: with delta_batch_max=2 and 5 pending
    // records, successive deltas to the same peer must eventually carry all 5.
    GossipEngine::Config bcfg;
    bcfg.local_peer_id = "src";
    bcfg.delta_batch_max = 2;
    GossipEngine be(bcfg);
    for (int i = 1; i <= 5; ++i) {
        PeerRecord r;
        r.peer_id = "bulk-" + std::to_string(i);
        r.primary_endpoint = "10.1.0." + std::to_string(i) + ":1";
        r.token_version = static_cast<uint64_t>(i);
        r.last_seen_utc = NOW;
        normalize_flags(r);
        std::string b(1, '\x01');
        b.append(encode_peer_record(r));
        CHECK(be.ingestDelta(b, NOW) == 1, "audit: bulk ingest");
    }
    std::set<std::string> delivered;
    for (int round = 0; round < 4; ++round) {
        const std::string delta = be.buildDeltaFor("downstream", NOW);
        const size_t cnt = static_cast<uint8_t>(delta[0]);
        size_t off = 1;
        for (size_t i = 0; i < cnt; ++i) {
            PeerRecord r;
            CHECK(decode_peer_record_at(delta, off, r), "audit: delta decodes");
            delivered.insert(r.peer_id);
        }
        if (delivered.size() == 5) break;
    }
    CHECK(delivered.size() == 5,
          "audit: truncated batches converge (no starvation)");

    // (3) Self must ride the wire exactly once per fresh peer (m_local only,
    // never a directory copy), and an empty token must not bump the version.
    GossipEngine::Config scfg;
    scfg.local_peer_id = "selfy";
    GossipEngine se2(scfg);
    se2.setLocalPushToken("", NOW);  // must be ignored
    CHECK(se2.localRecord().token_version == 0, "audit: empty token no bump");
    se2.setLocalPushToken("real-token", NOW);
    CHECK(se2.size() == 0, "audit: self not stored in directory");
    const std::string sd = se2.buildDeltaFor("friend", NOW);
    CHECK(static_cast<uint8_t>(sd[0]) == 1, "audit: self appears once");
}

static void test_cascade() {
    DiscoveryCascade c;
    PeerRecord out;
    CHECK(c.resolve("x", out) == CascadeTier::kExhausted,
          "no handlers -> exhausted");

    PeerRecord rec;
    rec.peer_id = "x";
    rec.primary_endpoint = "5.6.7.8:9";
    rec.token_version = 3;
    rec.last_seen_utc = NOW;
    normalize_flags(rec);

    int gossip_called = 0, push_called = 0;
    c.setCacheHandler([&](const std::string& id, PeerRecord& o) {
        o = rec;
        return id == "x";
    });
    c.setGossipHandler([&](const std::string&, PeerRecord&) {
        ++gossip_called;
        return false;
    });
    c.setPushHandler([&](const std::string&, PeerRecord&) {
        ++push_called;
        return false;
    });
    CHECK(c.resolve("x", out) == CascadeTier::kCache, "cache tier wins");
    CHECK(gossip_called == 0 && push_called == 0, "later tiers skipped");

    c.setCacheHandler([](const std::string&, PeerRecord&) { return false; });
    c.setGossipHandler([&](const std::string& id, PeerRecord& o) {
        o = rec;
        return id == "x";
    });
    CHECK(c.resolve("x", out) == CascadeTier::kGossip, "gossip fallback");
    CHECK(push_called == 0, "push skipped after gossip hit");

    c.setGossipHandler([](const std::string&, PeerRecord&) { return false; });
    c.setPushHandler([&](const std::string&, PeerRecord& o) {
        o = rec;
        return true;
    });
    CHECK(c.resolve("x", out) == CascadeTier::kPush, "push tier resolves");

    c.setPushHandler([](const std::string&, PeerRecord&) { return false; });
    c.setSignalingPoolHandler([&](const std::string&, PeerRecord& o) {
        o = rec;
        return true;
    });
    CHECK(c.resolve("x", out) == CascadeTier::kSignalingPool,
          "signaling pool last resort");
    CHECK(c.counters().exhausted == 1, "exhaustion counted once");
}

static void test_push_payload() {
    PushPayload p;
    CHECK(parse_push_payload(
              "{\"type\":\"candidates\",\"peer_id\":\"abc\",\"nonce\":77,"
              "\"candidates\":[\"1.2.3.4:5\",\"[::1]:6\"]}",
              p),
          "candidates payload parses");
    CHECK(p.type == PushPayload::Type::kCandidates && p.peer_id == "abc" &&
              p.nonce == 77 && p.candidates.size() == 2 &&
              p.candidates[1] == "[::1]:6",
          "candidates fields");

    PushPayload w;
    CHECK(parse_push_payload("{\"type\":\"wake\",\"peer_id\":\"zz\"}", w),
          "wake payload parses");
    CHECK(w.type == PushPayload::Type::kWake && w.peer_id == "zz" &&
              w.candidates.empty(),
          "wake fields");

    PushPayload bad;
    CHECK(!parse_push_payload("{\"type\":\"other\"}", bad), "bad type rejected");
    CHECK(!parse_push_payload("{\"type\":\"wake\"}", bad),
          "missing peer_id rejected");
    CHECK(!parse_push_payload("not json at all", bad), "garbage rejected");
}

static void test_qr_and_keepalive() {
    if (sodium_init() < 0) return;
    const std::string seed(64, '7');  // 0x77 x32 — valid hex seed
    PeerRecord me;
    me.peer_id = std::string(64, 'f');
    me.primary_endpoint = "77.1.2.3:40001";
    me.signaling_addr = "wss://mine:7900";
    normalize_flags(me);

    std::string qr = build_contact_qr(seed, me);
    CHECK(!qr.empty(), "qr built");
    CHECK(qr.find('=') == std::string::npos &&
              qr.find('+') == std::string::npos &&
              qr.find('/') == std::string::npos,
          "qr text is base64url (QR-safe)");

    ContactCard card;
    CHECK(parse_contact_qr(qr, card), "qr parses+verifies");
    CHECK(card.record.peer_id == me.peer_id &&
              card.record.primary_endpoint == me.primary_endpoint &&
              card.record.signaling_addr == me.signaling_addr,
          "qr fields roundtrip");
    CHECK(card.signer_pk_hex.size() == 64, "signer pk exported for pinning");

    std::string tampered = qr;
    tampered[10] = (tampered[10] == 'A') ? 'B' : 'A';
    ContactCard bad;
    CHECK(!parse_contact_qr(tampered, bad), "tampered qr rejected");

    const std::string seed2(64, '8');
    CHECK(build_contact_qr(seed2, me) != qr,
          "distinct seeds distinct payloads");

    AdaptiveKeepalive ka;
    CHECK(ka.intervalMs() == AdaptiveKeepalive::kInitialMs, "starts at 45s");
    ka.onSuccess();
    CHECK(ka.intervalMs() == 90'000, "ramp to 90s");
    ka.onSuccess();
    CHECK(ka.intervalMs() == 120'000, "ramp to 120s");
    ka.onSuccess();
    CHECK(ka.intervalMs() == AdaptiveKeepalive::kMaxMs, "ramp to 180s cap");
    ka.onFailure();
    CHECK(ka.intervalMs() == AdaptiveKeepalive::kMaxMs,
          "single failure tolerated");
    ka.onFailure();
    CHECK(ka.intervalMs() == AdaptiveKeepalive::kInitialMs,
          "double failure resets to 45s");
    ka.onSuccess();
    ka.onNetworkChange();
    CHECK(ka.intervalMs() == AdaptiveKeepalive::kInitialMs,
          "network change resets");
}

int main() {
    test_peer_record_codec();
    test_engine_delta_and_pool();
    test_engine_audit_regressions();
    test_cascade();
    test_push_payload();
    test_qr_and_keepalive();
    std::printf(g_fail ? "FAIL: %d checks, %d failure(s)\n"
                       : "PASS: %d checks, %d failure(s)\n",
                g_checks, g_fail);
    return g_fail ? 1 : 0;
}