// NetworkRuntime.cpp — Network OS Phase 1 runtime facade.
//
// A facade over the existing engine (SessionManager + discovery + overlay).
// NO logic moves in Phase 1 (locked decision 9); this only establishes the
// lifecycle skeleton every later phase plugs into:
//
//   start()  : load config -> open identity -> open transports (SessionManager)
//              -> restore durable state -> notify scheduler -> event loop.
//   stop()   : reverse order, clean shutdown, no blocked threads.
//   restore(): reconstruct the same logical state from persistence.
//
// The runtime owns the single native event queue -> one event sink (§35).

#include "networkos/Runtime.h"
#include "networkos/IIdentityStore.h"
#include "networkos/IPlatformAdapter.h"
#include "networkos/IScheduler.h"
#include "networkos/ITransport.h"
#include "networkos/objectstore/ObjectStore.h"
#include "networkos/handoff/HandoffManager.h"
#include "networkos/delivery/DeliveryManager.h"
#include "networkos/session/SessionFacade.h"

#include "config_manager.h"
#include "constants.h"
#include "session_manager.h"

#include <chrono>
#include <mutex>
#include <string>

namespace networkos {

namespace {

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

class NetworkRuntime : public Runtime {
public:
    NetworkRuntime() {
        m_scheduler = createScheduler();
        m_identity = createFileIdentityStore("");
        m_platform = createDesktopPlatformAdapter();
    }

    ~NetworkRuntime() override {
        stop();
    }

    Result start(const RuntimeConfig& cfg) override {
        std::lock_guard<std::mutex> lock(m_life_mu);
        if (m_state == RuntimeState::kStarting || m_state == RuntimeState::kRunning ||
            m_state == RuntimeState::kStopping) {
            return Result::kBusy;
        }
        m_cfg = cfg;
        m_state = RuntimeState::kStarting;
        emit_(RuntimeEventType::kLifecycle, "starting", "", "");

        // 1. Load configuration (explicit path, else files_dir/config.json).
        ConfigManager& cm = ConfigManager::getInstance();
        if (!cfg.config_path.empty()) {
            cm.loadConfig(cfg.config_path);
        } else if (!cfg.files_dir.empty()) {
            cm.loadConfig(cfg.files_dir + "/config.json");
        }
        // Apply the runtime toggles on top of config.json (mirrors the C ABI).
        cm.setValueAtPath({"network", "discovery_enabled"},
                          cfg.enable_discovery ? true : false);
        cm.setValueAtPath({"nat_traversal", "peer_discovery", "enabled"},
                          cfg.enable_discovery ? true : false);

        // 2. Open identity (create-once; PeerID stable across restarts).
        m_identity = createFileIdentityStore(cfg.files_dir);
        Identity ident;
        if (m_identity->loadOrCreate(cfg.peer_id, ident) != Result::kOk) {
            m_state = RuntimeState::kFailed;
            return Result::kIo;
        }
        m_peer_id = ident.peer_id;

        // 3. Open transports — start the existing engine behind the facade.
        const int port = cfg.listen_port > 0 ? cfg.listen_port : DEFAULT_SERVER_PORT;
        m_session = std::make_shared<SessionManager>();
        m_session->setMessageReceivedCallback(
            [this](const std::string& peer_id, const std::string& message) {
                emit_(RuntimeEventType::kMessage, "message", peer_id, message);
            });
        try {
            m_session->start(
                port,
                [this](const std::vector<Peer>& peers) {
                    std::lock_guard<std::mutex> lock(m_cb_mu);
                    for (const auto& p : peers) {
                        if (p.connected) {
                            emit_(RuntimeEventType::kPeerState, "peer_ready", p.id, "");
                            if (m_session_facade) m_session_facade->onPeerState(p.id, "READY");
                            // Phase 4: a new READY peer is a carrier
                            // opportunity — re-offer queued objects.
                            if (m_handoff) m_handoff->retryPending(now_ms());
                            // Phase 5: a newly-READY peer that is the
                            // destination of stored objects gets them pushed.
                            if (m_delivery) m_delivery->forwardPending(p.id);
                        } else {
                            emit_(RuntimeEventType::kPeerState, "peer_disconnected", p.id, "");
                            if (m_session_facade) m_session_facade->onPeerState(p.id, "DISCONNECTED");
                        }
                    }
                },
                cfg.comms_mode.empty() ? "UDP" : cfg.comms_mode,
                m_peer_id);
        } catch (const std::exception& e) {
            m_session.reset();
            m_session_facade.reset();
            m_state = RuntimeState::kFailed;
            emit_(RuntimeEventType::kLifecycle, "start_failed", "", e.what());
            return Result::kIo;
        }

        // Phase 2: the runtime owns the session lifecycle — the facade enforces
        // bounds and negotiates capabilities over the live engine.
        m_session_facade = std::make_unique<SessionFacade>(m_session, SessionFacade::Bounds{});

        // Phase 3: the runtime owns the durable object store (SQLite/WAL under
        // files_dir). Later phases (4=handoff, 5=delivery/receipts, 6=anti-
        // entropy, 7=replication) all operate on this store.
        if (!cfg.files_dir.empty()) {
            ObjectStore::Options o;
            o.path = cfg.files_dir + "/networkos.sqlite";
            m_object_store = std::make_unique<ObjectStore>();
            if (!m_object_store->open(o)) {
                // Non-fatal: fall back to no durable store and log.
                m_object_store.reset();
            }
        }

        // Phase 4: the two-phase durable handoff manager. Wired over the live
        // session (typed frames, encrypted channel) + the object store.
        if (m_object_store) {
            handoff::HandoffManager::Config hcfg;
            hcfg.local_peer_id = m_peer_id;
            hcfg.carrier_enabled = true;
            m_handoff = std::make_unique<handoff::HandoffManager>(
                m_object_store.get(), hcfg);
            m_handoff->setSendFn(
                [this](const std::string& peer_id, MessageType type,
                       const std::string& payload) -> bool {
                    return m_session && m_session->send_handoff_frame(
                                            peer_id, type, payload);
                });
            m_handoff->setConnectedPeersFn(
                [this]() -> std::vector<std::string> {
                    if (!m_session) return {};
                    return m_session->getConnectedPeerIds();
                });
            m_handoff->setSigningKeysFns(
                [this]() -> std::pair<std::vector<uint8_t>,
                                      std::vector<uint8_t>> {
                    if (!m_session) return {};
                    return m_session->get_local_signing_keys();
                },
                [this](const std::string& peer_id) -> std::vector<uint8_t> {
                    if (!m_session) return {};
                    return m_session->get_peer_signing_key(peer_id);
                });
            m_handoff->setEventFn(
                [this](const std::string& kind, const std::string& payload) {
                    emit_(RuntimeEventType::kDelivery, kind, "", payload);
                });
            // Incoming frames -> route to handoff (storage) and/or delivery
            // (direct-to-me) based on the object's destination.
            m_session->set_handoff_frame_handler(
                [this](const std::string& peer_id, MessageType type,
                       const std::string& payload) {
                    switch (type) {
                        case MessageType::OBJECT_OFFER:
                        case MessageType::OBJECT_DATA: {
                            // Is this object addressed to us (direct delivery)?
                            // Offer: read destination from the offer. Data:
                            // from the envelope (needs deserialize).
                            bool to_me = false;
                            if (type == MessageType::OBJECT_OFFER) {
                                handoff::OfferFrame f;
                                if (decode_offer(payload, f) &&
                                    f.destination == m_peer_id) {
                                    to_me = true;
                                }
                            } else {
                                handoff::DataFrame df;
                                obj::NetworkObject obj;
                                if (decode_data(payload, df) &&
                                    obj::deserialize(df.envelope, obj) &&
                                    obj.origin.destination == m_peer_id) {
                                    to_me = true;
                                }
                            }
                            if (to_me) {
                                if (m_delivery)
                                    m_delivery->onFrame(peer_id, type, payload, true);
                            } else {
                                if (m_handoff) m_handoff->onFrame(peer_id, type, payload);
                            }
                            break;
                        }
                        case MessageType::OBJECT_ACCEPT:
                            if (m_handoff) m_handoff->onFrame(peer_id, type, payload);
                            if (m_delivery)
                                m_delivery->onFrame(peer_id, type, payload, false);
                            break;
                        case MessageType::OBJECT_REJECT:
                        case MessageType::STORED_ACK:
                            if (m_handoff) m_handoff->onFrame(peer_id, type, payload);
                            break;
                        case MessageType::RECEIVED_ACK:
                            if (m_delivery)
                                m_delivery->onFrame(peer_id, type, payload, false);
                            break;
                        default:
                            break;
                    }
                });

            // Phase 5: direct delivery + signed receipts over the same session
            // channel + object store.
            delivery::DeliveryManager::Config dcfg;
            dcfg.local_peer_id = m_peer_id;
            m_delivery = std::make_unique<delivery::DeliveryManager>(
                m_object_store.get(), dcfg);
            m_delivery->setSendFn(
                [this](const std::string& peer_id, MessageType type,
                       const std::string& payload) -> bool {
                    return m_session && m_session->send_handoff_frame(
                                            peer_id, type, payload);
                });
            m_delivery->setConnectedPeersFn(
                [this]() -> std::vector<std::string> {
                    if (!m_session) return {};
                    return m_session->getConnectedPeerIds();
                });
            m_delivery->setSigningKeysFns(
                [this]() -> std::pair<std::vector<uint8_t>,
                                      std::vector<uint8_t>> {
                    if (!m_session) return {};
                    return m_session->get_local_signing_keys();
                },
                [this](const std::string& peer_id) -> std::vector<uint8_t> {
                    if (!m_session) return {};
                    return m_session->get_peer_signing_key(peer_id);
                });
            m_delivery->setEventFn(
                [this](const std::string& kind, const std::string& payload) {
                    emit_(RuntimeEventType::kDelivery, kind, "", payload);
                });
        }

        // 4. Durable state restore (peer DB bootstrap happens inside
        //    SessionManager::start; nothing extra to do in Phase 1).
        // 5. Notify scheduler.
        {
            SchedulerEvents ev;
            ev.on_connectivity_changed = [this]() {
                if (m_scheduler) m_scheduler->process(now_ms());
            };
            ev.on_peer_available = ev.on_connectivity_changed;
            ev.on_app_foreground = ev.on_connectivity_changed;
            ev.on_maintenance_window = ev.on_connectivity_changed;
            m_scheduler->setEvents(ev);
        }
        // 6. Event loop is inside SessionManager (unified loop / event manager).

        m_state = RuntimeState::kRunning;
        emit_(RuntimeEventType::kLifecycle, "started", m_peer_id, "");
        return Result::kOk;
    }

    Result stop() override {
        std::lock_guard<std::mutex> lock(m_life_mu);
        if (m_state != RuntimeState::kRunning && m_state != RuntimeState::kStarting) {
            return Result::kInvalidState;
        }
        m_state = RuntimeState::kStopping;
        emit_(RuntimeEventType::kLifecycle, "stopping", "", "");
        if (m_session) {
            m_session->set_handoff_frame_handler(nullptr);
            m_session->stop();
            m_session.reset();
        }
        m_handoff.reset();
        m_delivery.reset();
        m_session_facade.reset();
        m_object_store.reset();
        m_state = RuntimeState::kStopped;
        emit_(RuntimeEventType::kLifecycle, "stopped", m_peer_id, "");
        return Result::kOk;
    }

    Result restore() override {
        std::lock_guard<std::mutex> lock(m_life_mu);
        if (m_state == RuntimeState::kStarting || m_state == RuntimeState::kRunning) {
            return Result::kBusy;
        }
        m_state = RuntimeState::kRestoring;
        // Reconstruct identity from persistence (keystore + identity.json).
        m_identity = createFileIdentityStore(m_cfg.files_dir);
        Identity ident;
        if (m_identity->load(ident) != Result::kOk) {
            emit_(RuntimeEventType::kLifecycle, "restore_no_identity", "", "");
            m_state = RuntimeState::kFailed;
            return Result::kNotFound;
        }
        m_peer_id = ident.peer_id;
        emit_(RuntimeEventType::kLifecycle, "restored", m_peer_id, "");
        m_state = RuntimeState::kStopped;
        return Result::kOk;
    }

    RuntimeState state() const override { return m_state; }

    Result stateName(std::string& out) const override {
        switch (m_state) {
            case RuntimeState::kStopped: out = "STOPPED"; break;
            case RuntimeState::kStarting: out = "STARTING"; break;
            case RuntimeState::kRunning: out = "RUNNING"; break;
            case RuntimeState::kStopping: out = "STOPPING"; break;
            case RuntimeState::kRestoring: out = "RESTORING"; break;
            case RuntimeState::kFailed: out = "FAILED"; break;
        }
        return Result::kOk;
    }

    std::string peerId() const override { return m_peer_id; }

    // Phase 2: the session facade the runtime owns (bounds, capabilities,
    // telemetry). Valid only while running. Returns nullptr when stopped.
    SessionFacade* sessionFacade() override { return m_session_facade.get(); }

    // Phase 3: the durable object store the runtime owns. Valid only while
    // running (and only when files_dir was configured). Returns nullptr when
    // stopped or when SQLite is unavailable.
    ObjectStore* objectStore() override { return m_object_store.get(); }

    // Phase 4: the two-phase durable handoff manager. Valid while running and
    // only when the object store is present.
    handoff::HandoffManager* handoff() override { return m_handoff.get(); }

    // Phase 5: direct delivery + signed receipts. Valid while running and only
    // when the object store is present.
    delivery::DeliveryManager* delivery() override { return m_delivery.get(); }

    Result sendMessage(const std::string& peer_id, const std::string& payload) override {
        if (!m_session) return Result::kInvalidState;
        m_session->sendMessageToPeer(peer_id, payload);
        return Result::kOk;
    }

    Result onPlatformSignal(const std::string& signal, const std::string& value) override {
        PlatformSignal s;
        if (signal == "connectivity") s = PlatformSignal::kConnectivity;
        else if (signal == "metered") s = PlatformSignal::kMetered;
        else if (signal == "battery") s = PlatformSignal::kBattery;
        else if (signal == "charging") s = PlatformSignal::kCharging;
        else if (signal == "storage") s = PlatformSignal::kStoragePressure;
        else if (signal == "foreground") s = PlatformSignal::kForeground;
        else if (signal == "wakeup_window") s = PlatformSignal::kWakeupWindow;
        else return Result::kInvalidArg;
        if (m_platform) m_platform->pushSignal(s, value);
        // Phase 4: forward the signal to the handoff ResourceManager so the
        // carrier admission policy reacts to storage pressure / charging /
        // battery / metering (Step 4.2/4.7).
        if (m_handoff) {
            m_handoff->resourceManager().onSignal(s, value);
        }
        // Any connectivity/foreground/charging signal is a scheduler event.
        if (s == PlatformSignal::kConnectivity || s == PlatformSignal::kForeground ||
            s == PlatformSignal::kCharging) {
            if (m_scheduler) m_scheduler->process(now_ms());
            // Step 4.6: envoy-triggered lease-expiry sweep (emits
            // LEASE_EXPIRING so the Phase 7 planner can renew/replicate).
            if (m_handoff) m_handoff->sweepLeases(now_ms());
        }
        emit_(RuntimeEventType::kPlatform, signal, "", value);
        return Result::kOk;
    }

private:
    void emit_(RuntimeEventType type, const std::string& kind,
               const std::string& peer_id, const std::string& payload) {
        RuntimeEvent ev;
        ev.type = type;
        ev.kind = kind;
        ev.peer_id = peer_id;
        ev.payload = payload;
        ev.at_ms = now_ms();
        std::shared_ptr<RuntimeEventSink> sink;
        {
            std::lock_guard<std::mutex> lock(m_cb_mu);
            sink = m_cfg.event_sink;
        }
        if (sink) sink->onRuntimeEvent(ev);
    }

    RuntimeState m_state{RuntimeState::kStopped};
    RuntimeConfig m_cfg;
    std::string m_peer_id;

    std::unique_ptr<IIdentityStore> m_identity;
    std::unique_ptr<IScheduler> m_scheduler;
    std::unique_ptr<IPlatformAdapter> m_platform;
    std::shared_ptr<SessionManager> m_session;
    std::unique_ptr<SessionFacade> m_session_facade;
    std::unique_ptr<ObjectStore> m_object_store;
    std::unique_ptr<handoff::HandoffManager> m_handoff;
    std::unique_ptr<delivery::DeliveryManager> m_delivery;

    mutable std::mutex m_life_mu;
    mutable std::mutex m_cb_mu;
};

} // namespace

std::unique_ptr<Runtime> createRuntime() {
    return std::make_unique<NetworkRuntime>();
}

} // namespace networkos
