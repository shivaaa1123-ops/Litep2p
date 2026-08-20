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
        m_session = std::make_unique<SessionManager>();
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
                        } else {
                            emit_(RuntimeEventType::kPeerState, "peer_disconnected", p.id, "");
                        }
                    }
                },
                cfg.comms_mode.empty() ? "UDP" : cfg.comms_mode,
                m_peer_id);
        } catch (const std::exception& e) {
            m_session.reset();
            m_state = RuntimeState::kFailed;
            emit_(RuntimeEventType::kLifecycle, "start_failed", "", e.what());
            return Result::kIo;
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
            m_session->stop();
            m_session.reset();
        }
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
        // Any connectivity/foreground/charging signal is a scheduler event.
        if (s == PlatformSignal::kConnectivity || s == PlatformSignal::kForeground ||
            s == PlatformSignal::kCharging) {
            if (m_scheduler) m_scheduler->process(now_ms());
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
    std::unique_ptr<SessionManager> m_session;

    mutable std::mutex m_life_mu;
    mutable std::mutex m_cb_mu;
};

} // namespace

std::unique_ptr<Runtime> createRuntime() {
    return std::make_unique<NetworkRuntime>();
}

} // namespace networkos
