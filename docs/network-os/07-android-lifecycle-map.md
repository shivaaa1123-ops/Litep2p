# Network OS Phase 0 — Step 1.7: Android Service Lifecycle + JNI Map

**Date:** 2026-08-20
**Branch:** `network-os-dev`
**Scope:** Kotlin wrapper, JNI bridge, C ABI, foreground-service/work-manager use, process-death handling, single vs multi-thread flavors.
**Purpose:** Input to Phase 1 `IPlatformAdapter` + `NetworkRuntime` lifecycle, Phase 8 resource manager, Phase 12 Kotlin finalization.

## 1. Layering

```
Kotlin app
  ├─ LiteP2P (facade, LiteP2P.kt)  ── LiteP2PFlows (coroutine flows) ── LiteP2PListener
  ├─ LiteP2PRuntime (object, LiteP2PRuntime.kt)   — turnkey lifecycle manager
  ├─ LiteP2PService (foreground Service, LiteP2PService.kt)  — hosts native engine
  ├─ LiteP2PNative (LiteP2PNative.kt, 309 lines)  — @JvmStatic externals
  └─ EnvironmentHints (EnvironmentHints.kt)  — pushes network/battery/Doze state
        │ JNI
        ▼
jni_bridge.cpp  (Java_com_zeengal_litep2p_core_LiteP2PNative_* → C ABI, 1:1)
        ▼
litep2p_c_api.cpp  (litep2p_init/start/stop/shutdown/send/...)
        ▼
SessionManager + modules
```

## 2. Native entry points (jni_bridge.cpp)

`JNI_OnLoad` at `jni_bridge.cpp:637`; all `nativeXxx` map directly to the C ABI, e.g. `nativeInit` (`jni_bridge.cpp:661`) → `litep2p_init`, `nativeStart` (`jni_bridge.cpp:704`) → `litep2p_start`. Callbacks flow C→JNI→`NativeEvents` (static Kotlin class) → `LiteP2PFlows` → `LiteP2PListener`.

## 3. Android lifecycle

| Aspect | Current implementation |
|---|---|
| Host | `LiteP2PService` = **foreground service** (`FOREGROUND_SERVICE_TYPE_DATA_SYNC`, notification id 0x1C50), `START_STICKY` (`LiteP2PService.kt:32-33,67`) |
| Engine thread | dedicated `engineExecutor` single thread ("litep2p-engine", `LiteP2PService.kt:43-45`) — native init/start/stop never run on main thread |
| Locks | partial wakelock + Wi-Fi lock + multicast lock held while running (`LiteP2PService.kt:47-49, 305`) |
| Environment hints | `EnvironmentHints` registers network/battery/Doze/power-save receivers → `litep2p_set_network_info`/`litep2p_set_battery_level`/`litep2p_set_reconnect_mode` (`EnvironmentHints.kt:174`) |
| Config persistence | `LiteP2PRuntime` persists config in SharedPreferences (`LiteP2PRuntime.kt:181-216`); `reconstructConfig` after process death (`LiteP2PRuntime.kt:222`) |
| Process death | `START_STICKY` re-creates the service; `desiredRunning` prefs + `reconstructConfig` restore last state (`LiteP2PService.kt:84-87`) |
| WorkManager | **Not used** for engine scheduling today (`LiteP2PService` is the only host; `app` module has `EngineWatchdogWorker.kt` — an app-side watchdog, not WorkManager-gated engine work). Phase 8 bridge target. |
| Single vs multi-thread | `singleThreadMode` config flag → `LITEP2P_SINGLE_THREAD_MODE_COMPILE` AAR flavors; runtime behavior per `is_single_thread_mode()` (`session_manager.cpp:101`) |

## 4. C ABI lifecycle contract (litep2p_c_api.cpp)

- `litep2p_init(config)` → `litep2p_start()` → `litep2p_stop()` → `litep2p_shutdown()`; states `STOPPED → STARTING → RUNNING → STOPPING` (`litep2p_c_api.cpp:516-747`).
- **Process-wide singleton, no handles** (locked decision 10): re-init allowed only when fully stopped.
- Blocking `engine->start()` is called **without** the API lock held so consumers can re-enter the ABI from callbacks (`litep2p_c_api.cpp:680-682`).

## 5. Gaps / observations

1. No WorkManager integration for background scheduling (Phase 8 `PlatformAdapter→WorkManager` bridge is new work).
2. The foreground service is always-on while running — Phase 8 must map resource profiles (ECO/BALANCED/RELIABLE) to service/lock policies and `START_STICKY` behavior.
3. `EnvironmentHints` pushes state but is **app-side**; Phase 1 `IPlatformAdapter` must abstract these signals so the C++ core never depends on Android APIs.
4. Crash reporting: native `CrashHandler` writes async-safe crash context; `AnomalyReporter` uploads incidents on next engine start (repo `anomalies/` dir).
