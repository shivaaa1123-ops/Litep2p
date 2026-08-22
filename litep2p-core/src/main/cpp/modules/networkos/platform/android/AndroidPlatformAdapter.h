#pragma once

// Android platform adapter — wakeup bridge seam (Phase 8 / master doc §8).
//
// The C++ engine never touches Android APIs. When the NetworkRuntime needs
// deferred work to run at a future time (delivery retry backoff, lease
// renewal, maintenance), it calls IPlatformAdapter::requestWakeup(). On
// Android that must become a WorkManager job, because only WorkManager
// survives process death and Doze batching.
//
// JNI code lives exclusively in src/jni_bridge.cpp, so this header exposes a
// tiny function-pointer seam: the JNI layer registers an emitter during
// jniBridgeInit(), and the adapter forwards wakeup requests through it. Until
// a bridge registers, requests are queued (bounded, coalesced per reason) and
// flushed on registration — early-boot wakeups are never lost.

#include <cstdint>

namespace networkos {
namespace android {

// reason: short ASCII tag ("maintenance", "delivery_retry", "lease_renewal").
// delay_ms: clamped [0 .. 900000] hint for when the work becomes eligible.
using WakeBridgeFn = void (*)(const char* reason, int64_t delay_ms);

// Register (or replace) the JNI emitter. Thread-safe; flushes any wakeups
// requested before registration. Pass nullptr to unregister.
void setWakeBridge(WakeBridgeFn fn);

}  // namespace android
}  // namespace networkos