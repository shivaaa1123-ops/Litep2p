package com.zeengal.litep2p

/**
 * Static binding to the native engine.
 *
 * The engine used to be started through instance methods on [MainActivity], which tied
 * its lifecycle to an Activity: if the Activity was destroyed (rotation, backgrounding,
 * low memory) there was no supported way to drive the engine. Because the engine is a
 * long-lived process-wide resource owned by [LiteP2PService], its JNI entry points live
 * here instead, on a plain object with no UI dependency.
 *
 * These are declared without @JvmStatic so they remain instance methods of the Kotlin
 * object, which keeps the existing JNI signatures (JNIEnv*, jobject) unchanged.
 */
object EngineNative {

    /**
     * Starts the engine.
     *
     * This is a *request*: the native side performs the real startup asynchronously and
     * signals completion via MainActivity.onEngineStartComplete().
     *
     * @return "OK" on accepted start, or a "BUSY_<STATE>" string if the engine is not
     *         currently stopped. Callers must not treat a non-OK result as running.
     */
    external fun nativeStartLiteP2PWithPeerId(commsMode: String, peerId: String): String

    /** Requests an asynchronous shutdown; completion arrives via onEngineStopComplete(). */
    external fun nativeStopLiteP2P()

    /**
     * Supplies the app-private files directory (Context.getFilesDir()).
     *
     * Called by the foreground service before it starts the engine, because the engine is
     * started through this plain object (which is not a Context). The native side uses this
     * path for config.json discovery, the Noise keystore and the peer DB. Without it the
     * native engine tries to call getFilesDir() on this object and crashes.
     */
    external fun nativeSetFilesDir(dir: String)

    /** Applies proxy roles. Safe to call while running, so roles can change live. */
    external fun nativeConfigureProxy(enableGateway: Boolean, enableClient: Boolean)

    init {
        System.loadLibrary("litep2p")
    }
}
