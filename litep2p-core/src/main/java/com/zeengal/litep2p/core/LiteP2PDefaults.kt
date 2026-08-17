package com.zeengal.litep2p.core

import android.content.Context
import android.util.Log
import java.io.File
import java.util.UUID

/**
 * Internal first-run defaults for the SDK runtime (Feature 4, ask.md §4).
 *
 * Two jobs, both idempotent and safe to call repeatedly:
 *
 *  1. **Default config.json** — the AAR bundles `litep2p_default_config.json`
 *     in its assets. On first run (no `config.json` under [Context.getFilesDir])
 *     it is extracted to `filesDir/litep2p_default_config.json` and returned as
 *     the config path. An integrator-supplied `config.json` (or an explicit
 *     [LiteP2PConfig.configPath]) always wins; the SDK never overwrites either.
 *
 *     Unlike a naive extract-once scheme, the extracted copy is **content-hash
 *     stamped**: whenever the bundled default changes in a new SDK build (e.g.
 *     a new shared transport key or a new network.port_range), the stale
 *     extracted copy is replaced automatically on the next start. This keeps
 *     long-lived installs from pinning first-install defaults forever.
 *
 *  2. **Stable peer id** — generated once and persisted in the SDK's own
 *     SharedPreferences so the device keeps the same identity across restarts
 *     (mirrors the harness [PeerIdManager] pattern without depending on it).
 *
 * The transport-key footgun (ask.md honorable mention) is handled natively:
 * the bundled default config ships a fixed `security.transport_key`, so two
 * devices that both use the SDK defaults share the same key out of the box.
 * The native engine additionally falls back to a device-local key file when
 * none is configured (see crypto_utils.cpp).
 */
internal object LiteP2PDefaults {

    private const val TAG = "LiteP2PDefaults"

    private const val ASSET_CONFIG = "litep2p_default_config.json"
    private const val EXTRACTED_CONFIG = "litep2p_default_config.json"
    private const val EXTRACTED_HASH_FILE = "litep2p_default_config.sha256"
    private const val USER_CONFIG = "config.json"

    private const val PREFS_NAME = "litep2p_sdk_prefs"
    private const val KEY_PEER_ID = "peer_id"

    /**
     * Returns a stable peer id for this device, generating and persisting one
     * on first call.
     */
    fun getOrCreatePeerId(context: Context): String {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.getString(KEY_PEER_ID, null)?.let { return it }
        val id = UUID.randomUUID().toString()
        prefs.edit().putString(KEY_PEER_ID, id).apply()
        Log.i(TAG, "Generated new peer id: $id")
        return id
    }

    /**
     * Resolves the config path to hand to [LiteP2PConfig.Builder.configPath].
     *
     * Priority:
     *  1. [explicitPath] when non-null and readable (integrator override).
     *  2. `filesDir/config.json` when present (integrator-provided default).
     *  3. The bundled SDK default, extracted to
     *     `filesDir/litep2p_default_config.json` and content-hash refreshed
     *     whenever the bundled copy changes (so SDK upgrades reach devices
     *     whose first install was an older AAR).
     *
     * Returns null only when the asset extraction fails; the engine then runs
     * on its compiled-in defaults.
     */
    fun resolveConfigPath(context: Context, explicitPath: String?): String? {
        if (!explicitPath.isNullOrBlank() && File(explicitPath).canRead()) {
            return explicitPath
        }

        val filesDir = context.filesDir
        val userConfig = File(filesDir, USER_CONFIG)
        if (userConfig.canRead()) {
            return userConfig.absolutePath
        }

        // (Re)extract the SDK-managed default only when it is missing or when
        // its stored content hash differs from the bundled asset (stale copy
        // from an older AAR). The integrator's own files never get touched.
        val extracted = File(filesDir, EXTRACTED_CONFIG)
        val hashFile = File(filesDir, EXTRACTED_HASH_FILE)
        val bundledHash = try { sha256(context.assets.open(ASSET_CONFIG).use { it.readBytes() }) } catch (t: Throwable) { null }
        if (bundledHash == null) {
            // Asset unreadable; fall back to whatever is on disk.
            return if (extracted.canRead()) extracted.absolutePath else null
        }

        val stale = !extracted.canRead() ||
            (hashFile.canRead() && hashFile.readText().trim() != bundledHash) ||
            (!hashFile.canRead() && extracted.length() > 0 && extracted.readText().trim() != assetConfigOrNull(context))
        if (stale) {
            try {
                context.assets.open(ASSET_CONFIG).use { input ->
                    extracted.outputStream().use { output -> input.copyTo(output) }
                }
                hashFile.writeText(bundledHash)
                Log.i(TAG, "Extracted/refreshed default config to ${extracted.absolutePath}")
            } catch (t: Throwable) {
                Log.w(TAG, "Failed to (re)extract default config: ${t.message}")
            }
        }
        return if (extracted.canRead()) extracted.absolutePath else null
    }

    private fun assetConfigOrNull(context: Context): String? = try {
        context.assets.open(ASSET_CONFIG).use { it.bufferedReader().readText() }
    } catch (t: Throwable) {
        null
    }

    private fun sha256(bytes: ByteArray): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }
}
