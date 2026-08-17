# Censorship Resistance (Overlay, Phase B)

LiteP2P's overlay (LPX2) routes application messages through sealed relay hops
so no single relay can link a message to its origin. Since **0.3.0**, the
censorship-resistance layer is **secure by default**: every protection ships
enabled and each knob is an *opt-out*, never an opt-in. The only exception is
the relay role itself, which stays opt-in.

## Defaults at a glance

| Knob (`overlay.*`) | Default | Effect |
|---|---|---|
| `obfuscate_transport` | `true` | Wrap every outgoing frame in an OBF1 envelope |
| `padding_bucket` | `128` | Pad frames to multiples of 128 bytes |
| `cover_interval_ms` | `30000` | Relay-role nodes emit cover frames when idle ≥ 30 s |
| `pex_interval_ms` | `60000` | Relay-list exchange (PEX) every 60 s |
| `require_origin_auth` | `true` | Drop overlay payloads without a valid Ed25519 signature |
| `relay_enabled` | `false` | Forwarding / mailbox hosting for others (**opt-in**) |
| `default_hops` | `2` | Sealed relay hops per path (0–3) |

Omit the entire `overlay` section from `config.json` to keep all secure
defaults.

## What each protection does

### Transport obfuscation (`obfuscate_transport`)

Every outgoing overlay frame is wrapped in an **OBF1** envelope:

```
[magic "OBF1"][sender_pk 32][nonce 24][pad_len u16]
[secretbox: XChaCha20-Poly1305 ciphertext + MAC][pad bytes]
```

The shared key is derived with X25519 (`crypto_box_beforenm`) between the
sender's static secret key and the receiver's static public key — the same
Noise NK static keys already exchanged by the engine, so no extra handshake is
needed. The `LPX2` magic never appears on the wire, defeating signature-based
DPI.

**Mixed-config interop:** the receive path detects envelopes **by magic, not
by configuration**. A node with obfuscation disabled still unwraps incoming
OBF1 frames, and a node with obfuscation enabled still accepts plain LPX2
frames. This is not a downgrade attack: OBF1 envelopes are AEAD-sealed to the
receiver's static key, and plain LPX2 frames still require a sealed hop
instruction addressed to the receiver before anything is processed.

### Length padding (`padding_bucket`)

Frames are padded to the next multiple of the bucket size with fresh random
bytes, so all frames from a node fall into a small set of sizes and real
message lengths are hidden from length-based traffic analysis. Relays re-pad
on forward so every hop stays in the same size distribution.

The default bucket of **128** is chosen so the worst case stays under the IPv6
minimum MTU:

```
1100 B max frame + 78 B OBF1 overhead = 1178 B  ->  padded to 1216 B < 1280 B
```

Overlay frames therefore never force IP fragmentation. Do not raise the bucket
above ~192 without re-checking that bound. `0` disables padding.

### Cover traffic (`cover_interval_ms`)

When a relay-role node has sent no real traffic for the configured interval,
it emits a sealed **cover frame** (`HopKind::Cover`, opened and discarded by
the receiver). Cover frames are indistinguishable from real frames to a
passive observer, obscuring silence/presence patterns.

**Cost model:** cover traffic is gated on the relay role. Default (non-relay)
mobile clients never emit cover frames, so enabling the interval by default
costs them nothing. `0` disables cover traffic.

### Relay peer exchange (`pex_interval_ms`)

Peers periodically exchange their known relay lists (unsealed — relay roles are
public routing metadata) and answer every relay advertisement with a PEX.
Relay knowledge spreads peer-to-peer with no central directory. `0` disables
periodic PEX (advertisements are still answered).

### Origin authentication (`require_origin_auth`)

Every overlay payload carries an Ed25519 signature made with the origin's
signing keypair. Nodes **auto-generate** their signing keypair at first start
and sign every payload, so enforcing signatures breaks no legitimate 0.3.0
traffic. With the default `require_origin_auth=true`:

- **Unsigned** payloads (pre-Phase-B senders) are dropped.
- Payloads whose signature does not verify are dropped.
- If a signing key is **registered** for the claimed origin
  (`litep2p_overlay_register_peer_signing_key` /
  `LiteP2P.registerPeerSigningKey`), the embedded signer must match it —
  upgrading integrity to **identity binding** (forged origin ids are dropped).

Set `require_origin_auth=false` only to interoperate with pre-Phase-B peers.

## Relay role (opt-in)

Forwarding frames and hosting mailboxes for other peers is **off by default**
(`relay_enabled=false`), matching the proxy-gateway policy. Origin and
destination roles need no opt-in — they only ever act for the local node.
Enable the relay role with `overlay.relay_enabled: true` in `config.json` or
`LiteP2P.setOverlayRelayEnabled(true)` at runtime.

## Relaxing the defaults (legacy interop)

All knobs remain configurable under the `overlay` object in `config.json`:

```json
"overlay": {
    "obfuscate_transport": false,
    "padding_bucket": 0,
    "cover_interval_ms": 0,
    "pex_interval_ms": 0,
    "require_origin_auth": false
}
```

This is only needed to talk to pre-0.3.0 peers and is **not recommended** for
new deployments. Note that relaxing `obfuscate_transport` on the send side
does not affect receiving: envelopes are always auto-detected.

## Observability

- The overlay router logs its effective censorship-resistance settings at
  startup (`OVL: overlay router started (relay=..., obfuscate=..., padding=...,
  cover_ms=..., pex_ms=..., origin_auth=...)`).
- `litep2p_overlay_stats()` / `LiteP2P.overlayStats()` expose counters
  including `obf_ok_total` / `obf_fail_total` (envelope unwrap success/failure)
  and `auth_fail_total` (dropped unsigned/mismatched payloads).
- Telemetry counters: `overlay_cover_tx_total`, `overlay_cover_rx_total`,
  `overlay_auth_fail_total`.

## Test coverage

`desktop/tests/overlay_test.cpp` pins the secure defaults and the interop
guarantees:

- Default-config pinning (obfuscation on, bucket 128, cover 30 s, PEX 60 s,
  origin auth on).
- Default config drops unsigned payloads; `require_origin_auth=false` restores
  legacy delivery.
- OBF1 frame → obfuscation-OFF receiver, and plain LPX2 frame →
  obfuscation-ON receiver (mixed-config interop in both directions).
- OBF1 envelope round-trip, wrong-key rejection, tamper rejection, and
  padding round-trip.

