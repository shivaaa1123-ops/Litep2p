# Network OS — E2E Payload Encryption Key Model (Phase 3, Step 3.4)

**Master doc refs:** §4 (opaque payload), §19.4 (per-recipient content keys),
§29 (anti-abuse / verify-before-work). Locked decision #4.

> A storage/relay peer sees only ciphertext + envelope metadata — never
> plaintext, and never a key that lets it read the payload. Only the origin
> and the intended recipients can decrypt.

*(Note: this doc is `11-…` rather than `09-…` because the P0 freeze mapped
`09-` to `delivery-path-map.md`.)*

## 1. Model overview

Per-object **random 256-bit content key** (ephemeral), one key per object.
The payload is encrypted with that key using the engine's own AEAD
(XChaCha20-Poly1305 via the bundled cipher — never ad-hoc crypto). The
content key is then **wrapped** for every legitimate reader (origin + each
intended recipient) with that reader's public key using
`crypto_box_seal` (libsodium). Wrappers travel inside the envelope's
`recipient_keys` section (`recipient PeerID → wrapped content key`).

```
object_payload_bytes
      │  XChaCha20-Poly1305(content_key, payload)
      ▼
ciphertext ──────────────────────────────────────────┐  stored/forwarded as-is │
content_key (32B random)                              │                       │
      │                                               │                       │
      ├─ crypto_box_seal(content_key, pk_recipientA) ─┤→ recipient_keys[A]
      ├─ crypto_box_seal(content_key, pk_recipientB) ─┤→ recipient_keys[B]
      └─ crypto_box_seal(content_key, pk_origin)    ──┘→ recipient_keys[origin]
```

## 2. Key properties

| Property | Mechanism |
|---|---|
| Per-object confidentiality | One random content key per object; never reused |
| Forward secrecy-ish | Content key is ephemeral; compromise of a later object leaks nothing about earlier ones |
| Reader-addressed | Only readers with a wrapped key can decrypt; relay/storage peers have none |
| Tamper detection | AEAD tag (Poly1305) + envelope `payload_hash` pre-check before signature verify |
| No metadata leak | Storage sees `namespace_id`, size, hashes — not plaintext or key material |

## 3. Where keys live

- **Content key:** in memory only, inside the E2E module; never persisted by
  the object store. It survives only in wrapped form inside `recipient_keys`.
- **Reader keypairs:** engine `crypto_box` keypairs, provisioned from the
  existing identity store (`IIdentityStore`). The engine's own identity keys
  are already durable (FileIdentityStore); per-recipient keys are their public
  parts exchanged through the normal peer-identity path.
- **Object store:** stores only `payload` (ciphertext) + `recipient_keys`
  blobs — both opaque to the store.

## 4. E2E flow (origin side)

1. `e2e_encrypt(payload, [recipient_pks..., origin_pk])`
   → generates `content_key`, encrypts payload, wraps key per recipient,
   returns `(ciphertext, wrapped_keys)`.
2. Caller sets `origin.security_flags |= 0x01` (payload E2E-encrypted),
   sets `payload_size`/`payload_hash` from the ciphertext.
3. `sign_object()` binds the origin signature over the header (incl. the hash
   of the ciphertext).

## 5. E2E flow (recipient side)

1. **Verify first, decrypt last (§29):** on receive, check `payload_hash`
   against `hash(payload)` and verify the Ed25519 origin signature BEFORE any
   expensive decryption work.
2. Look up own `PeerID → wrapped key` in `recipient_keys`; if absent → this
   object is not addressed to us; store opaque (relay behavior).
3. `crypto_box_seal_open(wrapped_key, own_secret)` → `content_key` →
   XChaCha20-Poly1305 decrypt → plaintext.

## 6. Invariant enforcement (asserted by tests)

- `object_envelope_test`: payload hash pre-check rejects flipped payload bytes;
  origin signature verification rejects any tamper of the signed header.
- `e2e_test` (Phase 3 suite): encrypt→decrypt round-trip for the origin and
  each recipient; wrong keypair fails to open; tampered ciphertext fails AEAD.

## 7. Out of scope (future phases)

- Group/multi-recipient policy beyond an explicit recipient list.
- Key rotation/revocation of wrapped keys (Phase 7 replication surface).
- Hardware-backed key storage (Android Keystore) — Phase 8.
