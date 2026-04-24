# sigsig — architecture

This document is the tour you should take if you want to understand how sigsig fits together before changing anything non-trivial. It maps the public API down to the wire and calls out the places where real Signal compatibility requires more work.

## High-level view

```
   ┌──────────────────────────────────────────────────────┐
   │                  public: sigsig.Client                │
   │                                                      │
   │  qr_login()      send_message()       run()          │
   │  load_session()  save_session()       on(Event)      │
   └───────┬──────────────────────────────┬───────────────┘
           │                              │
           ▼                              ▼
   ┌─────────────────┐         ┌──────────────────────┐
   │ provisioning.   │         │     send / receive   │
   │    flow         │         │                      │
   └───┬──────────┬──┘         └───────┬───────┬──────┘
       │          │                    │       │
       ▼          ▼                    ▼       ▼
   ┌───────┐  ┌──────────┐      ┌──────────┐ ┌──────────────┐
   │ keys  │  │ transport│      │ crypto.  │ │ session.store│
   │       │  │  http/ws │      │ double_  │ │ (protocol    │
   │       │  │          │      │ ratchet  │ │  store)      │
   └───┬───┘  └─────┬────┘      └──────────┘ └──────────────┘
       │            │
       ▼            ▼
   ┌──────────────────────────────┐
   │      crypto primitives        │
   │  curve25519, HKDF, AES, UAK,  │
   │  provisioning_cipher           │
   └──────────────────────────────┘
```

Every arrow is an internal module boundary. The public API (`Client`, `events`, error types) is the only surface the user should depend on; anything under `sigsig.*` without a re-export in `sigsig/__init__.py` is free to change.

## Module responsibilities

| Module | Responsibility |
|---|---|
| `sigsig.client` | The orchestrator. Owns the `HttpClient`, the `ProtocolStore`, the session state, and the event handler registry. |
| `sigsig.events` | Dataclasses (`TextMessage`, `Receipt`, `Typing`, `SelfSent`, `UnknownMessage`, `DecryptionError`) dispatched to user handlers. |
| `sigsig.handlers` | Tiny event registry + `dispatch()` — one coroutine handler per event, per type, fan-out with exception containment. |
| `sigsig.provisioning.flow` | End-to-end QR linked-device sequence: WS handshake, `ProvisionEnvelope` decryption, local key generation, `PUT /v1/devices/link/{code}`. |
| `sigsig.provisioning.qr` | `sgnl://linkdevice?…` URL construction + ASCII QR rendering. |
| `sigsig.send` | `send_text_message` — session bootstrap via `PreKeyBundle`, Double Ratchet encrypt, `PUT /v1/messages/{serviceId}`. |
| `sigsig.receive` | WS read loop, `Envelope` parsing, decrypt → `Content` → `Event`. |
| `sigsig.keys.generate` / `keys.upload` | Prekey generation + upload-body shaping. |
| `sigsig.session.state` | `SessionFile` — the pydantic schema persisted to disk. |
| `sigsig.session.store` | `InMemoryProtocolStore` — the runtime analogue of libsignal's `SignalProtocolStore`. |
| `sigsig.transport.http` | httpx wrapper with Signal-aware auth, error mapping (409/410/428), and UAK header. |
| `sigsig.transport.ws` | `WebSocketMessage`-framed WS client, keepalive, REQUEST/RESPONSE matching. |
| `sigsig.crypto.*` | Pure-Python primitives. Everything here has a single responsibility and can be swapped for a Rust-backed binding later. |
| `sigsig._proto` | Generated protobuf stubs. Do not edit; regenerate via `scripts/gen_proto.sh`. |

## Wire format cheat-sheet

- **QR URL**: `sgnl://linkdevice?uuid={addr}&pub_key={b64_no_padding(0x05||pubkey32)}` (see `provisioning/qr.py`, signal-cli `DeviceLinkUrl.java:47`).
- **Provisioning envelope**: `0x01 || IV(16) || AES-256-CBC(ProvisionMessage) || HMAC-SHA256[:32]` under HKDF-derived keys (see `crypto/provisioning_cipher.py`).
- **Signal WebSocket**: `WebSocketMessage` protobuf (REQUEST/RESPONSE) on every frame; auth via query string (`?login={aci}.{deviceId}&password=…`).
- **Signal v3 message**: `version(1) || SignalMessage protobuf || truncated HMAC-SHA256(mac_key, …, 8 bytes)` (see `crypto/double_ratchet.py`).

## Key trust & identity

There is no Trust-on-First-Use dialog in sigsig; on first sight of a peer identity the store silently records it as `TRUSTED_UNVERIFIED`. If the peer's identity key rotates, `InMemoryProtocolStore.trust_peer_identity` returns `False` and the caller (send/receive) is expected to react — right now this surfaces as a `DecryptionError` event. Building a proper trust workflow (safety numbers, verification UI) is future work.

## Session persistence

A session file is JSON with base64-encoded binary. The top-level `SessionFile` model (in `session/state.py`) captures everything a linked device needs to resume operation: ACI/PNI identities, registration IDs, password, profile key, prekey bookkeeping, and serialised per-peer ratchet state. The file should be `chmod 600`; `save_session_file` writes atomically (`.tmp` + rename) and sets the mode for you.

Swap-out path: `SessionFile.protocol_store_path` is reserved for pointing at a SQLite sidecar once we need to scale beyond "a few contacts / a few hundred messages" without keeping the whole ratchet state in memory.

## Test pyramid

- **`tests/unit/`** — deterministic, no network. Exercises every pure-Python crypto primitive with KAT-style assertions plus round-trips (provisioning cipher, Double Ratchet in-order and out-of-order, sign/self-verify, UAK, protobuf framing, session-file (de)serialisation, envelope dispatch).
- **`tests/integration/`** — drives the real `Client` against `tests/fixtures/mock_signal_server.py` (aiohttp). Covers the full QR link flow, session save-and-reuse, HTTP send including PreKeyBundle bootstrap, and WS-delivered receive.
- **`tests/e2e/`** (reserved; not yet created) — opt-in tests against a real Signal server. These are the ones that will fail today without a libsignal binding.

## Design decisions & non-decisions

- **Pydantic for the session schema.** Keeps the JSON contract self-documenting and validated. Pydantic is already used by so many packages in the async ecosystem that bringing it in costs nothing extra.
- **httpx over aiohttp for the HTTP client.** httpx's modern API and transport-injection support make it trivial to test without spinning up a real server (used in `tests/integration/`).
- **websockets package rather than aiohttp WS.** Fewer moving parts — the mock server uses aiohttp only because it's easier on the server side.
- **No Rust code today.** This means no PQXDH, no real sealed sender, and no zkgroup. The gap is spelled out in [`LIMITATIONS.md`](LIMITATIONS.md). The interfaces in `sigsig.crypto.*` are deliberately narrow so a PyO3 wrapper over libsignal can replace them without touching the layers above.
