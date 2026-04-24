# sigsig — limitations

sigsig is a **pure-Python** client (httpx + websockets + cryptography + PyNaCl). Some of what Signal does on the wire can't be implemented in pure Python without reimplementing libsignal's specialised cryptography; those parts are listed here, along with the remediation path.

## 1. Post-quantum X3DH (PQXDH / Kyber1024)

**What:** Signal switched its session-bootstrap handshake from X3DH to **PQXDH**, which mixes a [Kyber1024](https://pq-crystals.org/kyber/) KEM into the shared-secret derivation. A PreKeyBundle from a modern Signal server includes a `pqPreKey`, and the sender is expected to encapsulate against it.

**Why sigsig can't do it today:** there is no production-grade pure-Python Kyber1024 implementation. (Informational implementations exist but are not constant-time and are not audited for side channels.)

**What sigsig does instead:** `sigsig.keys.generate.generate_kyber_last_resort` emits a **placeholder** prekey with the right byte lengths and a sentinel `operational=False`. Linking to the server with this placeholder succeeds against sigsig's mock server (the mock doesn't run a real KEM), but a production Signal server may reject the account.

**Remediation:** wire a libsignal Rust binding (PyO3) that exposes `KeyPair::generate(KeyType::Kyber1024)` and `SessionBuilder::process_prekey_bundle`. See the README's "libsignal primitives" research for the list of APIs needed.

## 2. Sealed sender / unidentified delivery

**What:** Most modern Signal traffic is "sealed-sender": the envelope is encrypted under the recipient's profile key + identity key + a SenderCertificate, so the server never sees the sender's ACI. Envelope type is `UNIDENTIFIED_SENDER = 6`.

**Why sigsig can't do it today:** the sealed-sender envelope construction uses a specific ChaCha20-Poly1305 chain over HKDF-derived keys plus a SenderCertificate signed by the Signal server under a trust-root key sigsig currently only stores (it can't verify and can't use).

**What sigsig does instead:** `sigsig/crypto/sealed_sender.py` contains a `USE_LIBSIGNAL=False` flag and raises `SealedSenderUnavailable` if anything tries to route through it. The `receive.py` path surfaces sealed-sender envelopes as `events.UnknownMessage` so your handlers can log / ignore them.

**Remediation:** libsignal's `SealedSessionCipher` again — add the corresponding PyO3 binding.

## 3. Real XEd25519 signatures

**What:** Signal signs its signed-prekey records with **XEd25519**, which treats the X25519 private scalar as an Ed25519 signing scalar. Verifiers check the signature using only the recipient's X25519 identity public, without needing a separate Ed25519 pubkey.

**Why sigsig can't do it today:** implementing XEd25519 in pure Python requires direct Edwards-curve point arithmetic; PyNaCl only exposes the Ed25519 → X25519 direction.

**What sigsig does instead:** `PrivateKey.sign` produces a plain Ed25519 signature using the scalar as a seed. `PrivateKey.self_verify` round-trips it. A real Signal peer will **not** validate these signatures.

**Remediation:** swap in libsignal's `PrivateKey::calculate_signature` (again, via PyO3).

## 4. zkgroup — Groups V2 credentials, profile credentials, endorsements

**What:** Signal uses a zero-knowledge credential system (poksho-based) for group authentication and for profile ownership proofs. Every group message ride on top of an `AuthCredentialWithPni` and `GroupSendEndorsement`, neither of which we can construct without the zkgroup Rust implementation.

**Why sigsig can't do it today:** zkgroup involves custom elliptic-curve arithmetic, Ristretto255 operations, and non-interactive proof-of-knowledge protocols. Porting is a multi-month project.

**What sigsig does instead:** groups aren't implemented. `SenderKeyDistributionMessage` and `SenderKeyMessage` envelopes are exposed as `events.UnknownMessage`.

**Remediation:** use libsignal's `zkgroup` crate via PyO3. This is optional for 1-on-1 use cases.

## 5. CDSI (Contact Discovery Service v2)

**What:** Turning a phone number into a ServiceId requires a secure-enclave-hosted service (CDSI) that performs a private set intersection. Signal-Desktop talks to CDSI via a WebSocket-tunneled attestation protocol.

**Why sigsig can't do it today:** CDSI attestation validates an SGX enclave signature; this is not something we can fake and not trivial to reimplement.

**What sigsig does instead:** recipients must be identified by `aci:<uuid>` / `PNI:<uuid>` directly. `parse_recipient` accepts `+e164` inputs and returns them unchanged so higher layers can fail loudly.

**Remediation:** `libsignal::cdsi` plus a PyO3 binding. Alternatively — since CDSI primarily benefits humans doing one-off lookups — a CLI subcommand that reads a JSON contacts file would cover most automation use cases.

## 6. Storage service, backups, username linking

These are fully functional in signal-cli but outside the MVP scope of sigsig. Adding them is mostly new HTTP plumbing; no additional crypto primitives required beyond what we already have.

## 7. Message-level limitations

- **Attachments** — not implemented (upload flow goes through CDN2/CDN3, which needs a TUS-style flow).
- **Reactions / edits / quotes** — parsed as `DataMessage` fields but not surfaced as dedicated event types yet; show up inside `TextMessage` (body only) or `UnknownMessage`.
- **Self-sync send** — sigsig currently only sends to the target recipient, not to our own linked devices. The peer receives the message, but the user's other devices won't see it in their message history. A `SyncMessage.Sent` fan-out is tracked in the send-pipeline design.
- **Multi-device fanout** — sigsig only targets `deviceId=1`. `/v1/profile/{aci}` needs to be wired up before we can iterate over every active device.

## 8. What's under the line

Everything *not* on this page is considered functional for its documented scope:

- Provisioning linked-device flow — complete.
- Session save/load round-trip — complete.
- Double Ratchet 1-on-1 round-trip (sigsig ↔ sigsig) — complete, including out-of-order delivery.
- WebSocket framing (provisioning + authenticated) — complete.
- HTTP error mapping (409/410/428) — complete; retry logic is stubbed at the caller level.
- CLI — `link`, `info`, `send`, `listen`, `render-qr` all exercise the public API end-to-end.
