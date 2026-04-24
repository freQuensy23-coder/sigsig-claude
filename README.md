# sigsig

Async Python client for [Signal](https://signal.org/). Talks to Signal's servers directly — no `signal-cli` wrapper, no daemon. libsignal-backed crypto (X3DH + PQXDH, Double Ratchet, Kyber1024, sealed sender) via a PyO3 extension, so everything under the covers is Signal's own audited Rust.

```python
import asyncio, sigsig
from sigsig import events

async def main():
    client = sigsig.Client()

    # First time: scan the QR code with Signal on your phone
    # (Settings → Linked Devices → +).
    await client.qr_login(on_url=print)
    await client.save_session("~/.config/sigsig/secret.json")

    @client.on(events.TextMessage)
    async def on_text(msg):
        print(f"{msg.sender}: {msg.text}")
        await client.send_message(msg.sender, text=f"echo: {msg.text}")

    await client.run()

asyncio.run(main())
```

## Install

```sh
git clone https://github.com/freQuensy23-coder/sigsig-claude.git
cd sigsig-claude
uv sync
./scripts/gen_proto.sh   # one-time: generate the protobuf stubs
```

`uv sync` compiles the Rust extension via `maturin` the first time you run it (~30 s cold). Requirements: `uv`, Rust 1.88+, `protoc`.

## First run: link a device

Either via the CLI:

```sh
uv run sigsig link --session ~/.config/sigsig/secret.json --qr-file /tmp/uuid.jpg
```

Scan the QR in your terminal (or the PNG in `/tmp/uuid.jpg`) from **Signal → Settings → Linked Devices → +**. On success the session file is written with `chmod 600`. You never scan again — subsequent runs load from this file.

Or programmatically:

```python
client = sigsig.Client()
await client.qr_login(on_url=print)           # prints sgnl:// URL; render however you like
await client.save_session(path)
```

## Reusing a saved session

```python
client = await sigsig.Client.from_session("~/.config/sigsig/secret.json")
```

## Sending a direct message

```python
await client.send_message("aci:<recipient-uuid>", text="hi")
```

Recipient accepts:
- `sigsig.ServiceId` instance
- `"aci:<uuid>"` / `"PNI:<uuid>"` strings
- bare UUID (treated as ACI)

**sigsig doesn't resolve phone numbers to ACIs** (no CDSI client). Either keep ACIs you learn from incoming messages or harvest them from Signal-Desktop's SQLite.

## Sending to a group

If you know the group's `master_key` (32 bytes) you can fetch the member list from the server via zkgroup:

```python
master_key = bytes.fromhex("bc54159b…")         # from a received GroupTextMessage
group = await client.fetch_group_members(master_key)
await client.send_message(group, text="hello group")
```

`fetch_group_members` talks to `/v2/groups/` on storage.signal.org with a zkgroup AuthCredentialPresentation — same path the official clients use. Requires the current account to be a member.

Or construct the group manually if you already know the members:

```python
from sigsig import Group, ServiceId

group = Group(
    master_key=bytes.fromhex("bc54159b…"),
    members=(
        ServiceId.parse("aci:11111111-..."),
        ServiceId.parse("aci:22222222-..."),
    ),
    revision=0,
)
await client.send_message(group, text="hello group")
```

sigsig fans the same encrypted `DataMessage` (with `groupV2 = {masterKey, revision}`) out to every member's ACI.

## Attachments (images, files)

Send from disk:

```python
from sigsig import Attachment

await client.send_message(
    recipient,
    text="here's the photo",
    attachments=[Attachment.from_file("~/Pictures/cat.jpg")],
)
```

Or from in-memory bytes:

```python
import io
from PIL import Image

buf = io.BytesIO()
Image.new("RGB", (256, 256), (220, 50, 50)).save(buf, format="PNG")

await client.send_message(
    recipient,
    text="red square",
    attachments=[
        Attachment.from_bytes(buf.getvalue(), content_type="image/png", file_name="red.png"),
    ],
)
```

Receive side — `msg.attachments` is a tuple of `InboundAttachment`; each one lazily downloads and decrypts when you `await` it:

```python
from pathlib import Path

@client.on(events.TextMessage)
async def on_text(msg):
    for att in msg.attachments:
        data = await att.download()   # CDN fetch + digest + HMAC + AES-CBC
        (Path("./inbox") / (att.file_name or "attachment")).write_bytes(data)
```

Protocol: AES-256-CBC + HMAC-SHA256 encryption client-side with a random 64-byte key (32 AES + 32 HMAC), uploaded to Signal's CDN3 over the TUS "creation-with-upload" flow, referenced from the `DataMessage` via an `AttachmentPointer`. Recipients fetch the encrypted blob, verify SHA-256 digest + HMAC, then decrypt. The 64-byte key + digest both ride inside the sealed-sender envelope, so only the intended recipient(s) can decrypt.

### Where does `master_key` come from?

Signal doesn't expose the master_key in the app UI. You get it one of these ways:

- **From any received `GroupTextMessage`** — `msg.group_master_key` is the 32-byte master key. Send one test message in the group from your phone and capture it from the listener.
- **From the group's invite link** (`https://signal.group/#…`) — the link encodes `master_key || invite_password` (not yet supported in sigsig).
- **From Signal-Desktop's SQLite DB** — if you have access to the primary's SQLite, groups are in the `groups` table.

## Receiving messages — event handlers

```python
from sigsig import events

@client.on(events.TextMessage)
async def on_text(msg: events.TextMessage):
    print(f"{msg.sender}/{msg.sender_device}: {msg.text}")

@client.on(events.GroupTextMessage)
async def on_group(msg: events.GroupTextMessage):
    print(f"[{msg.group_master_key.hex()[:8]}…] {msg.sender}: {msg.text}")

@client.on(events.Receipt)
async def on_receipt(r: events.Receipt):
    print(f"{r.kind} receipt from {r.sender} for {list(r.referenced_timestamps)}")

await client.run()     # blocks; Ctrl-C to stop
```

Event types (`from sigsig import events`):

| Event | When it fires |
|---|---|
| `TextMessage` | 1:1 DataMessage with text body |
| `GroupTextMessage` | DataMessage carrying `groupV2` |
| `Receipt` | Delivery / read / viewed receipt |
| `Typing` | Typing indicator start/stop |
| `SelfSent` | SyncMessage.Sent from your own primary |
| `UnknownMessage` | Anything sigsig doesn't special-case |
| `DecryptionError` | Decrypt failed for a specific envelope |

Handlers can be sync or `async`. Register as many as you want per event type; they run in registration order. An exception in one doesn't stop the others.

## CLI reference

```
uv run sigsig --help

  link          Scan QR and write a session file
  info          Print a summary of a saved session
  send          One-shot: send a text to an ACI
  listen        Open the auth WebSocket and print events (`--auto-reply` echoes DMs)
  render-qr     Render any URL as an ASCII QR (debugging)
```

Flags worth knowing:

- `--session PATH` — where to read/write the session (default `~/.config/sigsig/secret.json`).
- `sigsig link --qr-file /tmp/uuid.png` — also write the QR as a PNG/JPG and open it in the OS default viewer.
- `sigsig listen --verbose` — dump the raw websocket traffic alongside events.

## Errors

All exceptions derive from `sigsig.SigsigError`:

```python
try:
    await client.send_message("aci:...", text="hi")
except sigsig.MismatchedDevices as exc:
    # recipient's device list changed; refetch and retry
except sigsig.StaleDevices as exc:
    # some of our sessions are stale; drop them and retry
except sigsig.AuthenticationFailed:
    # session expired / revoked from the other side
```

See [`src/sigsig/errors.py`](src/sigsig/errors.py).

## What's supported

✅ 1:1 text message send + receive (sealed sender on inbound)
✅ Groups V2 text message send + receive
✅ Group member list fetch via zkgroup (`client.fetch_group_members`)
✅ Attachments (images, files) — CDN3 upload + download + decrypt
✅ Delivery / read / viewed receipts, typing indicators
✅ QR linked-device provisioning
✅ Session persistence (JSON + libsignal opaque blob)
✅ Multi-device fanout on send
✅ Key rotation / PreKeyBundle bootstrap

## What's NOT supported (yet)

- **Phone-number recipients** — no CDSI client, so no `+e164 → ACI` lookup. Use `aci:<uuid>` directly.
- **Group list** — you still need the `master_key` to fetch a group; we don't enumerate "groups the user is in" (needs Storage Service + contacts sync).
- **Group invite links** — parsing `https://signal.group/#…` URLs and joining isn't implemented.
- **Group admin operations** — creating / renaming / adding members / removing members / re-keying.
- **SenderKey multi-recipient fanout** — group sends use per-member individual encryption (the slower legacy path).
- **Self-sync on send** — sent messages don't appear in your own phone's chat UI (we skip the `SyncMessage.Sent` to our primary).
- **Stories, calls, payments, usernames, safety numbers**.

See [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) for which libsignal primitive each gap maps to.

## License

AGPL-3.0-only (same as signal-cli and libsignal).
