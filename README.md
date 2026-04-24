# sigsig

Async Python client for [Signal](https://signal.org/) with a Telethon-style event-driven API. **Not** a wrapper around `signal-cli` — sigsig talks to Signal's chat service directly over HTTPS + WebSocket.

```python
import asyncio
import sigsig
from sigsig import events

async def main():
    client = sigsig.Client()

    await client.qr_login(on_url=print)                      # first time: scan with a primary Signal device
    await client.save_session("~/.config/sigsig/secret.json")

    @client.on(events.TextMessage)
    async def on_text(msg: events.TextMessage) -> None:
        print(f"{msg.sender}: {msg.text}")
        await client.send_message(msg.sender, text=f"echo: {msg.text}")

    await client.run()

asyncio.run(main())
```

Re-login with a saved session — no QR scan required:

```python
client = await sigsig.Client.from_session("~/.config/sigsig/secret.json")
await client.send_message("aci:<uuid>", text="hi")
```

## Status

sigsig is **alpha** software. The happy-path 1-on-1 flow against Signal's mock server is exercised by the tests in `tests/integration/`. Compatibility with production Signal servers is currently limited by missing post-quantum handshake (PQXDH) and sealed-sender primitives — see [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) for the list and the path to closing the gaps via a libsignal Rust binding.

## Installation

sigsig uses [uv](https://github.com/astral-sh/uv).

```sh
git clone <this repo>
cd sigsig
uv sync --extra test --extra dev
./scripts/gen_proto.sh           # generate protobuf stubs
uv run pytest                    # 39 tests should pass
```

## CLI

```
uv run sigsig --help

  link          # scan-to-link: prints a QR, saves the session on success
  info          # dump the fields of a saved session
  send          # one-shot: send a text to a ServiceId
  listen        # open the WebSocket, log inbound events (--auto-reply for echo mode)
  render-qr     # debugging helper: render any URL as an ASCII QR
```

Typical first run:

```sh
uv run sigsig link --device-name "my-python-bot"
uv run sigsig listen --auto-reply -v
```

## Design

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design doc. A very short tour:

```
sigsig/
├── crypto/               pure-Python Curve25519, HKDF, AES, ProvisioningCipher,
│                         Double Ratchet, UAK derivation
├── session/              SessionFile (pydantic) + InMemoryProtocolStore
├── transport/            httpx HTTP client + websockets WS framing
├── keys/                 prekey / signed-prekey / Kyber-placeholder generation
├── provisioning/         QR URL, ASCII render, full link-device flow
├── send.py               send_text_message + PreKeyBundle bootstrap
├── receive.py            WS loop + envelope → event dispatch
├── events.py             TextMessage / Receipt / Typing / SelfSent / …
├── handlers.py           decorator registry
├── client.py             the public `Client` orchestrator
└── cli.py                typer-powered CLI
```

## Not yet supported

- Post-quantum handshake (PQXDH / Kyber1024) — needed against current Signal servers.
- Sealed-sender delivery (unidentified access) — sealed-sender-encrypted envelopes are emitted as `events.UnknownMessage`.
- Groups V2 (zkgroup).
- Attachments (upload to CDN2/CDN3).
- CDSI phone-number lookup — recipients must be addressed by `aci:<uuid>` today.
- Multi-device recipient fanout — sigsig currently targets `deviceId=1`.

Each of these has a clean extension point in the code; see [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md).

## License

AGPL-3.0-only (same as signal-cli).
