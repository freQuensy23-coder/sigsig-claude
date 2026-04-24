"""``sigsig`` CLI — handy for manual testing.

Subcommands:

- ``sigsig link``     — run the QR flow, save session.
- ``sigsig info``     — inspect a saved session.
- ``sigsig send``     — send one text message to a recipient.
- ``sigsig listen``   — connect the authenticated WS and dump events.

The CLI is intentionally thin: every subcommand just calls into the
public :class:`sigsig.Client` API.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from typing import Annotated

import subprocess

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import sigsig
from sigsig.provisioning.qr import render_qr_ascii, save_qr_image

app = typer.Typer(
    help="Async Python client for Signal.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s: %(message)s",
    )


def _default_session_path() -> Path:
    return Path.home() / ".config" / "sigsig" / "secret.json"


@app.command()
def link(
    session: Annotated[
        Path, typer.Option(help="Where to save the linked session.")
    ] = _default_session_path(),
    device_name: Annotated[str, typer.Option(help="Name shown in the primary's devices list.")] = "sigsig",
    qr_file: Annotated[
        Path | None,
        typer.Option(
            "--qr-file",
            help="Also save the QR as an image here (.png/.jpg). "
            "Implies --qr-open. Useful when the terminal render is unscannable.",
        ),
    ] = None,
    qr_open: Annotated[
        bool,
        typer.Option(
            "--qr-open/--no-qr-open",
            help="Open the saved QR file with the OS default viewer.",
        ),
    ] = True,
    qr_invert: Annotated[
        bool,
        typer.Option(
            "--qr-invert",
            help="Invert the terminal QR colours (helpful on dark-theme terminals).",
        ),
    ] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Run the QR linked-device flow and save the resulting session to disk."""
    _configure_logging(verbose)

    async def _run() -> None:
        client = sigsig.Client()
        attempt = 0

        async def on_url(url: str) -> None:
            nonlocal attempt
            attempt += 1
            console.print(Panel.fit(url, title=f"scan with your primary device (attempt {attempt})", border_style="cyan"))
            console.print(render_qr_ascii(url, invert=qr_invert))
            if qr_file is not None:
                try:
                    save_qr_image(url, str(qr_file))
                except Exception as exc:  # noqa: BLE001
                    console.print(f"[yellow]could not save QR image:[/yellow] {exc}")
                else:
                    console.print(f"[green]QR image saved to[/green] {qr_file}")
                    if qr_open:
                        _open_file(qr_file)

        try:
            await client.qr_login(device_name=device_name, on_url=on_url)
        except sigsig.ProvisioningError as exc:
            console.print(f"[red]provisioning failed:[/red] {exc}")
            raise typer.Exit(1) from exc
        await client.save_session(str(session))
        console.print(f"[green]linked![/green] session saved to [bold]{session}[/bold]")

    asyncio.run(_run())


def _open_file(path: Path) -> None:
    """Best-effort 'open file in OS default viewer'."""
    try:
        if sys.platform == "darwin":
            subprocess.run(["open", str(path)], check=False)
        elif sys.platform.startswith("linux"):
            subprocess.run(["xdg-open", str(path)], check=False)
        elif sys.platform == "win32":
            subprocess.run(["cmd", "/c", "start", "", str(path)], check=False, shell=False)
    except Exception:  # noqa: BLE001
        pass


@app.command()
def info(
    session: Annotated[
        Path, typer.Option(help="Session file path.")
    ] = _default_session_path(),
) -> None:
    """Print a summary of a saved session file."""
    from sigsig.session.store import load_session_file

    try:
        s = load_session_file(str(session))
    except FileNotFoundError:
        console.print(f"[red]no session file at[/red] {session}")
        raise typer.Exit(1) from None

    table = Table(title=f"session {session}", show_header=False, title_style="bold")
    table.add_column("field", style="cyan")
    table.add_column("value")
    table.add_row("number", s.number)
    table.add_row("ACI", s.aci)
    table.add_row("PNI", s.pni or "-")
    table.add_row("device id", str(s.device_id))
    table.add_row("environment", s.environment)
    table.add_row("peers known", str(len(s.peers)))
    table.add_row("sessions cached", str(len(s.sessions)))
    table.add_row("ACI signed prekeys", str(len(s.aci_account.signed_pre_keys)))
    table.add_row("ACI one-time prekeys", str(len(s.aci_account.one_time_pre_keys)))
    console.print(table)


@app.command()
def send(
    recipient: Annotated[str, typer.Argument(help="aci:<uuid>, PNI:<uuid>, or +e164 (requires CDSI, not yet wired).")],
    message: Annotated[str, typer.Argument(help="Message body.")],
    session: Annotated[Path, typer.Option(help="Session file path.")] = _default_session_path(),
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Send a single text message."""
    _configure_logging(verbose)

    async def _run() -> None:
        client = await sigsig.Client.from_session(str(session))
        try:
            result = await client.send_message(recipient, text=message)
            console.print(
                f"[green]sent[/green] ts={result.timestamp_ms} "
                f"resp={result.server_response}"
            )
        finally:
            await client.save_session(str(session))
            await client.aclose()

    try:
        asyncio.run(_run())
    except sigsig.SigsigError as exc:
        console.print(f"[red]{type(exc).__name__}:[/red] {exc}")
        raise typer.Exit(1) from exc


@app.command()
def listen(
    session: Annotated[Path, typer.Option(help="Session file path.")] = _default_session_path(),
    auto_reply: Annotated[bool, typer.Option(help="Echo every inbound text back.")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Open the authenticated WebSocket and print incoming events."""
    _configure_logging(verbose)

    async def _run() -> None:
        client = await sigsig.Client.from_session(str(session))

        @client.on(sigsig.events.TextMessage)
        async def on_text(msg: sigsig.events.TextMessage) -> None:
            console.print(
                f"[cyan]{msg.sender}[/cyan]/{msg.sender_device} "
                f"[dim]({msg.timestamp_ms})[/dim]: {msg.text}"
            )
            if auto_reply:
                try:
                    await client.send_message(msg.sender, text=f"echo: {msg.text}")
                except sigsig.SigsigError as exc:
                    console.print(f"[red]failed to reply:[/red] {exc}")

        @client.on(sigsig.events.GroupTextMessage)
        async def on_group(msg: sigsig.events.GroupTextMessage) -> None:
            console.print(
                f"[magenta]group {msg.group_master_key.hex()}[/magenta] "
                f"[cyan]{msg.sender}[/cyan]/{msg.sender_device}: {msg.text}"
            )

        @client.on(sigsig.events.Receipt)
        async def on_receipt(r: sigsig.events.Receipt) -> None:
            console.print(
                f"[dim]receipt[/dim] {r.kind} from {r.sender}/{r.sender_device} "
                f"for ts={list(r.referenced_timestamps)}"
            )

        @client.on(sigsig.events.DecryptionError)
        async def on_fail(d: sigsig.events.DecryptionError) -> None:
            console.print(f"[yellow]decryption error[/yellow] type={d.envelope_type} err={d.error}")

        console.print(f"[dim]listening as[/dim] {client.aci}.{client.device_id} …")
        try:
            await client.run()
        finally:
            await client.save_session(str(session))
            await client.aclose()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("\n[dim]stopped[/dim]")


@app.command(name="render-qr")
def render_qr(
    url: Annotated[str, typer.Argument(help="An sgnl://linkdevice URL to render.")],
) -> None:
    """Render an arbitrary URL as an ASCII QR (debugging helper)."""
    console.print(render_qr_ascii(url))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
