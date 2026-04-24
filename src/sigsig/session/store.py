"""Session store — wraps the libsignal :class:`SignalStore`.

Layer responsibilities:

- :class:`SigsigStore` is sigsig's Python-facing handle on the protocol
  state. It owns exactly one libsignal ``SignalStore`` (the ACI store),
  plus the small amount of metadata pydantic tracks in :class:`SessionFile`.
- Persistence is a round-trip through :meth:`SigsigStore.to_session_file` /
  :meth:`SigsigStore.from_session_file`.

All cryptographic operations (signing, session bootstrap, encrypt, decrypt)
go straight to the libsignal wrapper — there is no hand-rolled crypto left
under this abstraction.
"""

from __future__ import annotations

import os
import pathlib
from dataclasses import dataclass

from sigsig_libsignal._libsignal import (  # type: ignore[import-not-found]
    SignalStore,
    generate_identity_key_pair,
    generate_registration_id,
    identity_key_pair_from_raw,
)

from sigsig.session.state import SessionFile


@dataclass(slots=True)
class SigsigStore:
    """Owner of the libsignal ACI state + account metadata.

    Obtained either from a fresh link (``SigsigStore.fresh``) or from an
    existing session file (:func:`load_session_file`).
    """

    file: SessionFile
    aci_store: SignalStore
    # The libsignal serialization of our PNI identity keypair, kept so we
    # can regenerate PNI signed/kyber prekeys when the server asks us to.
    pni_identity_bytes: bytes

    # ------------------------------------------------------------------
    # factory
    # ------------------------------------------------------------------

    @classmethod
    def fresh(
        cls,
        *,
        number: str,
        aci: str,
        pni: str,
        device_id: int,
        password: str,
        aci_identity_bytes: bytes,
        aci_registration_id: int,
        pni_identity_bytes: bytes,
        profile_key: bytes | None = None,
        account_entropy_pool: str | None = None,
        media_root_backup_key: bytes | None = None,
    ) -> "SigsigStore":
        aci_store = SignalStore.from_identity(aci_identity_bytes, aci_registration_id)
        file = SessionFile(
            number=number,
            device_id=device_id,
            aci=aci,
            pni=pni,
            password=password,
            profile_key=profile_key,
            account_entropy_pool=account_entropy_pool,
            media_root_backup_key=media_root_backup_key,
            pni_identity_key_pair=pni_identity_bytes,
            signal_store_blob=aci_store.serialize(),
        )
        return cls(file=file, aci_store=aci_store, pni_identity_bytes=pni_identity_bytes)

    @classmethod
    def from_file(cls, file: SessionFile) -> "SigsigStore":
        aci_store = SignalStore.deserialize(file.signal_store_blob)
        return cls(file=file, aci_store=aci_store, pni_identity_bytes=file.pni_identity_key_pair)

    # ------------------------------------------------------------------
    # sync back to file
    # ------------------------------------------------------------------

    def snapshot(self) -> SessionFile:
        """Refresh :attr:`file.signal_store_blob` from the live ACI store."""
        self.file.signal_store_blob = self.aci_store.serialize()
        return self.file


# ---------------------------------------------------------------------------
# Thin re-exports so call sites can use module-level names.
# ---------------------------------------------------------------------------


def new_registration_id() -> int:
    return generate_registration_id()


def new_identity_key_pair() -> bytes:
    return generate_identity_key_pair()


def identity_from_raw(public: bytes, private: bytes) -> bytes:
    return identity_key_pair_from_raw(public, private)


def signal_store_from_raw_identity(
    public: bytes, private: bytes, registration_id: int
) -> SignalStore:
    return SignalStore.from_raw_identity(public, private, registration_id)


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------


def load_session_file(path: str) -> SessionFile:
    raw = pathlib.Path(path).expanduser().read_text()
    return SessionFile.from_json(raw)


def save_session_file(path: str, session: SessionFile) -> None:
    p = pathlib.Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(session.to_json())
    os.chmod(tmp, 0o600)
    tmp.replace(p)
