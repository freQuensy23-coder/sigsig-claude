"""Minimal Groups V2 support.

The caller supplies the group master key (32 bytes) and the ACIs of the
members to send to. sigsig encrypts one ``DataMessage`` containing a
``GroupContextV2{masterKey, revision}`` and PUTs it per-member — the same
fan-out path 1:1 DMs use, just repeated.

Receive side: inbound DataMessages carrying ``groupV2`` are emitted as
:class:`sigsig.events.GroupTextMessage` with ``group_master_key`` set, so
handlers can key off it.

Out of scope (use libsignal's zkgroup/GroupCipher path for these):
- auto-discovery of group membership from the Signal server
- invite links / revisions beyond whatever the caller supplies
- SenderKey distribution + ``/v1/messages/multi_recipient`` (efficient fanout)
- admin / permission changes
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sigsig.types import ServiceId


GROUP_MASTER_KEY_LENGTH = 32


@dataclass(frozen=True, slots=True)
class Group:
    """A Signal Groups V2 group, identified by its master key.

    ``members`` is the list of ACIs sigsig will fan out to on send. You must
    keep it in sync with the actual group membership — there is no
    server-side check that stops you from sending to somebody who was kicked,
    but their client will silently drop the message.
    """

    master_key: bytes
    members: tuple[ServiceId, ...] = ()
    revision: int = 0

    def __post_init__(self) -> None:
        if len(self.master_key) != GROUP_MASTER_KEY_LENGTH:
            raise ValueError(
                f"group master_key must be {GROUP_MASTER_KEY_LENGTH} bytes, got {len(self.master_key)}"
            )

    @classmethod
    def from_hex(cls, master_key_hex: str, members: list[ServiceId], revision: int = 0) -> "Group":
        return cls(
            master_key=bytes.fromhex(master_key_hex),
            members=tuple(members),
            revision=revision,
        )

    @property
    def master_key_hex(self) -> str:
        return self.master_key.hex()
