"""High-level attachment upload + download on top of
:mod:`sigsig.attachments` crypto and :mod:`sigsig.transport.cdn` HTTP.

Outbound ``Attachment`` → ``AttachmentPointer`` protobuf ready to drop
into a ``DataMessage``.
"""

from __future__ import annotations

from dataclasses import dataclass

from sigsig._proto import SignalService_pb2 as svc_pb
from sigsig.attachments import (
    Attachment,
    AttachmentDownloader,
    InboundAttachment,
    decrypt_attachment,
    encrypt_attachment,
)
from sigsig.errors import ProtocolError
from sigsig.transport import cdn
from sigsig.transport.http import HttpClient


@dataclass(slots=True)
class UploadForm:
    cdn: int
    key: str
    headers: dict[str, str]
    signed_upload_location: str


async def fetch_upload_form(http: HttpClient, *, upload_length: int) -> UploadForm:
    resp = await http.get(
        "/v4/attachments/form/upload", params={"uploadLength": upload_length}
    )
    body = resp.json()
    return UploadForm(
        cdn=int(body["cdn"]),
        key=str(body["key"]),
        headers={str(k): str(v) for k, v in body.get("headers", {}).items()},
        signed_upload_location=str(body["signedUploadLocation"]),
    )


async def upload_attachment(
    *, http: HttpClient, attachment: Attachment
) -> svc_pb.AttachmentPointer:
    blob, key, digest = encrypt_attachment(attachment.data)
    form = await fetch_upload_form(http, upload_length=len(blob))
    if form.cdn != 3:
        raise ProtocolError(
            f"sigsig only supports CDN3 uploads for now; server returned cdn={form.cdn}"
        )
    await cdn.upload_cdn3(
        signed_upload_url=form.signed_upload_location,
        upload_headers=form.headers,
        body=blob,
    )

    ap = svc_pb.AttachmentPointer()
    ap.cdnKey = form.key
    ap.cdnNumber = form.cdn
    ap.contentType = attachment.content_type
    ap.key = key
    ap.digest = digest
    ap.size = len(attachment.data)
    if attachment.file_name:
        ap.fileName = attachment.file_name
    if attachment.caption:
        ap.caption = attachment.caption
    if attachment.width:
        ap.width = attachment.width
    if attachment.height:
        ap.height = attachment.height
    return ap


class SignalAttachmentDownloader(AttachmentDownloader):
    async def download(self, att: InboundAttachment) -> bytes:
        blob = await cdn.download(att.cdn_number, att.cdn_key)
        return decrypt_attachment(blob, att.key, att.digest, att.size)


def inbound_from_pointer(ap: svc_pb.AttachmentPointer) -> InboundAttachment:
    return InboundAttachment(
        cdn_key=ap.cdnKey,
        cdn_number=ap.cdnNumber,
        key=bytes(ap.key),
        digest=bytes(ap.digest),
        size=ap.size,
        content_type=ap.contentType or "application/octet-stream",
        file_name=ap.fileName or None,
        caption=ap.caption or None,
        width=ap.width or 0,
        height=ap.height or 0,
        _downloader=SignalAttachmentDownloader(),
    )
