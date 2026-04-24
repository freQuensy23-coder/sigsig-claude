import base64
import re
import urllib.parse

from sigsig.crypto.curve25519 import KeyPair
from sigsig.provisioning.qr import build_link_url, render_qr_ascii


def test_url_format() -> None:
    kp = KeyPair.generate()
    url = build_link_url(session_uuid="abc-123==", public_key=kp.public)
    assert url.startswith("sgnl://linkdevice?")
    # Match signal-cli: values are URL-encoded with URLEncoder.encode.
    params = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert params["uuid"] == ["abc-123=="]

    pub_param = params["pub_key"][0]
    assert not pub_param.endswith("=")  # padding stripped
    pad = "=" * (-len(pub_param) % 4)
    decoded = base64.b64decode(pub_param + pad)
    assert decoded == kp.public.serialize()


def test_url_percent_encodes_reserved_chars() -> None:
    # "==" in the uuid must appear as %3D%3D in the raw URL.
    kp = KeyPair.generate()
    raw = build_link_url(session_uuid="xyz==", public_key=kp.public)
    assert "uuid=xyz%3D%3D" in raw


def test_render_qr_is_square_text() -> None:
    kp = KeyPair.generate()
    url = build_link_url(session_uuid="x", public_key=kp.public)
    rendered = render_qr_ascii(url)
    lines = rendered.splitlines()
    assert len(lines) > 8
    assert len({len(line) for line in lines}) == 1
