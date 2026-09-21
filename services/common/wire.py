"""Wire encoding helpers shared by all three services.

Everything on the wire is JSON; binary fields are base64 (standard alphabet,
with padding). Transcripts that get hashed or signed are built with `lp()` so
that concatenation is unambiguous.
"""

from __future__ import annotations

import base64
import struct

PROTOCOL = "wx-legacy/1"

HOP_DEVICE_GATEWAY = "device-gateway"
HOP_GATEWAY_CLOUD = "gateway-cloud"


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    """Strict base64 decode.

    Every input here comes off the wire, so a non-string (JSON null, a number,
    an object) is an expected hostile case, not a programming error. It must
    raise ValueError like any other bad encoding so that request handlers can
    catch one exception type and return a clean rejection -- an AttributeError
    escaping from here would surface as a 500.
    """
    if not isinstance(text, str):
        raise ValueError(f"expected a base64 string, got {type(text).__name__}")
    try:
        # validate=True so a caller cannot smuggle whitespace/garbage past us.
        return base64.b64decode(text.encode("ascii"), validate=True)
    except UnicodeEncodeError as exc:
        # Non-ASCII cannot be base64 either way.
        raise ValueError("base64 string contains non-ASCII characters") from exc


def lp(*parts: bytes) -> bytes:
    """Length-prefixed concatenation.

    Each part is emitted as a 4-byte big-endian length followed by the bytes.
    Without this, ("ab", "c") and ("a", "bc") would hash identically and a
    signature over one would verify over the other.
    """
    out = bytearray()
    for part in parts:
        if not isinstance(part, bytes):
            raise TypeError(f"lp() takes bytes, got {type(part).__name__}")
        out += struct.pack(">I", len(part))
        out += part
    return bytes(out)


def s(text: str) -> bytes:
    """UTF-8 encode a string for inclusion in an lp() transcript."""
    return text.encode("utf-8")


def counter_bytes(seq: int) -> bytes:
    """8-byte big-endian message counter, used in both the nonce and the AAD."""
    if seq < 0 or seq > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("sequence number out of range")
    return struct.pack(">Q", seq)
