"""Load-or-create persistence for long-term keys.

Keys live on a mounted volume so that a restarted node keeps its identity and
previously captured traffic stays relevant to the attacker demonstration. They
are stored unencrypted, which is a deliberate simplification: the threat model
here is a network adversary, not host compromise. A production deployment
would use a KMS or an HSM, and that gap is recorded in the risk register.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import rsa

from cryptosuite.hybrid import (
    generate_identity_key,
    load_identity_private,
    serialize_identity_private,
)
from cryptosuite.legacy import (
    generate_private_key,
    load_private_key,
    serialize_private_key,
)


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    # 0600 before any bytes land, so the key is never briefly world-readable.
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.replace(str(tmp), str(path))


def load_or_create_rsa(path: Path) -> rsa.RSAPrivateKey:
    path = Path(path)
    if path.exists():
        return load_private_key(path.read_bytes())
    key = generate_private_key()
    _write_private(path, serialize_private_key(key))
    return key


def load_or_create_identity(path: Path) -> Any:
    """Load or create the responder's long-term ML-DSA-65 signing key.

    Stored as the 32-byte seed rather than an expanded key: the seed is the
    canonical form in FIPS 204 and regenerates the key deterministically.
    """
    path = Path(path)
    if path.exists():
        return load_identity_private(path.read_bytes())
    key = generate_identity_key()
    _write_private(path, serialize_identity_private(key))
    return key
