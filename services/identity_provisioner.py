"""Provision separate ML-DSA identities and peer pins for cloud and gateway.

This runs outside the service network before either endpoint starts. Every
private seed and public pin has its own volume, so neither long-running service
receives the peer's private identity or can rewrite its trust anchor.
"""

from __future__ import annotations

import os
from pathlib import Path

import pqcsuite as cs
from pqcnode.config import env_path


def _write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(descriptor, data)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


def provision(private_path: Path, public_path: Path) -> None:
    """Create a pair once, or validate that the persisted pair still matches."""
    if private_path.resolve() == public_path.resolve():
        raise RuntimeError("identity private key and public-key pin paths must be different")

    private_exists = private_path.exists()
    public_exists = public_path.exists()
    if private_exists != public_exists:
        raise RuntimeError("identity provisioning is incomplete; refusing to replace one half")

    if private_exists:
        private_key = cs.load_identity_private(private_path.read_bytes())
        pinned_public = cs.load_identity_public(public_path.read_bytes())
        expected = cs.serialize_identity_public(private_key.public_key())
        actual = cs.serialize_identity_public(pinned_public)
        if actual != expected:
            raise RuntimeError(
                "cloud identity private key does not match the gateway public-key pin"
            )
        return

    private_key = cs.generate_identity_key()
    _write(private_path, cs.serialize_identity_private(private_key), 0o600)
    _write(public_path, cs.serialize_identity_public(private_key.public_key()), 0o644)


def main() -> None:
    provision(
        env_path("CLOUD_IDENTITY_PATH", "/run/cloud-identity-private/cloud_mldsa.key"),
        env_path(
            "CLOUD_IDENTITY_PUBLIC_KEY_PATH",
            "/run/cloud-identity-public/cloud_mldsa.pub",
        ),
    )
    provision(
        env_path("GATEWAY_IDENTITY_PATH", "/run/gateway-identity-private/gateway_mldsa.key"),
        env_path(
            "GATEWAY_IDENTITY_PUBLIC_KEY_PATH",
            "/run/gateway-identity-public/gateway_mldsa.pub",
        ),
    )


if __name__ == "__main__":
    main()
