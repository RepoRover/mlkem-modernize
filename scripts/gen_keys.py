#!/usr/bin/env python3
"""Generate the P-256 keypairs the baseline needs.

DEVELOPMENT ONLY. These keys are written unencrypted to a shared volume with no
HSM, no attestation and no rotation. A real deployment would provision device
keys in a secure element at manufacture and keep server keys in an HSM/KMS.

Run by the `keygen` service in docker-compose before anything else starts, or
by hand:  python scripts/gen_keys.py --out keys

Existing keys are left alone unless --force is given, so restarting the stack
does not silently invalidate a device's pinned gateway key.
"""

from __future__ import annotations

import argparse
import contextlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.common import cryptoutil as cu

# name -> what it is used for
KEYS = {
    "device_ecdh": "hop 1 device long-term ECDH key (static-static; IS the device identity)",
    "gateway_ecdh": "hop 1 gateway long-term ECDH key (static-static; pinned in the device)",
    "gateway_ecdsa": "hop 2 gateway ECDSA key (authenticates gateway to cloud)",
    "cloud_ecdsa": "hop 2 cloud long-term ECDSA key (authenticates the cloud to the gateway)",
}


def generate(out_dir: Path, force: bool) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = 0

    for name, purpose in KEYS.items():
        priv_path = out_dir / f"{name}_priv.pem"
        pub_path = out_dir / f"{name}_pub.pem"

        if priv_path.exists() and pub_path.exists() and not force:
            print(f"  keep   {name:<14} (already present)")
            continue

        private_key = cu.generate_private_key()
        priv_path.write_bytes(cu.private_key_to_pem(private_key))
        pub_path.write_bytes(cu.public_key_to_pem(private_key.public_key()))

        # Best effort on POSIX; a no-op on Windows, where the volume is the boundary.
        with contextlib.suppress(OSError):
            priv_path.chmod(0o600)

        print(f"  write  {name:<14} {purpose}")
        written += 1

    marker = out_dir / "DEV_KEYS_DO_NOT_USE_IN_PRODUCTION"
    marker.write_text(
        "These P-256 keys are generated for local development of the legacy baseline.\n"
        "They are unencrypted on disk and shared between containers.\n"
        "Do not reuse them anywhere real.\n",
        encoding="utf-8",
    )
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="keys", help="output directory (default: keys)")
    parser.add_argument("--force", action="store_true", help="overwrite existing keys")
    args = parser.parse_args()

    out_dir = Path(args.out)
    print(f"generating development keys in {out_dir.resolve()}")
    written = generate(out_dir, args.force)
    print(f"done ({written} keypair(s) written)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
