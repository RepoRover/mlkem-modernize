from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from services.common import cryptoutil as cu  # noqa: E402

DATA_FILE = ROOT / "data" / "weather_data.csv"


@pytest.fixture(scope="session")
def keys_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Generate a throwaway set of development keys for the test session."""
    out = tmp_path_factory.mktemp("keys")
    for name in ("device_ecdh", "gateway_ecdh", "gateway_ecdsa", "cloud_ecdsa"):
        key = cu.generate_private_key()
        (out / f"{name}_priv.pem").write_bytes(cu.private_key_to_pem(key))
        (out / f"{name}_pub.pem").write_bytes(cu.public_key_to_pem(key.public_key()))
    return out
