"""Evidence that the legacy device genuinely cannot adopt ML-KEM itself.

The claim under test is specific. The device is *not* blocked by its Python
version or its CPU budget -- a current cryptography release installs on Python
3.9 and ML-KEM-768 keygen takes well under a millisecond. It is blocked by the
things that actually freeze fielded firmware: a pinned dependency inside an
immutable image, no route to a package index, and a read-only root filesystem.

These tests assert that accurate version, so the architecture's justification
rests on something reproducible rather than on a comfortable assumption.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]

REPO_ROOT = Path(__file__).resolve().parents[2]
IMAGE_TAG = "mlkem-device-probe:test"

DOCKER = shutil.which("docker")
requires_docker = pytest.mark.skipif(DOCKER is None, reason="docker is not installed")


def _run(args: list[str], timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(
        [DOCKER, *args], capture_output=True, text=True, timeout=timeout, check=False
    )


@pytest.fixture(scope="module")
def device_image() -> str:
    build = _run(
        [
            "build",
            "-f",
            "deploy/Dockerfile.device",
            "-t",
            IMAGE_TAG,
            str(REPO_ROOT),
        ],
        timeout=600,
    )
    if build.returncode != 0:
        pytest.fail(f"device image build failed:\n{build.stderr[-2000:]}")
    return IMAGE_TAG


@requires_docker
def test_device_image_has_no_mlkem_primitive(device_image):
    result = _run(
        [
            "run",
            "--rm",
            "--network",
            "none",
            device_image,
            "python",
            "-c",
            "import pqcsuite, json; print(json.dumps(pqcsuite.probe().to_dict()))",
        ]
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout.strip().splitlines()[-1])

    assert report["mlkem_available"] is False
    assert report["supported_suites"] == ["LEGACY-RSA2048-OAEP-AESGCM"]
    assert "cryptography>=48" in report["reason"]


@requires_docker
def test_device_cannot_fetch_a_post_quantum_build(device_image):
    """The blocker is the missing update path, not the Python version."""
    result = _run(
        [
            "run",
            "--rm",
            "--network",
            "none",
            device_image,
            "python",
            "-m",
            "pip",
            "install",
            "cryptography>=48",
        ]
    )
    assert result.returncode != 0
    combined = result.stdout + result.stderr
    assert "No matching distribution" in combined or "Network is unreachable" in combined


@requires_docker
def test_device_root_filesystem_is_immutable(device_image):
    result = _run(
        [
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            "/tmp",
            device_image,
            "python",
            "-c",
            "open('/app/implant.py', 'w').write('x')",
        ]
    )
    assert result.returncode != 0
    assert "Read-only file system" in (result.stdout + result.stderr)


@requires_docker
def test_python_version_alone_would_not_have_blocked_mlkem():
    """Guards against the tempting but false claim that Python 3.9 is the limit.

    If this ever fails, the honest justification in the architecture docs needs
    revisiting -- not the docs quietly rewritten to match.
    """
    result = _run(
        [
            "run",
            "--rm",
            "python:3.9-slim",
            "sh",
            "-c",
            "pip install -q 'cryptography>=48' && python -c "
            "'from cryptography.hazmat.primitives.asymmetric import mlkem; "
            "k=mlkem.MLKEM768PrivateKey.generate(); ss,ct=k.public_key().encapsulate(); "
            "print(k.decapsulate(ct)==ss)'",
        ],
        timeout=300,
    )
    assert result.returncode == 0, result.stderr
    assert "True" in result.stdout
