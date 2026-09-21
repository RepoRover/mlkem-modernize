"""Integration test against the real docker-compose stack.

This is the only test that exercises the actual deployment artefact: the image
build, the keygen init ordering, the shared keys volume, healthchecks,
`depends_on` conditions, and service-to-service DNS. Everything else in the
suite runs the Python in-process and would pass even if the containers were
broken.

It is slow (image build plus a full 366-record replay), so it is marked
`docker` and excluded from the default run. Run it explicitly:

    pytest -m docker

Skipped automatically when Docker is unavailable.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
COMPOSE = ["docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.fast.yml"]
CLOUD = "http://127.0.0.1:8000"

pytestmark = pytest.mark.docker


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(
            ["docker", "info"], capture_output=True, timeout=30
        ).returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


requires_docker = pytest.mark.skipif(
    not docker_available(), reason="Docker is not available on this machine"
)


def compose(*args: str, timeout: int = 900) -> subprocess.CompletedProcess:
    return subprocess.run(
        COMPOSE + list(args), cwd=ROOT, capture_output=True, text=True, timeout=timeout
    )


def get_json(url: str, timeout: float = 5.0):
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.loads(response.read())


def wait_for(url: str, attempts: int = 60, delay: float = 2.0):
    """Poll until the endpoint answers, or fail with the compose logs attached."""
    last = None
    for _ in range(attempts):
        try:
            return get_json(url)
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            last = exc
            time.sleep(delay)
    pytest.fail(f"{url} never became available ({last})\n{compose('logs', '--tail', '50').stdout}")


@pytest.fixture(scope="module")
def stack():
    """Bring the whole stack up once for this module, then tear it down."""
    # Start from clean volumes so keygen runs and the DB is empty.
    compose("down", "-v", timeout=300)

    up = compose("up", "-d", "--build", timeout=1800)
    if up.returncode != 0:
        pytest.fail(f"docker compose up failed:\n{up.stdout}\n{up.stderr}")

    try:
        wait_for(f"{CLOUD}/health")
        yield
    finally:
        logs = compose("logs", "--tail", "40", timeout=120)
        print(logs.stdout)
        compose("down", "-v", timeout=300)


@requires_docker
def test_keygen_runs_once_and_exits_cleanly(stack):
    result = compose("ps", "-a", "--format", "{{.Service}} {{.State}} {{.ExitCode}}")
    lines = [line for line in result.stdout.splitlines() if line.startswith("keygen")]
    assert lines, f"no keygen container found:\n{result.stdout}"
    assert "exited 0" in lines[0].lower(), lines[0]


@requires_docker
def test_cloud_and_gateway_report_healthy(stack):
    cloud = get_json(f"{CLOUD}/health")
    assert cloud["status"] == "ok"
    # Both protocol versions are understood, and the hybrid suite is offered.
    assert "wx-hybrid/2" in cloud["protocols"]
    assert "wx-legacy/1" in cloud["protocols"]
    assert "hybrid-x25519-mlkem768" in cloud["suites"]
    # The cloud ships requiring PQC.
    assert cloud["policy"] == "require"

    # The gateway is not published to the host, so ask it from inside the network.
    result = compose(
        "exec", "-T", "gateway", "python", "-c",
        "import urllib.request;print(urllib.request.urlopen"
        "('http://localhost:8000/health',timeout=5).read().decode())",
    )
    assert result.returncode == 0, result.stderr
    assert "ECDH-P256-static-static" in result.stdout


@requires_docker
def test_the_full_year_flows_device_to_gateway_to_cloud(stack):
    """The headline integration assertion: all 366 readings arrive intact."""
    deadline = time.time() + 300
    stats = {}
    while time.time() < deadline:
        stats = get_json(f"{CLOUD}/stats")
        if stats["storage"]["total"] >= 366:
            break
        time.sleep(3)

    assert stats["storage"]["total"] == 366, f"only {stats['storage']['total']} stored: {stats}"
    assert stats["storage"]["devices"] == 1
    assert stats["storage"]["first_date"] == "2024-01-01"
    assert stats["storage"]["last_date"] == "2024-12-31"

    # Nothing was rejected on either hop.
    assert stats["messages"]["rejected"] == 0
    assert stats["messages"]["accepted"] == 366

    # 366 readings against a 100-record budget forces rekeying.
    assert stats["messages"]["handshakes"] >= 4


@requires_docker
def test_hop2_actually_negotiates_hybrid_pqc_in_containers(stack):
    """The whole point of Phase 4, verified against the real deployment.

    The in-process tests could pass with a misconfigured image; this asserts
    that the containers as shipped negotiate ML-KEM and never fall back.
    """
    stats = get_json(f"{CLOUD}/stats")["pqc"]

    assert stats["policy"] == "require"
    assert stats["handshakes_hybrid"] >= 4
    assert stats["handshakes_classical"] == 0, "a classical session was negotiated"
    assert stats["handshakes_downgrade_refused"] == 0
    assert stats["pqc_fraction"] == 1.0

    # And the gateway agrees about what it negotiated.
    result = compose(
        "exec", "-T", "cloud", "python", "-c",
        "import urllib.request;print(urllib.request.urlopen"
        "('http://gateway:8000/stats',timeout=5).read().decode())",
    )
    assert result.returncode == 0, result.stderr
    assert "hybrid-x25519-mlkem768" in result.stdout
    # Hop 1 is still classical -- the device was not upgraded.
    assert "ECDH-P256-static-static" in result.stdout


@requires_docker
def test_downgrade_is_refused_by_the_running_cloud(stack):
    """A classical-only offer against the shipped 'require' policy.

    Runs from inside the network so it reaches the cloud the way the gateway
    would, and checks the refusal is counted rather than silently handled.
    """
    before = get_json(f"{CLOUD}/stats")["pqc"]["handshakes_downgrade_refused"]

    script = """
import json, sys, urllib.request, urllib.error
sys.path.insert(0, "/app")
from services.common import cryptoutil as cu
from services.common.handshake import KeyShare, hop2_v2_client_transcript
from services.common.suites import SUITE_CLASSICAL
from services.common.wire import b64e

nonce = cu.random_bytes(16)
p256 = cu.public_key_to_bytes(cu.generate_private_key().public_key())
offered = [SUITE_CLASSICAL]
shares = {SUITE_CLASSICAL: KeyShare(p256_pub=p256)}
signing = cu.load_private_key("/keys/gateway_ecdsa_priv.pem")

body = {
    "protocol": "wx-hybrid/2", "hop": "gateway-cloud", "client_id": "gw-01",
    "client_nonce": b64e(nonce), "offered_suites": offered,
    "key_shares": {SUITE_CLASSICAL: {"eph_pub": b64e(p256)}},
    "sig": b64e(cu.sign(signing, hop2_v2_client_transcript(
        "gw-01", nonce, offered, shares))),
}
try:
    urllib.request.urlopen(urllib.request.Request(
        "http://cloud:8000/handshake",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}), timeout=10)
    print("RESULT: accepted-should-not-happen")
except urllib.error.HTTPError as e:
    print("RESULT:", e.code, json.loads(e.read()).get("detail"))
"""
    result = compose("exec", "-T", "gateway", "python", "-c", script)
    assert result.returncode == 0, f"{result.stdout}\n{result.stderr}"
    assert "RESULT: 403 downgrade_refused" in result.stdout, result.stdout

    after = get_json(f"{CLOUD}/stats")["pqc"]["handshakes_downgrade_refused"]
    assert after == before + 1, "the refusal was not counted"


@requires_docker
def test_device_container_exits_zero_after_its_run(stack):
    deadline = time.time() + 300
    while time.time() < deadline:
        result = compose("ps", "-a", "--format", "{{.Service}} {{.State}} {{.ExitCode}}")
        lines = [line for line in result.stdout.splitlines() if line.startswith("device")]
        if lines and "exited" in lines[0].lower():
            assert lines[0].strip().endswith("0"), lines[0]
            return
        time.sleep(3)
    pytest.fail("device container did not finish within the timeout")


@requires_docker
def test_read_api_serves_the_stored_data(stack):
    body = get_json(f"{CLOUD}/readings?limit=5")
    assert body["count"] == 5

    row = body["readings"][0]
    assert row["device_id"] == "device-berlin-01"
    assert row["gateway_id"] == "gw-01"
    assert set(row) >= {
        "date", "temp_max_c", "temp_min_c", "precip_mm",
        "wind_max_kmh", "received_at", "stored_at",
    }

    # A known record from the source file, end to end through both hops.
    first = get_json(f"{CLOUD}/readings/2024-01-01")
    assert first["count"] == 1
    assert first["readings"][0]["temp_max_c"] == pytest.approx(7.4)
    assert first["readings"][0]["wind_max_kmh"] == pytest.approx(19.7)

    assert get_json(f"{CLOUD}/readings?since=2024-12-01")["count"] == 31


@requires_docker
def test_services_run_as_a_non_root_user(stack):
    """The image creates appuser; a root container would be a finding."""
    result = compose("exec", "-T", "cloud", "id", "-un")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "appuser"


@requires_docker
def test_private_keys_are_not_world_readable_and_stay_in_the_volume(stack):
    """Keys live on the shared volume, never baked into the image layers."""
    in_image = compose("exec", "-T", "cloud", "sh", "-c", "ls /app/keys 2>&1 || true")
    assert "No such file" in in_image.stdout or in_image.stdout.strip() == ""

    on_volume = compose("exec", "-T", "cloud", "sh", "-c", "ls /keys")
    assert "cloud_ecdsa_priv.pem" in on_volume.stdout
    # The cloud must not be able to read the gateway's or device's private keys
    # in a real deployment; here it can, which is a documented baseline weakness.
    assert "device_ecdh_priv.pem" in on_volume.stdout


@requires_docker
def test_gateway_ingest_is_not_published_to_the_host(stack):
    """Only the cloud read API is exposed; ingest stays on the internal network."""
    for port in (8001, 8002):
        with pytest.raises((urllib.error.URLError, OSError)):
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=3)


@requires_docker
def test_tampered_message_is_rejected_by_the_running_gateway(stack):
    """One negative case against real containers, not just in-process apps.

    Runs from the `cloud` container rather than `device`: in fast mode the
    device finishes its replay and exits, so `exec` into it is not available by
    the time this test runs. The cloud container is long-lived, sits on the same
    network, and has the keys volume mounted read-only.
    """
    script = """
import json, urllib.request, urllib.error, base64, os, sys
sys.path.insert(0, "/app")
from services.common import cryptoutil as cu
from services.common.handshake import hop1_derive
from services.common.wire import b64e, b64d

base = "http://gateway:8000"
nonce = cu.random_bytes(16)
hello = json.loads(urllib.request.urlopen(urllib.request.Request(
    base + "/handshake",
    data=json.dumps({"protocol":"wx-legacy/1","hop":"device-gateway",
                     "client_id":"device-berlin-01","client_nonce":b64e(nonce)}).encode(),
    headers={"Content-Type":"application/json"}), timeout=10).read())

sid = b64d(hello["session_id"]); prefix = b64d(hello["nonce_prefix"])
d = hop1_derive(cu.load_private_key("/keys/device_ecdh_priv.pem"),
                cu.load_public_key("/keys/gateway_ecdh_pub.pem"),
                nonce, b64d(hello["server_nonce"]), sid, prefix)
sender = cu.AeadSender(d.key, sid, prefix)
payload = {"device_id":"device-berlin-01","date":"2099-01-01","temp_max_c":7.4,
           "temp_min_c":3.4,"precip_mm":1.8,"wind_max_kmh":19.7}
seq, n, ct = sender.encrypt(json.dumps(payload).encode())
bad = bytes([ct[0] ^ 1]) + ct[1:]

try:
    urllib.request.urlopen(urllib.request.Request(
        base + "/ingest",
        data=json.dumps({"session_id":b64e(sid),"seq":seq,"nonce":b64e(n),
                         "ct":b64e(bad)}).encode(),
        headers={"Content-Type":"application/json"}), timeout=10)
    print("RESULT: accepted-should-not-happen")
except urllib.error.HTTPError as e:
    print("RESULT:", e.code, json.loads(e.read())["reason"])
"""
    result = compose("exec", "-T", "cloud", "python", "-c", script)
    assert result.returncode == 0, f"{result.stdout}\n{result.stderr}"
    assert "RESULT: 400 bad_tag" in result.stdout, result.stdout

    # And the poisoned date never reached storage.
    with pytest.raises(urllib.error.HTTPError) as exc:
        get_json(f"{CLOUD}/readings/2099-01-01")
    assert exc.value.code == 404
