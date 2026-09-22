import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCKER = shutil.which("docker")


@pytest.mark.parametrize(
    ("compose_file", "expected_mode"),
    [
        ("deploy/docker-compose.yml", "hybrid"),
        ("deploy/docker-compose.baseline.yml", "legacy"),
    ],
)
def test_rendered_deployment_security_invariants(compose_file, expected_mode):
    if DOCKER is None:
        pytest.skip("docker is not installed")
    result = subprocess.run(
        [DOCKER, "compose", "-f", compose_file, "config", "--format", "json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail(result.stderr)
    services = json.loads(result.stdout)["services"]

    gateway = services["gateway"]
    assert gateway["environment"]["UPSTREAM_SUITE"] == expected_mode
    assert "/readyz" in " ".join(gateway["healthcheck"]["test"])

    for service_name in ("cloud", "gateway"):
        identity_mounts = [
            volume
            for volume in services[service_name]["volumes"]
            if "identity" in volume.get("target", "")
        ]
        if service_name == "cloud" or expected_mode == "hybrid":
            assert identity_mounts
        assert all(volume["read_only"] for volume in identity_mounts)
        assert all(port["host_ip"] == "127.0.0.1" for port in services[service_name]["ports"])

    device = services["legacy-device"]
    assert device["read_only"] is True
    assert any(mount.startswith("/tmp") for mount in device["tmpfs"])
    assert device["environment"]["LOOP_FOREVER"] == "true"


@pytest.mark.parametrize(
    "compose_file",
    ["deploy/docker-compose.yml", "deploy/docker-compose.baseline.yml"],
)
def test_observability_ports_bind_only_to_loopback(compose_file):
    if DOCKER is None:
        pytest.skip("docker is not installed")
    result = subprocess.run(
        [
            DOCKER,
            "compose",
            "-f",
            compose_file,
            "-f",
            "deploy/docker-compose.observability.yml",
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail(result.stderr)
    services = json.loads(result.stdout)["services"]

    for service_name, expected_port in (("prometheus", 9090), ("grafana", 3000)):
        ports = services[service_name]["ports"]
        assert len(ports) == 1
        assert ports[0]["host_ip"] == "127.0.0.1"
        assert int(ports[0]["published"]) == expected_port
        assert ports[0]["target"] == expected_port
