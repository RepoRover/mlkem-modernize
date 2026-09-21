"""Validate the optional observability overlay's security boundaries."""

import json
import sys


def main() -> None:
    """Read merged Compose JSON from stdin and fail closed on unsafe wiring."""
    config = json.load(sys.stdin)
    services = config["services"]

    expected_networks = {
        "device": {"device_net"},
        "gateway": {"device_net", "cloud_net"},
        "cloud": {"cloud_net"},
        "postgres": {"cloud_net"},
        "otel-device": {"device_net", "observability_net"},
        "otel-cloud": {"cloud_net", "observability_net"},
        "grafana-lgtm": {"observability_net", "dashboard_net"},
    }
    for name, networks in expected_networks.items():
        assert set(services[name]["networks"]) == networks

    assert config["networks"]["observability_net"]["internal"]
    assert not config["networks"]["dashboard_net"].get("internal", False)
    for name, service in services.items():
        ports = service.get("ports", [])
        if name == "grafana-lgtm":
            assert len(ports) == 1
            assert ports[0]["host_ip"] == "127.0.0.1"
            assert int(ports[0]["published"]) == 3000
            assert int(ports[0]["target"]) == 3000
        else:
            assert not ports, f"{name} must not publish ports"

    for name in ("otel-device", "otel-cloud"):
        service = services[name]
        assert service["read_only"]
        assert service["user"].split(":")[0] not in ("0", "root")
        assert service["cap_drop"] == ["ALL"]
        targets = {mount["target"] for mount in service.get("volumes", [])}
        assert targets == {"/etc/otelcol-contrib/config.yaml"}
        assert all(mount["read_only"] for mount in service["volumes"])

    print(
        "Observability checks passed: segmented collectors and loopback-only Grafana."
    )


if __name__ == "__main__":
    main()
