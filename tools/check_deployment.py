"""Validate rendered Compose security boundaries before deployment."""

import json
import sys


def main() -> None:
    """Read `docker compose config --format json` from stdin; fail closed."""
    config = json.load(sys.stdin)
    services = config["services"]
    assert set(services["device"]["networks"]) == {"device_net"}
    assert set(services["gateway"]["networks"]) == {"device_net", "cloud_net"}
    assert set(services["cloud"]["networks"]) == {"cloud_net"}
    assert set(services["postgres"]["networks"]) == {"cloud_net"}
    assert all(network["internal"] for network in config["networks"].values())
    margin = float(
        services["device"]["environment"]["GATEWAY_TIMEOUT_SECONDS"]
    ) - float(services["gateway"]["environment"]["CLOUD_FORWARD_DEADLINE_SECONDS"])
    assert margin >= 5, "Device request deadline must exceed Gateway deadline by >=5s"
    allowed = {
        "device": {"/run/secrets/device.key", "/run/secrets/ca.crt"},
        "gateway": {
            "/run/secrets/device.key",
            "/run/secrets/ca.crt",
            "/run/secrets/gateway.token",
            "/run/secrets/cloud.pub",
            "/run/secrets/tls.crt",
            "/run/secrets/tls.key",
        },
        "cloud": {
            "/run/secrets/active",
            "/run/secrets/gateway.token",
            "/run/secrets/database.url",
            "/run/secrets/tls.crt",
            "/run/secrets/tls.key",
        },
    }
    for name, targets in allowed.items():
        service = services[name]
        assert service["user"].split(":")[0] not in ("0", "root")
        assert service["read_only"]
        assert not service.get("ports")
        mounts = service["volumes"]
        assert {mount["target"] for mount in mounts} == targets
        assert all(mount["read_only"] for mount in mounts)
        assert all(
            "/staged" not in mount["source"] and not mount["source"].endswith("ca.key")
            for mount in mounts
        )
    assert int(services["device"]["mem_limit"]) == 128 * 1024 * 1024
    assert float(services["device"]["cpus"]) == 0.25
    assert not services["postgres"].get("ports")
    assert any(mount["type"] == "volume" for mount in services["postgres"]["volumes"])
    print(
        "Deployment checks passed: deadlines, identities, limits, networks, secret mounts."
    )


if __name__ == "__main__":
    main()
