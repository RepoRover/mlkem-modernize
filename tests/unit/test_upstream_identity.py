from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import pqcsuite as cs
from pqcwire.frames import DataFrame, b64e
from pqcwire.protocol import LEGACY_RSA
from services.gateway import upstream as upstream_module
from services.gateway.upstream import HybridUpstream, UpstreamError, build_upstream
from services.identity_provisioner import provision


def _write_pin(path: Path, identity) -> None:
    path.write_bytes(cs.serialize_identity_public(identity.public_key()))


def _write_gateway_identity(path: Path):
    identity = cs.generate_identity_key()
    path.write_bytes(cs.serialize_identity_private(identity))
    return identity


def test_hybrid_upstream_requires_an_identity_pin():
    with pytest.raises(UpstreamError, match="CLOUD_IDENTITY_PUBLIC_KEY_PATH is required"):
        build_upstream("http://cloud", "hybrid")


def test_hybrid_upstream_rejects_a_missing_identity_pin(tmp_path):
    with pytest.raises(UpstreamError, match="cannot read identity key"):
        build_upstream("http://cloud", "hybrid", identity_path=tmp_path / "missing.pub")


def test_hybrid_upstream_rejects_a_malformed_identity_pin(tmp_path):
    pin = tmp_path / "cloud.pub"
    pin.write_bytes(b"not an ML-DSA-65 public key")

    with pytest.raises(UpstreamError, match="malformed"):
        build_upstream("http://cloud", "hybrid", identity_path=pin)


def test_hybrid_upstream_requires_a_gateway_signing_identity(tmp_path):
    identity = cs.generate_identity_key()
    pin = tmp_path / "cloud.pub"
    _write_pin(pin, identity)

    with pytest.raises(UpstreamError, match="GATEWAY_IDENTITY_PATH is required"):
        build_upstream("http://cloud", "hybrid", identity_path=pin)


def test_auto_is_a_hybrid_alias_without_capability_negotiation(tmp_path, monkeypatch):
    identity = cs.generate_identity_key()
    pin = tmp_path / "cloud.pub"
    _write_pin(pin, identity)

    def reject_capability_request(*args, **kwargs):
        raise AssertionError("auto must not consult network capabilities")

    monkeypatch.setattr(upstream_module.httpx, "get", reject_capability_request)

    gateway_path = tmp_path / "gateway.key"
    _write_gateway_identity(gateway_path)
    upstream = build_upstream(
        "http://cloud", "auto", identity_path=pin, gateway_identity_path=gateway_path
    )

    assert isinstance(upstream, HybridUpstream)


def test_auto_refuses_local_capability_fallback(tmp_path, monkeypatch):
    identity = cs.generate_identity_key()
    pin = tmp_path / "cloud.pub"
    _write_pin(pin, identity)
    gateway_path = tmp_path / "gateway.key"
    _write_gateway_identity(gateway_path)
    monkeypatch.setattr(cs, "supported_suites", lambda: [LEGACY_RSA])

    with pytest.raises(UpstreamError, match="UPSTREAM_SUITE=legacy explicitly"):
        build_upstream(
            "http://cloud",
            "auto",
            identity_path=pin,
            gateway_identity_path=gateway_path,
        )


def test_provisioned_identity_pin_matches_private_key(tmp_path):
    private_path = tmp_path / "private" / "cloud.key"
    public_path = tmp_path / "public" / "cloud.pub"

    provision(private_path, public_path)
    provision(private_path, public_path)

    private_key = cs.load_identity_private(private_path.read_bytes())
    assert public_path.read_bytes() == cs.serialize_identity_public(private_key.public_key())


def test_provisioner_rejects_equal_resolved_paths(tmp_path):
    private_path = tmp_path / "identity"
    public_path = tmp_path / "unused" / ".." / "identity"

    with pytest.raises(RuntimeError, match="paths must be different"):
        provision(private_path, public_path)

    assert not private_path.exists()


@pytest.mark.parametrize("existing_half", ["private", "public"])
def test_provisioner_refuses_an_incomplete_pair_without_modifying_it(tmp_path, existing_half):
    private_path = tmp_path / "cloud.key"
    public_path = tmp_path / "cloud.pub"
    existing_path = private_path if existing_half == "private" else public_path
    missing_path = public_path if existing_half == "private" else private_path
    existing_path.write_bytes(b"unchanged")

    with pytest.raises(RuntimeError, match="incomplete"):
        provision(private_path, public_path)

    assert existing_path.read_bytes() == b"unchanged"
    assert not missing_path.exists()


def test_provisioner_refuses_a_mismatched_persisted_pin(tmp_path):
    private_path = tmp_path / "cloud.key"
    public_path = tmp_path / "cloud.pub"
    provision(private_path, public_path)
    public_path.write_bytes(cs.serialize_identity_public(cs.generate_identity_key().public_key()))

    with pytest.raises(RuntimeError, match="does not match"):
        provision(private_path, public_path)


def test_network_substitution_of_identity_and_offer_does_not_replace_pin(tmp_path):
    legitimate_identity = cs.generate_identity_key()
    gateway_path = tmp_path / "gateway.key"
    gateway_identity = _write_gateway_identity(gateway_path)
    attacker_server = cs.HybridServer(cs.generate_identity_key(), gateway_identity.public_key())
    pin = tmp_path / "cloud.pub"
    _write_pin(pin, legitimate_identity)

    identity_requests = 0
    session_requests = 0
    mitm = FastAPI()

    @mitm.get("/pqc/identity")
    def substituted_identity():
        nonlocal identity_requests
        identity_requests += 1
        return {
            "algorithm": "ML-DSA-65",
            "public_key": b64e(cs.serialize_identity_public(attacker_server.identity_public_key)),
        }

    @mitm.get("/pqc/offer")
    def substituted_offer():
        return attacker_server.make_offer().to_dict()

    @mitm.post("/pqc/session")
    def substituted_session():
        nonlocal session_requests
        session_requests += 1
        return {"accepted": True}

    upstream = build_upstream(
        "http://cloud",
        "hybrid",
        identity_path=pin,
        gateway_identity_path=gateway_path,
    )
    assert isinstance(upstream, HybridUpstream)
    upstream._client = TestClient(mitm, base_url="http://cloud")

    with pytest.raises(UpstreamError, match="signature"):
        upstream.open_session()

    assert identity_requests == 0
    assert session_requests == 0


def test_upstream_retries_transient_gets_with_a_bounded_response():
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        assert request.headers["accept-encoding"] == "identity"
        if calls == 1:
            return httpx.Response(503, stream=httpx.ByteStream(b'{"status":"retry"}'))
        return httpx.Response(200, stream=httpx.ByteStream(b'{"status":"ready"}'))

    upstream = build_upstream(
        "http://cloud",
        "legacy",
        retry_attempts=2,
        retry_initial=0,
        retry_max=0,
    )
    upstream._client = httpx.Client(transport=httpx.MockTransport(handler))

    upstream.ready()
    assert calls == 2


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(
            200,
            headers={"Content-Encoding": "gzip"},
            stream=httpx.ByteStream(b"compressed"),
        ),
        httpx.Response(200, stream=httpx.ByteStream(b"x" * 33)),
    ],
    ids=["compressed", "oversized"],
)
def test_upstream_rejects_unsafe_response_bodies(response):
    upstream = build_upstream(
        "http://cloud",
        "legacy",
        retry_attempts=1,
        max_response_bytes=32,
    )
    upstream._client = httpx.Client(transport=httpx.MockTransport(lambda request: response))

    with pytest.raises(UpstreamError, match=r"compressed|too large"):
        upstream.ready()


def test_upstream_enforces_a_wall_clock_per_attempt_timeout(monkeypatch):
    clock = {"now": 0.0}

    class SlowStream(httpx.SyncByteStream):
        def __iter__(self):
            clock["now"] = 2.0
            yield b"late"

    monkeypatch.setattr(upstream_module.time, "monotonic", lambda: clock["now"])
    upstream = build_upstream(
        "http://cloud",
        "legacy",
        timeout=1,
        retry_attempts=1,
    )
    upstream._client = httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, stream=SlowStream()))
    )

    with pytest.raises(UpstreamError, match="per-attempt timeout"):
        upstream.ready()


def test_upstream_retries_stop_at_the_total_deadline(monkeypatch):
    clock = {"now": 0.0}
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(503, stream=httpx.ByteStream(b"unready"))

    monkeypatch.setattr(upstream_module.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(
        upstream_module.time,
        "sleep",
        lambda delay: clock.__setitem__("now", clock["now"] + delay),
    )
    upstream = build_upstream(
        "http://cloud",
        "legacy",
        timeout=1,
        deadline=0.15,
        retry_attempts=10,
        retry_initial=0.1,
        retry_max=0.1,
    )
    upstream._client = httpx.Client(transport=httpx.MockTransport(handler))

    with pytest.raises(UpstreamError, match="bounded attempts"):
        upstream.ready()

    assert calls == 2
    assert clock["now"] < 0.15


def test_state_changing_posts_are_not_retried():
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(503, stream=httpx.ByteStream(b"retry"))

    upstream = build_upstream("http://cloud", "legacy", retry_attempts=3)
    upstream._client = httpx.Client(transport=httpx.MockTransport(handler))
    frame = DataFrame(suite=LEGACY_RSA, session_id="0123456789abcdef", seq=0, ciphertext=b"ct")

    with pytest.raises(UpstreamError):
        upstream.send(frame)
    assert calls == 1


def test_upstream_policy_rejects_unbounded_configuration():
    with pytest.raises(UpstreamError, match="between 1 and 10"):
        build_upstream("http://cloud", "legacy", retry_attempts=11)
    with pytest.raises(UpstreamError, match="positive"):
        build_upstream("http://cloud", "legacy", deadline=0)
