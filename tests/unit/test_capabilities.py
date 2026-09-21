import cryptography
import pytest

import cryptosuite as cs
from cryptosuite import capabilities
from wire.protocol import HYBRID_PQC, LEGACY_RSA


def test_probe_describes_the_installed_backend():
    report = cs.probe()
    assert report.cryptography_version == cryptography.__version__
    # A reason is present exactly when ML-KEM is missing.
    assert report.mlkem_available is (report.reason is None)


def test_backend_capability_is_not_the_same_as_an_implemented_suite():
    """A capable crypto backend does not by itself mean a suite is supported.

    Conflating the two is how a node ends up advertising a suite it cannot
    actually complete a handshake with.
    """
    assert LEGACY_RSA in cs.supported_suites()
    assert HYBRID_PQC not in cs.supported_suites()


def test_requesting_mlkem_without_support_fails_loudly(monkeypatch):
    monkeypatch.setattr(capabilities, "MLKEM_AVAILABLE", False)
    with pytest.raises(capabilities.CapabilityError, match="ML-KEM"):
        capabilities.mlkem_module()
