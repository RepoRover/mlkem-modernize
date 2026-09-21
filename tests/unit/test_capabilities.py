import cryptography
import pytest

import pqcsuite as cs
from pqcsuite import capabilities
from pqcwire.protocol import HYBRID_PQC, LEGACY_RSA


def test_probe_describes_the_installed_backend():
    report = cs.probe()
    assert report.cryptography_version == cryptography.__version__
    # A reason is present exactly when ML-KEM is missing.
    assert report.mlkem_available is (report.reason is None)


def test_supported_suites_require_both_an_implementation_and_a_backend():
    """A node advertises the hybrid suite only when it could actually run it.

    Both conditions have to hold. Advertising on backend capability alone is
    how a node ends up offering a suite it cannot complete a handshake with;
    advertising on implementation alone is how the legacy device would claim
    post-quantum support it does not have.
    """
    suites = cs.supported_suites()
    assert LEGACY_RSA in suites
    assert (HYBRID_PQC in suites) is cs.MLKEM_AVAILABLE


def test_requesting_mlkem_without_support_fails_loudly(monkeypatch):
    monkeypatch.setattr(capabilities, "MLKEM_AVAILABLE", False)
    with pytest.raises(capabilities.CapabilityError, match="ML-KEM"):
        capabilities.mlkem_module()
