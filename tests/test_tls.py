"""Exercise certificate failures over real loopback TLS connections on both hops."""

import asyncio
import ssl
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Literal

import httpx
import pytest
from config import Settings as DeviceSettings
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from delivery import deliver
from errors import DeviceError
from gateway.errors import PermanentCloudError
from gateway.forwarding import CloudForwarder
from gateway.models import Observation
from models import Observation as DeviceObservation

from tools.bootstrap import generate, private_bytes


@pytest.mark.parametrize("hop", ["device", "gateway"])
@pytest.mark.parametrize("failure", ["untrusted", "hostname", "expired"])
def test_certificate_failure_is_fatal_without_retries(
    tmp_path: Path,
    hop: Literal["device", "gateway"],
    failure: Literal["untrusted", "hostname", "expired"],
) -> None:
    generate(tmp_path)
    ca = x509.load_pem_x509_certificate((tmp_path / "ca/ca.crt").read_bytes())
    ca_key = serialization.load_pem_private_key(
        (tmp_path / "ca/ca.key").read_bytes(), password=None
    )
    assert isinstance(ca_key, ec.EllipticCurvePrivateKey)
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(
            now - timedelta(days=1) if failure == "expired" else now + timedelta(days=1)
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("wrong-host" if failure == "hostname" else "localhost")]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    (tmp_path / "test.crt").write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM)
    )
    (tmp_path / "test.key").write_bytes(private_bytes(key))
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(tmp_path / "test.crt", tmp_path / "test.key")
    context = ssl.create_default_context(
        cafile=None if failure == "untrusted" else str(tmp_path / "ca/ca.crt")
    )
    if hop == "device":
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
    else:
        context.minimum_version = ssl.TLSVersion.TLSv1_3
    item = Observation(
        observation_id="device:2024-01-01",
        device_id="device",
        observed_on=date(2024, 1, 1),
        latitude=0,
        longitude=0,
        elevation_m=0,
        utc_offset_seconds=0,
        timezone="UTC",
        timezone_abbreviation="UTC",
        temperature_max_c=1,
        temperature_min_c=0,
        precipitation_mm=0,
        wind_speed_max_kmh=0,
    )

    async def scenario():
        attempts = 0

        async def count_attempt(request: httpx.Request) -> None:
            nonlocal attempts
            attempts += 1

        def connected(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            writer.close()

        server = await asyncio.start_server(
            connected, "127.0.0.1", 0, ssl=server_context
        )
        url = f"https://localhost:{server.sockets[0].getsockname()[1]}"
        async with (
            server,
            httpx.AsyncClient(
                verify=context,
                trust_env=False,
                event_hooks={"request": [count_attempt]},
            ) as client,
        ):
            if hop == "device":
                settings = DeviceSettings.model_validate(
                    {
                        "DEVICE_ID": "device",
                        "DEVICE_KEY_ID": "key",
                        "DEVICE_KEY_FILE": tmp_path / "device.key",
                        "GATEWAY_URL": url,
                        "GATEWAY_TIMEOUT_SECONDS": 2,
                        "CA_CERT_FILE": tmp_path / "ca/ca.crt",
                        "WEATHER_CSV_FILE": Path(__file__).resolve().parents[1]
                        / "device/data/weather_data.csv",
                        "SEND_INTERVAL_SECONDS": 0,
                        "RETRY_INITIAL_SECONDS": 0.01,
                        "RETRY_MAX_SECONDS": 0.01,
                    }
                )
                with pytest.raises(DeviceError, match="certificate"):
                    await asyncio.wait_for(
                        deliver(
                            client,
                            settings,
                            b"x" * 32,
                            DeviceObservation.model_validate_json(
                                item.model_dump_json()
                            ),
                        ),
                        timeout=3,
                    )
            else:
                forwarder = CloudForwarder(
                    client=client,
                    cloud_url=url,
                    bearer_token="a" * 43,
                    gateway_id="gw",
                    kem_key_id="key",
                    public_key=MLKEM768PrivateKey.generate().public_key(),
                    attempts=3,
                    timeout_seconds=2,
                    deadline_seconds=3,
                    retry_initial_seconds=0,
                    retry_max_seconds=0,
                )
                with pytest.raises(PermanentCloudError, match="certificate"):
                    await forwarder.forward(item)
        assert attempts == 1

    asyncio.run(scenario())
