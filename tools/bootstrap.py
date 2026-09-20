"""Generate development-only secrets without printing their values."""

import argparse
import ipaddress
import os
import secrets
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def private_bytes(key: ec.EllipticCurvePrivateKey | MLKEM768PrivateKey) -> bytes:
    """Serialize a generated private key for read-only runtime provisioning."""
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def generate(directory: Path, *, force: bool = False) -> None:
    """Create current and staged material; refuse replacement by default.

    Args:
        directory: Dedicated local development-material directory.
        force: Explicitly allow replacing material, invalidating existing data access.
    """
    if directory.is_symlink():
        raise ValueError("material directory must not be a symlink")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    children = list(directory.iterdir())
    if children and not force:
        raise ValueError(
            "material directory is not empty; replacement requires --force"
        )
    if force:
        for child in children:
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
    directory.chmod(0o700)

    def save(name: str, data: bytes, mode: int = 0o600) -> None:
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Do not follow pre-existing symlinks even when --force was requested.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            os.fchmod(output.fileno(), mode)
        print(f"created {path}")

    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ML-KEM demo CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    save("ca/ca.key", private_bytes(ca_key))
    save("ca/ca.crt", ca.public_bytes(serialization.Encoding.PEM), 0o644)
    for service in ("gateway", "cloud"):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, service)]))
            .issuer_name(ca.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    True, False, False, False, False, False, False, False, False
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName(service),
                        x509.DNSName("localhost"),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    ]
                ),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .sign(ca_key, hashes.SHA256())
        )
        save(f"{service}/tls.key", private_bytes(key))
        save(f"{service}/tls.crt", cert.public_bytes(serialization.Encoding.PEM), 0o644)
    save("device.key", secrets.token_bytes(32))
    save("gateway.token", secrets.token_urlsafe(32).encode())
    password = secrets.token_urlsafe(32)
    # PostgreSQL runs under its own UID. The enclosing host directory is 0700;
    # only this individual file is mounted into the database container.
    save("postgres.password", password.encode(), 0o444)
    save(
        "database.url",
        f"postgresql://weather:{password}@postgres:5432/weather".encode(),
    )
    for key_id, folder in (("cloud-kem-001", "active"), ("cloud-kem-002", "staged")):
        key = MLKEM768PrivateKey.generate()
        save(f"{folder}/{key_id}.pem", private_bytes(key))
        save(f"public/{key_id}.pub", key.public_key().public_bytes_raw(), 0o644)


def main() -> None:
    """Run the explicit, container-friendly provisioning command."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("/material"))
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    try:
        generate(args.directory, force=args.force)
    except ValueError, OSError:
        parser.exit(
            1,
            "Bootstrap failed: use an empty writable directory, or explicitly --force replacement.\n",
        )


if __name__ == "__main__":
    main()
