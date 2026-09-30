#!/usr/bin/env python3
"""Generate one PXN development-only credential set."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


CREDENTIAL_SET_ID = "23aaea2a-a511-4e3d-9a95-34f8e00a48ef"
NOT_BEFORE = datetime(2025, 1, 1, tzinfo=timezone.utc)
NOT_AFTER = datetime(2045, 1, 1, tzinfo=timezone.utc)


def public_der(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def key_record(key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    digest = hashlib.sha256(public_der(key)).digest()
    return {
        "key_id_hex": digest[:8].hex(),
        "public_key_sha256": digest.hex(),
    }


def write_private_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def write_public_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def ca_certificate(
    subject_name: str,
    subject_key: ec.EllipticCurvePrivateKey,
    issuer_name: x509.Name,
    issuer_key: ec.EllipticCurvePrivateKey,
    *,
    path_length: int,
) -> x509.Certificate:
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PXN DEVELOPMENT ONLY"),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
            critical=False,
        )
        .sign(issuer_key, hashes.SHA256())
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    private_dir = root / "private"
    public_dir = root / "public"
    manifest_path = root / "development_credentials.json"

    protected_outputs = [private_dir, public_dir, manifest_path]
    if any(path.exists() for path in protected_outputs):
        raise SystemExit("credential outputs already exist; create a new credential-set version instead of overwriting")

    private_dir.mkdir()
    public_dir.mkdir()

    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PXN DEVELOPMENT ONLY"),
            x509.NameAttribute(NameOID.COMMON_NAME, "PXN Development Root CA v1"),
        ]
    )
    root_cert = ca_certificate(
        "PXN Development Root CA v1", root_key, root_name, root_key, path_length=1
    )

    issuer_key = ec.generate_private_key(ec.SECP256R1())
    issuer_cert = ca_certificate(
        "PXN Development Device Issuer v1",
        issuer_key,
        root_cert.subject,
        root_key,
        path_length=0,
    )
    host_key = ec.generate_private_key(ec.SECP256R1())
    ota_key = ec.generate_private_key(ec.SECP256R1())

    write_private_key(private_dir / "development-root-ca-key.pem", root_key)
    write_private_key(private_dir / "device-issuer-key.pem", issuer_key)
    write_private_key(private_dir / "host-authorization-key.pem", host_key)
    write_private_key(private_dir / "ota-signing-key.pem", ota_key)
    write_public_key(public_dir / "host-authorization-public.pem", host_key)
    write_public_key(public_dir / "ota-signing-public.pem", ota_key)
    (public_dir / "development-root-ca.pem").write_bytes(
        root_cert.public_bytes(serialization.Encoding.PEM)
    )
    (public_dir / "development-root-ca.der").write_bytes(
        root_cert.public_bytes(serialization.Encoding.DER)
    )
    (public_dir / "device-issuer.pem").write_bytes(
        issuer_cert.public_bytes(serialization.Encoding.PEM)
    )
    (public_dir / "device-issuer.der").write_bytes(
        issuer_cert.public_bytes(serialization.Encoding.DER)
    )

    manifest = {
        "schema_version": 1,
        "environment": "development",
        "credential_set_id": CREDENTIAL_SET_ID,
        "credential_set_version": "1.0.0-dev.1",
        "algorithm": "P-256_ES256",
        "validity": {
            "not_before": NOT_BEFORE.isoformat().replace("+00:00", "Z"),
            "not_after": NOT_AFTER.isoformat().replace("+00:00", "Z"),
        },
        "keys": {
            "development_root_ca": {
                **key_record(root_key),
                "certificate_sha256": root_cert.fingerprint(hashes.SHA256()).hex(),
            },
            "device_issuer": {
                **key_record(issuer_key),
                "certificate_sha256": issuer_cert.fingerprint(hashes.SHA256()).hex(),
            },
            "host_authorization": key_record(host_key),
            "ota_signing": key_record(ota_key),
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
