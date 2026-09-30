#!/usr/bin/env python3
"""Create a device-local XProtocol authentication CSR.

This command generates only the device key and CSR.  It never loads an issuer
key and it never installs a credential.  Signing and installation remain
outside this repository's public tooling and must be performed by the
authorized development or production provisioning system.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, ObjectIdentifier


AUTH_EXTENSION_OID = ObjectIdentifier("1.3.6.1.4.1.55555.1.1")
CHANNEL_VERSION = 1


def _environment_byte(environment: str) -> int:
    return {"development": 1, "production": 2}[environment]


def _spki_sha256(public_key: ec.EllipticCurvePublicKey) -> str:
    encoded = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(encoded).hexdigest()


def create_request(environment: str, trust_generation: int, common_name: str) -> tuple[bytes, bytes, dict]:
    if not 1 <= trust_generation <= 0xFFFFFFFF:
        raise ValueError("trust generation must be in 1..4294967295")
    if not common_name or len(common_name) > 128:
        raise ValueError("common name must contain 1..128 characters")

    key = ec.generate_private_key(ec.SECP256R1())
    request = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)]))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]
            ),
            critical=False,
        )
        .add_extension(
            x509.UnrecognizedExtension(
                AUTH_EXTENSION_OID,
                bytes([_environment_byte(environment)]) + trust_generation.to_bytes(4, "big"),
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    csr_pem = request.public_bytes(serialization.Encoding.PEM)
    csr_der = request.public_bytes(serialization.Encoding.DER)
    manifest = {
        "schema_version": 1,
        "credential_type": "xprotocol-authentication-csr",
        "channel_version": CHANNEL_VERSION,
        "construction": "TLS_1_3_MUTUAL_AUTH",
        "environment": environment,
        "trust_generation": trust_generation,
        "common_name": common_name,
        "signature": "P256_ES256",
        "key_exchange": "P256_ECDHE",
        "csr_sha256": hashlib.sha256(csr_der).hexdigest(),
        "public_spki_sha256": _spki_sha256(key.public_key()),
        "issuer_private_key_included": False,
        "installed": False,
    }
    return key_pem, csr_pem, manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", choices=("development", "production"), required=True)
    parser.add_argument("--trust-generation", type=int, required=True)
    parser.add_argument("--common-name", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise SystemExit(f"refusing to overwrite non-empty output directory: {output}")
    output.mkdir(parents=True, exist_ok=True)
    key_pem, csr_pem, manifest = create_request(
        args.environment, args.trust_generation, args.common_name
    )
    (output / "device-auth-key.pem").write_bytes(key_pem)
    (output / "device-auth.csr.pem").write_bytes(csr_pem)
    (output / "auth-request.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
