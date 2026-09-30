#!/usr/bin/env python3
"""Validate the checked-in development credential set."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization


def public_fingerprint(private_key_path: Path) -> tuple[str, str]:
    key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    public_der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(public_der).digest()
    return digest[:8].hex(), digest.hex()


def loaded_public_fingerprint(public_key_path: Path) -> str:
    key = serialization.load_pem_public_key(public_key_path.read_bytes())
    public_der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(public_der).hexdigest()


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / "development_credentials.json").read_text(encoding="utf-8"))
    paths = {
        "development_root_ca": "development-root-ca-key.pem",
        "device_issuer": "device-issuer-key.pem",
        "host_authorization": "host-authorization-key.pem",
        "ota_signing": "ota-signing-key.pem",
    }
    for name, filename in paths.items():
        key_id, digest = public_fingerprint(root / "private" / filename)
        record = manifest["keys"][name]
        if record["key_id_hex"] != key_id or record["public_key_sha256"] != digest:
            raise ValueError(f"key manifest mismatch: {name}")

    root_cert = x509.load_pem_x509_certificate(
        (root / "public" / "development-root-ca.pem").read_bytes()
    )
    issuer_cert = x509.load_pem_x509_certificate(
        (root / "public" / "device-issuer.pem").read_bytes()
    )
    if root_cert.fingerprint(hashes.SHA256()).hex() != manifest["keys"]["development_root_ca"]["certificate_sha256"]:
        raise ValueError("root certificate manifest mismatch")
    if issuer_cert.fingerprint(hashes.SHA256()).hex() != manifest["keys"]["device_issuer"]["certificate_sha256"]:
        raise ValueError("issuer certificate manifest mismatch")
    _, root_public_sha = public_fingerprint(root / "private" / paths["development_root_ca"])
    _, issuer_public_sha = public_fingerprint(root / "private" / paths["device_issuer"])
    root_cert_public_sha = hashlib.sha256(
        root_cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()
    issuer_cert_public_sha = hashlib.sha256(
        issuer_cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()
    if root_public_sha != root_cert_public_sha:
        raise ValueError("root certificate public key mismatch")
    if issuer_public_sha != issuer_cert_public_sha:
        raise ValueError("issuer certificate public key mismatch")
    if loaded_public_fingerprint(root / "public" / "host-authorization-public.pem") != manifest["keys"]["host_authorization"]["public_key_sha256"]:
        raise ValueError("host authorization public key mismatch")
    if loaded_public_fingerprint(root / "public" / "ota-signing-public.pem") != manifest["keys"]["ota_signing"]["public_key_sha256"]:
        raise ValueError("OTA signing public key mismatch")
    if not root_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("root certificate is not a CA")
    if not issuer_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("device issuer certificate is not a CA")
    root_cert.public_key().verify(
        issuer_cert.signature,
        issuer_cert.tbs_certificate_bytes,
        issuer_cert.signature_algorithm_parameters,
    )
    print("OK: development credential repository")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
