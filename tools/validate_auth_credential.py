#!/usr/bin/env python3
"""Validate an externally signed XProtocol authentication certificate.

Validation is intentionally not provisioning: this command does not write
device storage, change a trust bundle, or accept a new root.  It checks the
certificate and optional CSR/issuer relationships before a separate controlled
installer is allowed to consume them.
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
ENVIRONMENT_BYTES = {"development": 1, "production": 2}


def _load_certificate(path: Path) -> x509.Certificate:
    data = path.read_bytes()
    if b"BEGIN CERTIFICATE" in data:
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(data)


def _load_csr(path: Path) -> x509.CertificateSigningRequest:
    data = path.read_bytes()
    if b"BEGIN CERTIFICATE REQUEST" in data:
        return x509.load_pem_x509_csr(data)
    return x509.load_der_x509_csr(data)


def _spki_sha256(public_key: ec.EllipticCurvePublicKey) -> str:
    encoded = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(encoded).hexdigest()


def validate(
    certificate: x509.Certificate,
    environment: str,
    trust_generation: int,
    issuer: x509.Certificate | None = None,
    csr: x509.CertificateSigningRequest | None = None,
) -> dict:
    public_key = certificate.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
        public_key.curve, ec.SECP256R1
    ):
        raise ValueError("authentication certificate must use P-256")
    basic = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    if basic.ca:
        raise ValueError("authentication leaf certificate must not be a CA")
    eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    if ExtendedKeyUsageOID.CLIENT_AUTH not in eku or ExtendedKeyUsageOID.SERVER_AUTH not in eku:
        raise ValueError("authentication certificate must allow mutual TLS client and server use")
    extension = certificate.extensions.get_extension_for_oid(AUTH_EXTENSION_OID).value.value
    expected_extension = bytes([ENVIRONMENT_BYTES[environment]]) + trust_generation.to_bytes(4, "big")
    if extension != expected_extension:
        raise ValueError("authentication environment or trust generation mismatch")
    if csr is not None:
        if csr.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ) != public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ):
            raise ValueError("certificate public key does not match CSR")
    if issuer is not None:
        issuer_basic = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not issuer_basic.ca:
            raise ValueError("issuer certificate is not a CA")
        if certificate.issuer != issuer.subject:
            raise ValueError("certificate issuer does not match supplied issuer")
        issuer_key = issuer.public_key()
        if not isinstance(issuer_key, ec.EllipticCurvePublicKey):
            raise ValueError("issuer must use an EC public key")
        issuer_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(certificate.signature_hash_algorithm),
        )
    return {
        "certificate_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
        "public_spki_sha256": _spki_sha256(public_key),
        "environment": environment,
        "trust_generation": trust_generation,
        "issuer_verified": issuer is not None,
        "provisioned": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--environment", choices=tuple(ENVIRONMENT_BYTES), required=True)
    parser.add_argument("--trust-generation", type=int, required=True)
    parser.add_argument("--issuer", type=Path)
    parser.add_argument("--csr", type=Path)
    args = parser.parse_args(argv)
    if not 1 <= args.trust_generation <= 0xFFFFFFFF:
        raise SystemExit("trust generation must be in 1..4294967295")
    result = validate(
        _load_certificate(args.certificate),
        args.environment,
        args.trust_generation,
        _load_certificate(args.issuer) if args.issuer else None,
        _load_csr(args.csr) if args.csr else None,
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
