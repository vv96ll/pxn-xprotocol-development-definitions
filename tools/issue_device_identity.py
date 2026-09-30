#!/usr/bin/env python3
"""Issue a development-only device identity for a product target."""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import struct
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


NOT_BEFORE = datetime(2025, 1, 1, tzinfo=timezone.utc)
NOT_AFTER = datetime(2040, 1, 1, tzinfo=timezone.utc)


def raw_public_key(key: ec.EllipticCurvePublicKey) -> bytes:
    numbers = key.public_numbers()
    return numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")


def c_array(name: str, value: bytes) -> str:
    rows = []
    for offset in range(0, len(value), 12):
        row = ", ".join(f"0x{byte:02x}" for byte in value[offset : offset + 12])
        rows.append(f"    {row},")
    return (
        f"static const uint8_t {name}[{len(value)}] PXN_DEVELOPMENT_MAYBE_UNUSED = {{\n"
        + "\n".join(rows)
        + "\n};\n"
    )


def load_identity(path: Path, target: str) -> tuple[dict, dict]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if document.get("schema_version") != 1 or document.get("environment") != "development":
        raise ValueError("identity file must be schema_version 1 and environment development")
    targets = document.get("targets")
    if not isinstance(targets, dict) or target not in targets:
        raise ValueError(f"unknown development target: {target}")
    return document, targets[target]


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity-file", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--random-device-uuid", action="store_true")
    args = parser.parse_args()

    document, target = load_identity(args.identity_file.resolve(), args.target)
    manifest = json.loads((repo_root / "development_credentials.json").read_text(encoding="utf-8"))
    if document.get("credential_set_id") != manifest.get("credential_set_id"):
        raise ValueError("product identity references a different development credential set")

    expected = document.get("credential_fingerprints", {})
    for name in ("development_root_ca", "device_issuer", "host_authorization", "ota_signing"):
        actual = manifest["keys"][name]["public_key_sha256"]
        if expected.get(name) != actual:
            raise ValueError(f"credential fingerprint mismatch: {name}")

    device_uuid = uuid.uuid4() if args.random_device_uuid else uuid.UUID(target["default_device_uuid"])
    unique_code = secrets.token_hex(16)
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise SystemExit(f"output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)

    issuer_key = serialization.load_pem_private_key(
        (repo_root / "private" / "device-issuer-key.pem").read_bytes(), password=None
    )
    issuer_cert = x509.load_pem_x509_certificate(
        (repo_root / "public" / "device-issuer.pem").read_bytes()
    )
    device_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PXN DEVELOPMENT ONLY"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"PXN Development Device {device_uuid}"),
        ]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(device_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(f"urn:uuid:{str(device_uuid).lower()}")]
            ),
            critical=False,
        )
        .sign(issuer_key, hashes.SHA256())
    )

    leaf_der = certificate.public_bytes(serialization.Encoding.DER)
    issuer_der = issuer_cert.public_bytes(serialization.Encoding.DER)
    chain = struct.pack("<H", 2) + struct.pack("<I", len(leaf_der)) + leaf_der
    chain += struct.pack("<I", len(issuer_der)) + issuer_der

    (output / "device-identity-key.pem").write_bytes(
        device_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (output / "device-certificate.pem").write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM)
    )
    (output / "device-certificate.der").write_bytes(leaf_der)
    (output / "device-credential-chain.bin").write_bytes(chain)
    host_public_key = serialization.load_pem_public_key(
        (repo_root / "public" / "host-authorization-public.pem").read_bytes()
    )
    ota_public_key = serialization.load_pem_public_key(
        (repo_root / "public" / "ota-signing-public.pem").read_bytes()
    )
    private_scalar = device_key.private_numbers().private_value.to_bytes(32, "big")
    header = (
        "/* Generated development identity. Never use in production firmware. */\n"
        "#ifndef PXN_DEVELOPMENT_IDENTITY_H\n"
        "#define PXN_DEVELOPMENT_IDENTITY_H\n\n"
        "#include <stdint.h>\n\n"
        "#define PXN_DEVELOPMENT_IDENTITY 1\n"
        "#if defined(PXN_PRODUCTION_BUILD)\n"
        "#error \"Development identity must not be used in a production build\"\n"
        "#endif\n"
        f"#define PXN_DEVELOPMENT_DEVICE_UUID_TEXT \"{str(device_uuid).lower()}\"\n"
        f"#define PXN_DEVELOPMENT_CREDENTIAL_SET_ID \"{manifest['credential_set_id']}\"\n"
        "#if defined(__GNUC__) || defined(__clang__)\n"
        "#define PXN_DEVELOPMENT_MAYBE_UNUSED __attribute__((unused))\n"
        "#else\n"
        "#define PXN_DEVELOPMENT_MAYBE_UNUSED\n"
        "#endif\n\n"
        + c_array("pxn_development_device_uuid", device_uuid.bytes)
        + "\n"
        + c_array("pxn_development_unique_code", bytes.fromhex(unique_code))
        + "\n"
        + c_array("pxn_development_device_private_key", private_scalar)
        + "\n"
        + c_array("pxn_development_device_public_key", raw_public_key(device_key.public_key()))
        + "\n"
        + c_array("pxn_development_device_credential_chain", chain)
        + "\n"
        + c_array("pxn_development_host_authorization_public_key", raw_public_key(host_public_key))
        + "\n"
        + c_array("pxn_development_host_authorization_key_id", bytes.fromhex(manifest["keys"]["host_authorization"]["key_id_hex"]))
        + "\n"
        + c_array("pxn_development_ota_signing_public_key", raw_public_key(ota_public_key))
        + "\n"
        + c_array("pxn_development_ota_signing_key_id", bytes.fromhex(manifest["keys"]["ota_signing"]["key_id_hex"]))
        + "\n#undef PXN_DEVELOPMENT_MAYBE_UNUSED\n"
        + "#endif\n"
    )
    (output / "pxn-development-identity.h").write_text(header, encoding="utf-8")
    identity = {
        "schema_version": 1,
        "environment": "development",
        "credential_set_id": manifest["credential_set_id"],
        "product": document["product"],
        "target": args.target,
        "device_uuid": str(device_uuid).lower(),
        "device_uuid_source": "random" if args.random_device_uuid else "product_default",
        "unique_code_hex": unique_code,
        "certificate_sha256": hashlib.sha256(leaf_der).hexdigest(),
        "credential_chain_sha256": hashlib.sha256(chain).hexdigest(),
        "c_header": "pxn-development-identity.h",
    }
    (output / "identity.json").write_text(json.dumps(identity, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(identity, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
