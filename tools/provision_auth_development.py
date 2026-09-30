#!/usr/bin/env python3
"""Run the controlled development authentication initialization flow.

The development station owns one reusable ephemeral test issuer. It signs
fresh per-device CSRs, validates the resulting credential set and atomically
publishes each device directory. The station issuer key never enters a device
directory or firmware package. Production provisioning is refused and must
use an external production issuer and station.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sys
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from create_auth_csr import AUTH_EXTENSION_OID, create_request
from validate_auth_credential import validate


class ProvisioningError(RuntimeError):
    pass


def _name(value: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def _ephemeral_issuer() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    now = dt.datetime.now(dt.timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    name = _name("PXN development test issuer")
    cert = x509.CertificateBuilder().subject_name(name).issuer_name(name) \
        .public_key(key.public_key()).serial_number(x509.random_serial_number()) \
        .not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(days=1)) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True) \
        .sign(key, hashes.SHA256())
    return key, cert


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class DevelopmentStation:
    """Reusable controlled development trust domain."""

    def __init__(self, directory: Path, key: ec.EllipticCurvePrivateKey,
                 certificate: x509.Certificate):
        self.directory = directory.resolve()
        self.key = key
        self.certificate = certificate
        self.root_sha256 = certificate.fingerprint(hashes.SHA256()).hex()

    @classmethod
    def create(cls, directory: Path) -> "DevelopmentStation":
        directory = directory.resolve()
        directory.mkdir(parents=True, exist_ok=True)
        key_path, cert_path = directory / "station-issuer-key.pem", directory / "station-root.pem"
        if key_path.exists() != cert_path.exists():
            raise ProvisioningError("development station has only one issuer material")
        if key_path.exists():
            key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        else:
            key, cert = _ephemeral_issuer()
            _write(key_path, key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
            _write(cert_path, cert.public_bytes(serialization.Encoding.PEM))
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
            raise ProvisioningError("development station issuer must use P-256")
        if cert.subject != cert.issuer:
            raise ProvisioningError("development station issuer must be self-signed")
        return cls(directory, key, cert)

    def sign(self, csr: x509.CertificateSigningRequest) -> x509.Certificate:
        now = dt.datetime.now(dt.timezone.utc)
        return x509.CertificateBuilder().subject_name(csr.subject) \
            .issuer_name(self.certificate.subject).public_key(csr.public_key()) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(days=1)) \
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
            .add_extension(x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH,
            ]), critical=True) \
            .add_extension(csr.extensions.get_extension_for_oid(AUTH_EXTENSION_OID).value, critical=False) \
            .sign(self.key, hashes.SHA256())


_CREDENTIAL_FILES = (
    "device-auth-key.pem",
    "device-auth.certificate.pem",
    "development-trust-root.pem",
    "device-auth.csr.pem",
    "auth-request.json",
)


def _public_spki(key: ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey) -> bytes:
    public = key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
    return public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _validate_credential_directory(directory: Path, *, expected_device_name: str | None = None,
                                   expected_trust_generation: int | None = None,
                                   expected_station_root: str | None = None) -> dict:
    state_path = directory / "provisioning-state.json"
    if not state_path.is_file():
        raise ProvisioningError(f"missing provisioning state: {directory}")
    state = _read_json(state_path)
    if state.get("schema_version") != 1 or state.get("state") != "PROVISIONED" or \
            state.get("environment") != "development" or state.get("production_eligible") is not False:
        raise ProvisioningError("invalid development provisioning state")
    if expected_device_name is not None and state.get("device_name") != expected_device_name:
        raise ProvisioningError("existing credential belongs to another device name")
    if expected_trust_generation is not None and state.get("trust_generation") != expected_trust_generation:
        raise ProvisioningError("existing credential has another trust generation")
    file_hashes = {}
    for name in _CREDENTIAL_FILES:
        path = directory / name
        if not path.is_file():
            raise ProvisioningError(f"missing credential file: {name}")
        file_hashes[name] = _sha256(path.read_bytes())
    if state.get("file_sha256") != file_hashes:
        raise ProvisioningError("credential file hash binding mismatch")

    key = serialization.load_pem_private_key((directory / _CREDENTIAL_FILES[0]).read_bytes(), password=None)
    leaf = x509.load_pem_x509_certificate((directory / _CREDENTIAL_FILES[1]).read_bytes())
    issuer = x509.load_pem_x509_certificate((directory / _CREDENTIAL_FILES[2]).read_bytes())
    csr = x509.load_pem_x509_csr((directory / _CREDENTIAL_FILES[3]).read_bytes())
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ProvisioningError("device authentication key must be P-256")
    public_spki = _public_spki(key)
    if public_spki != _public_spki(leaf.public_key()) or public_spki != _public_spki(csr.public_key()):
        raise ProvisioningError("device key, certificate and CSR are not bound")
    request = _read_json(directory / _CREDENTIAL_FILES[4])
    csr_der = csr.public_bytes(serialization.Encoding.DER)
    public_spki_sha256 = _sha256(public_spki)
    if request.get("csr_sha256") != _sha256(csr_der) or request.get("public_spki_sha256") != public_spki_sha256:
        raise ProvisioningError("CSR manifest binding mismatch")
    if request.get("environment") != "development" or request.get("trust_generation") != state.get("trust_generation"):
        raise ProvisioningError("CSR environment or trust generation mismatch")
    if state.get("device_identity") != public_spki_sha256 or state.get("public_spki_sha256") != public_spki_sha256 or \
            state.get("certificate_sha256") != leaf.fingerprint(hashes.SHA256()).hex() or \
            state.get("trust_root_sha256") != issuer.fingerprint(hashes.SHA256()).hex() or \
            state.get("csr_sha256") != _sha256(csr_der):
        raise ProvisioningError("credential identity or certificate hash binding mismatch")
    common_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if common_name != state.get("device_name") or request.get("common_name") != common_name:
        raise ProvisioningError("device name binding mismatch")
    if expected_station_root is not None and state.get("trust_root_sha256") != expected_station_root:
        raise ProvisioningError("credential belongs to another development trust domain")
    try:
        validate(leaf, "development", int(state["trust_generation"]), issuer, csr)
    except Exception as exc:
        raise ProvisioningError(f"credential certificate validation failed: {exc}") from exc
    return state


def _complete_stage(stage: Path, output: Path, *, expected_device_name: str,
                    expected_trust_generation: int, expected_station_root: str) -> dict:
    state = _validate_credential_directory(
        stage, expected_device_name=expected_device_name,
        expected_trust_generation=expected_trust_generation,
        expected_station_root=expected_station_root,
    )
    if output.exists():
        raise ProvisioningError(f"refusing to overwrite existing output: {output}")
    os.replace(stage, output)
    return {**state, "result": "PROVISIONED"}


def provision(output: Path, device_name: str, *, station: DevelopmentStation | None = None,
              environment: str = "development", trust_generation: int = 3,
              interrupt_after_stage: bool = False) -> dict:
    if environment != "development":
        raise ProvisioningError("production provisioning requires the external production issuer and station")
    if not 1 <= trust_generation <= 0xFFFFFFFF:
        raise ProvisioningError("trust generation must be in 1..4294967295")
    if not device_name or len(device_name) > 128:
        raise ProvisioningError("device name must contain 1..128 characters")
    if station is None:
        raise ProvisioningError("a reusable controlled development station is required")

    output = output.resolve()
    if output == station.directory or station.directory in output.parents:
        raise ProvisioningError("device credential output must not contain station issuer material")
    state_path = output / "provisioning-state.json"
    if state_path.is_file():
        state = _validate_credential_directory(
            output, expected_device_name=device_name,
            expected_trust_generation=trust_generation,
            expected_station_root=station.root_sha256,
        )
        return {**state, "result": "ALREADY_PROVISIONED"}

    stage = output.parent / f".{output.name}.provisioning"
    if stage.exists():
        return _complete_stage(
            stage, output, expected_device_name=device_name,
            expected_trust_generation=trust_generation,
            expected_station_root=station.root_sha256,
        )
    stage.mkdir(parents=True)
    try:
        key_pem, csr_pem, request = create_request("development", trust_generation, device_name)
        csr = x509.load_pem_x509_csr(csr_pem)
        leaf = station.sign(csr)
        leaf_pem = leaf.public_bytes(serialization.Encoding.PEM)
        issuer_pem = station.certificate.public_bytes(serialization.Encoding.PEM)
        public_spki_sha256 = _sha256(_public_spki(csr.public_key()))
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        credential_files = {
            "device-auth-key.pem": key_pem,
            "device-auth.certificate.pem": leaf_pem,
            "development-trust-root.pem": issuer_pem,
            "device-auth.csr.pem": csr_pem,
            "auth-request.json": (json.dumps(request, indent=2) + "\n").encode("utf-8"),
        }
        for name, data in credential_files.items():
            _write(stage / name, data)
        state = {
            "schema_version": 1,
            "state": "PROVISIONED",
            "result": "PROVISIONED",
            "credential_id": str(uuid.uuid4()),
            "device_name": device_name,
            "environment": "development",
            "channel_version": 1,
            "construction": "TLS_1_3_MUTUAL_AUTH",
            "trust_generation": trust_generation,
            "device_identity": public_spki_sha256,
            "public_spki_sha256": public_spki_sha256,
            "csr_sha256": _sha256(csr_der),
            "certificate_sha256": leaf.fingerprint(hashes.SHA256()).hex(),
            "trust_root_sha256": station.root_sha256,
            "issuer": "EPHEMERAL_DEVELOPMENT_STATION",
            "issuer_private_key_in_package": False,
            "production_eligible": False,
            "reboot_required": True,
            "file_sha256": {name: _sha256(data) for name, data in credential_files.items()},
        }
        (stage / "provisioning-state.json").write_text(
            json.dumps(state, indent=2) + "\n", encoding="utf-8"
        )
        _validate_credential_directory(
            stage, expected_device_name=device_name,
            expected_trust_generation=trust_generation,
            expected_station_root=station.root_sha256,
        )
        if interrupt_after_stage:
            return {**state, "result": "INTERRUPTED_BEFORE_COMMIT"}
        return _complete_stage(
            stage, output, expected_device_name=device_name,
            expected_trust_generation=trust_generation,
            expected_station_root=station.root_sha256,
        )
    except Exception:
        if stage.exists() and not (stage / "provisioning-state.json").is_file():
            for child in stage.iterdir():
                child.unlink()
            stage.rmdir()
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", choices=("development", "production"), default="development")
    parser.add_argument("--station", type=Path, required=True)
    parser.add_argument("--device-name", required=True)
    parser.add_argument("--trust-generation", type=int, default=3)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--interrupt-after-stage", action="store_true")
    args = parser.parse_args(argv)
    station = DevelopmentStation.create(args.station)
    result = provision(
        args.output, args.device_name, station=station,
        environment=args.environment, trust_generation=args.trust_generation,
        interrupt_after_stage=args.interrupt_after_stage,
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
