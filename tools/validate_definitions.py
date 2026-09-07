#!/usr/bin/env python3
"""Validate the checked-in non-secret XProtocol development definition set."""

from __future__ import annotations

import json
import hashlib
import argparse
import re
import uuid
from pathlib import Path


HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical_uuid(value: str) -> str:
    return str(uuid.UUID(value)).upper()


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    profile = json.loads(
        (root / "definitions" / "development_profile_v1.json").read_text(
            encoding="utf-8"
        )
    )
    version = (root / "VERSION").read_text(encoding="utf-8").strip()

    require(profile["schema_version"] == 1, "schema_version must be 1")
    require(profile["environment"] == "development", "environment must be development")
    require(profile["production_eligible"] is False, "development profile cannot be production eligible")
    require(profile["profile_version"] == version, "VERSION/profile_version mismatch")
    parser = argparse.ArgumentParser()
    parser.add_argument("--core-repo", type=Path, default=root.parent / "pxn-xprotocol-core")
    args = parser.parse_args()
    authority = args.core_repo / "schemas/current.yaml"
    require(profile["xprotocol"] == {
        "authority": "schemas/current.yaml",
        "schema_sha256": hashlib.sha256(authority.read_bytes().replace(b'\r\n', b'\n')).hexdigest(),
        "wire_version": None,
    }, "current Core contract binding mismatch")

    profile_id = canonical_uuid(profile["profile_id"])
    namespace = canonical_uuid(profile["identifiers"]["development_uuid_namespace"])
    require(profile_id == profile["profile_id"], "profile_id must be canonical uppercase UUID")
    require(namespace == profile["identifiers"]["development_uuid_namespace"], "namespace UUID must be canonical uppercase")

    interface_guid = profile["identifiers"]["usb_bulk_device_interface_guid"]
    require(interface_guid.startswith("{") and interface_guid.endswith("}"), "USB GUID must use braces")
    require(canonical_uuid(interface_guid[1:-1]) == interface_guid[1:-1], "USB GUID must be canonical uppercase")

    credentials = profile["credentials"]
    require(bool(HEX_40.fullmatch(credentials["commit"])), "credential commit must be 40 lowercase hex characters")
    uuid.UUID(credentials["credential_set_id"])

    signature = profile["ota"]["signature"]
    encryption = profile["ota"]["encryption"]
    require(signature["required"] is True, "OTA signature must be required")
    require(signature["algorithm"] == "ECDSA_P256_SHA256_RAW_RS_LOW_S", "signature algorithm mismatch")
    require(1 <= signature["key_id"] <= 0xFFFF, "signature key_id out of range")
    require(bool(HEX_64.fullmatch(signature["public_key_sha256"])), "signing public-key fingerprint must be SHA-256 hex")
    require(encryption["optional"] is True, "OTA encryption must remain optional")
    require(encryption["plaintext_packages_allowed"] is True, "development profile must allow signed plaintext packages")
    require(encryption["algorithm"] == "AES_256_GCM", "encryption algorithm mismatch")
    require(1 <= encryption["key_id"] <= 0xFFFF, "encryption key_id out of range")
    require((encryption["key_bytes"], encryption["nonce_bytes"], encryption["tag_bytes"]) == (32, 12, 16), "AES-GCM size contract mismatch")
    require(bool(HEX_64.fullmatch(encryption["key_hex"])), "development AES key must be 32-byte hex")
    require(encryption["key_hex"] not in {"00" * 32, "ff" * 32}, "development AES key cannot be blank")

    print("OK: XProtocol development definitions are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
