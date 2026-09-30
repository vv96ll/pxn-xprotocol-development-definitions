#!/usr/bin/env python3
"""Validate a product integration development identity file."""

from __future__ import annotations

import argparse
import json
import re
import uuid
from pathlib import Path

import yaml


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity-file", type=Path, required=True)
    parser.add_argument("--credential-manifest", type=Path)
    args = parser.parse_args()

    document = yaml.safe_load(args.identity_file.read_text(encoding="utf-8"))
    if document.get("schema_version") != 1 or document.get("environment") != "development":
        raise ValueError("expected schema_version 1 and environment development")
    product_namespace = uuid.UUID(document["product_namespace_uuid"])
    if product_namespace.version != 4:
        raise ValueError("product_namespace_uuid must be a random UUIDv4")
    targets = document.get("targets")
    if not isinstance(targets, dict) or not targets:
        raise ValueError("targets must be a non-empty mapping")
    values: list[str] = []
    for target_name, target in targets.items():
        parsed = uuid.UUID(target["default_device_uuid"])
        if parsed.version != 4:
            raise ValueError(f"default development UUID must be UUIDv4: {target_name}")
        value = str(parsed).lower()
        if value != target["default_device_uuid"]:
            raise ValueError(f"non-canonical UUID for {target_name}")
        values.append(value)
    if len(values) != len(set(values)):
        raise ValueError("default development UUIDs must be unique within a product")

    fingerprints = document.get("credential_fingerprints", {})
    expected_names = {
        "development_root_ca",
        "device_issuer",
        "host_authorization",
        "ota_signing",
    }
    if set(fingerprints) != expected_names:
        raise ValueError("credential_fingerprints set is incomplete or contains unknown names")
    if any(not SHA256_RE.fullmatch(value) for value in fingerprints.values()):
        raise ValueError("credential fingerprints must be lowercase SHA-256 hex")

    if args.credential_manifest:
        manifest = json.loads(args.credential_manifest.read_text(encoding="utf-8"))
        if document["credential_set_id"] != manifest["credential_set_id"]:
            raise ValueError("credential_set_id mismatch")
        for name in expected_names:
            if fingerprints[name] != manifest["keys"][name]["public_key_sha256"]:
                raise ValueError(f"credential fingerprint mismatch: {name}")
    print(f"OK: {args.identity_file} targets={len(targets)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
