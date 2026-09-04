# PXN XProtocol Development Definitions

This repository is the canonical shared definition set for PXN XProtocol
development and HIL environments. It centralizes identifiers and development
cryptographic values that must agree across firmware, Host tooling and test
fixtures.

## Contents

- the development USB Bulk `DeviceInterfaceGUID`;
- the UUID namespace used when a development product needs deterministic UUIDs;
- OTA signing and encryption key-slot IDs;
- the signed-package and optional AES-256-GCM policy;
- an immutable reference to the development credential set;
- a fixed, checked-in development AES-256 key;
- a validator for malformed or inconsistent definitions.

The active definition is
[`definitions/development_profile_v1.json`](definitions/development_profile_v1.json).
Version `1.2.0-dev.1` declares compatibility with XProtocol Wire 1.3 while
retaining the same development-only identifiers and credential-set reference.

## Development boundary

Values in this repository are intentionally shared and are not secrets. The
development AES key is checked in so local firmware, Host and HIL use the same
value without extra provisioning. P-256 signing material remains in the
referenced `pxn-development-credentials` repository to avoid maintaining two
copies. Product/model/device UUIDs remain product-owned; the namespace here is
only a deterministic development convention.

Definitions are marked `environment: development` and
`production_eligible: false`. This is a compatibility label, not a secrecy
mechanism: the values may be used freely during development, but production
uses a separate definition and credential set.

## Validate

```powershell
python tools/validate_definitions.py
```

The validator uses only the Python standard library.
