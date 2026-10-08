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
- the development credential set, public certificates, signing keys and provisioning tools;
- a fixed, checked-in development AES-256 key;
- a validator for malformed or inconsistent definitions.

The active definition is
[`definitions/development_profile_v1.json`](definitions/development_profile_v1.json).
Version `2.0.0-dev.17` binds the current Core schema by SHA-256, with no assigned
released Wire version. Package version and schema format version are independent.
Development identifiers and credential values remain unchanged. Validate against
the selected Core checkout before use (`--core-repo PATH`). Product OTA integration
still requires its installation and authorization providers; this profile does
not establish their implementation or qualification.

## Development boundary

Development values and keys in this repository are intentionally shared for laboratory use. The
development AES key is checked in so local firmware, Host and HIL use the same
value without extra provisioning. P-256 development signing private keys are
committed in `private/`, with public certificates in `public/` and the fingerprint manifest in
`development_credentials.json`. The profile binds that manifest by SHA-256.
See [credential tooling](CREDENTIALS.md) for issuance and validation. Product/model/device UUIDs remain product-owned; the namespace here is
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

## Public binding checks

`definitions/development_binding_v1.json` contains only the package version and
Core binding. Workspace consumers validate this metadata from the selected Git
commit without reading the credential-bearing profile. The full definitions
validator also checks that the public binding matches the private profile;
that full validation remains a separate, credential-authorized operation.
