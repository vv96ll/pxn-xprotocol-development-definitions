#!/usr/bin/env python3
"""Software-only tests for the controlled development initialization harness."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cryptography import x509

from provision_auth_development import DevelopmentStation, ProvisioningError, provision
from validate_auth_credential import validate


class ProvisionAuthDevelopmentTests(unittest.TestCase):
    def test_idempotent_and_independent_devices(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            station = DevelopmentStation.create(root / "station-a")
            first = provision(root / "device-a", "device-a", station=station)
            repeated = provision(root / "device-a", "device-a", station=station)
            second = provision(root / "device-b", "device-b", station=station)
            self.assertEqual(first["result"], "PROVISIONED")
            self.assertEqual(repeated["result"], "ALREADY_PROVISIONED")
            self.assertNotEqual(first["device_identity"], second["device_identity"])
            validate(
                x509.load_pem_x509_certificate(
                    (root / "device-a" / "device-auth.certificate.pem").read_bytes()
                ),
                "development",
                3,
                x509.load_pem_x509_certificate(
                    (root / "station-a" / "station-root.pem").read_bytes()
                ),
            )

    def test_interrupted_initialization_is_resumable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "device"
            station = DevelopmentStation.create(Path(directory) / "station-a")
            interrupted = provision(output, "device", station=station, interrupt_after_stage=True)
            self.assertEqual(interrupted["result"], "INTERRUPTED_BEFORE_COMMIT")
            self.assertFalse(output.exists())
            resumed = provision(output, "device", station=station)
            self.assertEqual(resumed["result"], "PROVISIONED")
            self.assertTrue((output / "provisioning-state.json").is_file())

    def test_corrupt_staging_and_trust_generation_change_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            station = DevelopmentStation.create(root / "station")

            corrupt_output = root / "corrupt"
            provision(corrupt_output, "corrupt", station=station, interrupt_after_stage=True)
            stage = root / ".corrupt.provisioning"
            cert = stage / "device-auth.certificate.pem"
            cert.write_bytes(cert.read_bytes()[:-1] + b"0")
            with self.assertRaises(ProvisioningError):
                provision(corrupt_output, "corrupt", station=station)

            generation_output = root / "generation"
            provision(generation_output, "generation", station=station,
                      trust_generation=3, interrupt_after_stage=True)
            with self.assertRaises(ProvisioningError):
                provision(generation_output, "generation", station=station,
                          trust_generation=4)

    def test_development_harness_rejects_production(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            station = DevelopmentStation.create(Path(directory) / "station-a")
            with self.assertRaises(ProvisioningError):
                provision(Path(directory) / "device", "device", station=station, environment="production")

    def test_other_development_domain_and_tamper_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            station_a = DevelopmentStation.create(root / "station-a")
            station_b = DevelopmentStation.create(root / "station-b")
            provision(root / "device-a", "device-a", station=station_a)
            with self.assertRaises(ProvisioningError):
                provision(root / "device-a", "device-a", station=station_b)
            cert = root / "device-a" / "device-auth.certificate.pem"
            cert.write_bytes(cert.read_bytes()[:-1] + b"0")
            with self.assertRaises(ProvisioningError):
                provision(root / "device-a", "device-a", station=station_a)


if __name__ == "__main__":
    unittest.main()
