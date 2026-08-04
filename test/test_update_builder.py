from __future__ import annotations

import importlib.util
import json
import struct
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("build_update", ROOT / "tools" / "build_update.py")

try:
    assert SPEC and SPEC.loader
    build_update = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(build_update)
    HAS_CRYPTOGRAPHY = True
except SystemExit:
    HAS_CRYPTOGRAPHY = False


@unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography is not installed")
class UpdateBuilderTests(unittest.TestCase):
    def test_host_parser_rejects_device_incompatible_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "info.json"
            for document in (
                '{"schema":1,"schema":1}',
                '{"name":"\\u0041"}',
            ):
                with self.subTest(document=document):
                    path.write_text(document, encoding="utf-8")
                    with self.assertRaises(SystemExit):
                        build_update.load_json(path)

    def test_rejects_values_the_device_cannot_parse(self) -> None:
        info = {
            "schema": 1,
            "product": "openos",
            "channel": "stable",
            "target": build_update.TARGET,
            "partitionScheme": build_update.PARTITION_SCHEME,
            "name": "Test release",
            "version": "9.0.0",
            "versionCode": 9,
            "minUpdaterVersionCode": 2,
            "releaseType": "security",
            "description": "bad\rdescription",
            "publishedAt": "2026-08-04",
            "firmware": "firmware-9.bin",
            "size": 4096,
            "sha256": "0" * 64,
            "keyId": build_update.KEY_ID,
            "signature": "A" * 96,
        }
        with self.assertRaises(SystemExit):
            build_update.validate_metadata(info)

    def test_signed_release_verifies_and_tampering_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            info_path = root / "info.json"
            firmware_path = root / "firmware-2.bin"
            private_path = root / "private.pem"
            public_path = root / "public.pem"
            info = {
                "schema": 1,
                "product": "openos",
                "channel": "stable",
                "target": build_update.TARGET,
                "partitionScheme": build_update.PARTITION_SCHEME,
                "name": "Test release",
                "version": "9.0.0",
                "versionCode": 9,
                "minUpdaterVersionCode": 1,
                "releaseType": "security",
                "description": "Signed test",
                "publishedAt": "2026-08-04",
                "firmware": firmware_path.name,
                "size": 4096,
                "sha256": "0" * 64,
                "keyId": build_update.KEY_ID,
                "signature": "",
            }
            firmware = bytearray(4801)
            firmware[0] = build_update.ESP_IMAGE_MAGIC
            firmware[1] = 1
            struct.pack_into("<H", firmware, 12, build_update.ESP32_CHIP_ID)
            struct.pack_into("<I", firmware, 32, build_update.ESP_APP_DESC_MAGIC)
            marker = build_update.expected_image_marker(info)
            firmware[256:256 + len(marker)] = marker
            firmware_path.write_bytes(firmware)
            build_update.write_json_lf(info_path, info)
            build_update.generate_keypair(private_path, public_path)
            build_update.sign_release(info_path, private_path)
            build_update.verify_release(info_path, public_path)

            changed = json.loads(info_path.read_text(encoding="utf-8"))
            changed["description"] = "tampered"
            build_update.write_json_lf(info_path, changed)
            with self.assertRaises(SystemExit):
                build_update.verify_release(info_path, public_path)


if __name__ == "__main__":
    unittest.main()
