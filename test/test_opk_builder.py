from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from zipfile import ZIP_STORED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("build_opk", ROOT / "tools" / "build_opk.py")
assert SPEC and SPEC.loader
build_opk = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build_opk)

# build_opk imports build_update (and through it `cryptography`) lazily; the
# signing tests need both, the framing tests need neither.
sys.path.insert(0, str(ROOT / "tools"))
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


def generate_release_keypair(directory: Path) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    private_path = directory / "release-private.pem"
    public_path = directory / "release-public.pem"
    private_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    public_path.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return private_path, public_path


class OpkBuilderTests(unittest.TestCase):
    def test_osa_discovery_hash_is_independent_of_line_endings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lf = root / "lf.osa"
            crlf = root / "crlf.osa"
            lf.write_bytes(b'#app "Test"\nloop\n  wait(1)\nend\n')
            crlf.write_bytes(b'#app "Test"\r\nloop\r\n  wait(1)\r\nend\r\n')
            self.assertEqual(build_opk.sha256_file(lf), build_opk.sha256_file(crlf))
            self.assertEqual(
                build_opk.archive_source_bytes(lf, "app.osa"),
                build_opk.archive_source_bytes(crlf, "app.osa"),
            )
            package = root / "existing.opk"
            with ZipFile(package, "w", compression=ZIP_STORED) as archive:
                archive.writestr("manifest.json", b"{}")
                archive.writestr("app.osa", crlf.read_bytes())
            self.assertTrue(build_opk.existing_package_matches(
                package, b"{}", [("app.osa", lf, lf.stat().st_size)]
            ))

    def test_manifest_compatibility_levels_are_validated(self) -> None:
        base = {
            "schema": 1,
            "id": "test.app",
            "name": "Test",
            "version": "1.0.0",
            "versionCode": 1,
            "entry": "app.osa",
            "scope": "user",
            "isApp": True,
        }
        validated = build_opk.validate_manifest(dict(base), "test manifest")
        self.assertEqual(validated["minSdk"], 1)
        self.assertEqual(validated["minOpenOS"], 1)
        for field in ("minSdk", "minOpenOS"):
            for invalid in (0, -1, 32768, True, "2"):
                with self.subTest(field=field, invalid=invalid), self.assertRaises(SystemExit):
                    manifest = dict(base)
                    manifest[field] = invalid
                    build_opk.validate_manifest(manifest, "test manifest")

    def test_unsafe_archive_paths_are_rejected(self) -> None:
        for path in ("../app.osa", "/app.osa", "a//b", "a/./b", "a\\b", "C:app.osa"):
            with self.subTest(path=path), self.assertRaises(SystemExit):
                build_opk.safe_archive_path(path)

    def test_catalog_signature_framing_round_trips(self) -> None:
        apps = [{"id": "a.b", "name": "quote\"inside", "url": "https://x/y.opk"}]
        unsigned = build_opk.unsigned_catalog_bytes(apps)
        self.assertTrue(unsigned.startswith(b'{"schema":1,"apps":['))
        self.assertTrue(unsigned.endswith(b',"keyId":"' + build_opk.KEY_ID.encode() + b'"}'))
        signature = "A" * 96
        signed = build_opk.signed_catalog_bytes(unsigned, signature)
        self.assertTrue(signed.endswith(b'"}\n'))
        # The device strips trailing whitespace before looking at the field.
        for document in (signed, signed.rstrip(b"\n"), signed + b"\r\n \n"):
            with self.subTest(document=document[-8:]):
                self.assertEqual(build_opk.split_signed_catalog(document),
                                 (unsigned, signature))
        for bad in (
            unsigned + b"\n",                                  # unsigned
            signed.replace(b'"}\n', b'" }\n'),                # whitespace before }
            signed.replace(b'"}\n', b'","x":1}\n'),           # not the last field
            b'{"schema":1,"apps":[],"keyId":"k","signature":"' + b"A" * 96 + b'"}}',
        ):
            with self.subTest(bad=bad[-16:]), self.assertRaises(SystemExit):
                build_opk.split_signed_catalog(bad)
        with self.assertRaises(SystemExit):
            build_opk.signed_catalog_bytes(unsigned, "not base64!")

    @unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography is not installed")
    def test_signed_catalog_verifies_and_tampering_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            private_path, public_path = generate_release_keypair(Path(directory))
            unsigned = build_opk.unsigned_catalog_bytes([{
                "id": "test.app", "name": "Test", "version": "1.0.0", "versionCode": 1,
                "minSdk": 1, "minOpenOS": 1, "scope": "user", "developer": "t",
                "summary": "s", "description": "d", "appColor": "#000000",
                "url": "https://example.invalid/test.app.opk", "sha256": "0" * 64,
            }])
            signed = build_opk.sign_catalog(unsigned, private_path)
            parsed = build_opk.verify_catalog(signed, public_path)
            self.assertEqual(parsed["apps"][0]["id"], "test.app")
            self.assertEqual(json.loads(signed)["keyId"], build_opk.KEY_ID)
            tampered = signed.replace(b'"sha256":"' + b"0" * 64, b'"sha256":"' + b"1" * 64)
            self.assertNotEqual(tampered, signed)
            with self.assertRaises(SystemExit):
                build_opk.verify_catalog(tampered, public_path)
            other_private, other_public = generate_release_keypair(Path(directory) / "other")
            with self.assertRaises(SystemExit):
                build_opk.verify_catalog(signed, other_public)

    def test_published_packages_match_catalog(self) -> None:
        document = (ROOT / "store" / "catalog.json").read_bytes()
        # OpenOS 1.2+ rejects an unsigned catalog, so the published file must
        # carry the release signature (tools/build_opk.py --key ...).
        try:
            unsigned, signature = build_opk.split_signed_catalog(document)
        except SystemExit as exc:
            self.fail(f"store/catalog.json is not publishable ({exc}); "
                      "run: python tools/build_opk.py --key <release private key>")
        catalog = json.loads(unsigned)
        self.assertEqual(catalog["keyId"], build_opk.KEY_ID)
        if HAS_CRYPTOGRAPHY:
            build_opk.verify_catalog(document, build_opk.DEFAULT_PUBLIC_KEY)
        self.assertEqual(catalog["schema"], 1)
        self.assertGreater(len(catalog["apps"]), 0)

        for item in catalog["apps"]:
            self.assertGreater(len(item["developer"]), 0)
            self.assertLessEqual(len(item["developer"]), 64)
            self.assertGreater(len(item["summary"]), 0)
            self.assertLessEqual(len(item["summary"]), 50)
            self.assertGreater(len(item["description"]), 0)
            self.assertLessEqual(len(item["description"].encode("utf-8")), 10000)
            self.assertRegex(item["appColor"], r"^#[0-9A-F]{6}$")
            self.assertGreaterEqual(item["minSdk"], 1)
            self.assertGreaterEqual(item["minOpenOS"], 1)
            package_path = ROOT / "store" / "packages" / f"{item['id']}.opk"
            self.assertLessEqual(package_path.stat().st_size, build_opk.MAX_PACKAGE_BYTES)
            digest = hashlib.sha256(package_path.read_bytes()).hexdigest()
            self.assertEqual(digest, item["sha256"])
            with ZipFile(package_path) as archive:
                self.assertIsNone(archive.testzip())
                infos = archive.infolist()
                self.assertLessEqual(len(infos), build_opk.MAX_ENTRIES)
                self.assertLessEqual(sum(info.file_size for info in infos),
                                     build_opk.MAX_TOTAL_BYTES)
                folded_names: set[str] = set()
                for info in infos:
                    self.assertLessEqual(info.file_size, build_opk.MAX_FILE_BYTES)
                    self.assertEqual(info.compress_type, ZIP_STORED)
                    self.assertEqual(info.flag_bits & 0x0009, 0)
                    build_opk.safe_archive_path(info.filename)
                    folded = info.filename.casefold()
                    self.assertNotIn(folded, folded_names)
                    folded_names.add(folded)
                self.assertEqual(archive.namelist().count("manifest.json"), 1)
                self.assertLessEqual(archive.getinfo("manifest.json").file_size,
                                     build_opk.MAX_MANIFEST_BYTES)
                manifest = json.loads(archive.read("manifest.json"))
                self.assertEqual(manifest["id"], item["id"])
                self.assertEqual(manifest["scope"], item["scope"])
                self.assertEqual(manifest["versionCode"], item["versionCode"])
                self.assertEqual(manifest["minSdk"], item["minSdk"])
                self.assertEqual(manifest["minOpenOS"], item["minOpenOS"])
                self.assertIn(manifest["entry"], archive.namelist())


if __name__ == "__main__":
    unittest.main()
