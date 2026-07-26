from __future__ import annotations

import hashlib
import importlib.util
import json
import unittest
from pathlib import Path
from zipfile import ZIP_STORED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("build_opk", ROOT / "tools" / "build_opk.py")
assert SPEC and SPEC.loader
build_opk = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build_opk)


class OpkBuilderTests(unittest.TestCase):
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

    def test_published_packages_match_catalog(self) -> None:
        catalog = json.loads((ROOT / "store" / "catalog.json").read_text(encoding="utf-8"))
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
